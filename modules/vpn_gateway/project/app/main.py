import base64
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import load_config
from app.mirror_manager import MirrorManager
from app.proxy import forward_request
from app.router_logic import match_route
from app.url_utils import merge_query



def _build_target(base: str, path: str, query: str, preserve_path: bool, preserve_query: bool) -> str:
    target = base.rstrip("/")
    if preserve_path:
        target = urljoin(target + "/", path.lstrip("/"))
    if preserve_query:
        target = merge_query(target, query)
    return target


def _build_start_destination(
    request: Request,
    default_target: str,
    target_override: str | None = None,
) -> str:
    target = target_override or request.query_params.get("target") or default_target
    passthrough = [(k, v) for k, v in request.query_params.multi_items() if k != "target"]
    base = f"/buy/{target}"
    if not passthrough:
        return base
    return f"{base}?{urlencode(passthrough)}"


def _b64url_encode(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> str:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii")).decode("utf-8")


def _obfuscate_return_value(raw_value: str, public_domain: str) -> str:
    decoded = raw_value
    for _ in range(2):
        if "%" not in decoded:
            break
        decoded = unquote(decoded)

    parts = urlsplit(decoded)
    if parts.scheme not in ("http", "https") or parts.netloc != public_domain:
        return raw_value

    token = _b64url_encode(decoded)
    return f"https://{public_domain}/_r/{token}"


def _obfuscate_return_in_url(url: str, public_domain: str) -> str:
    parts = urlsplit(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)

    changed = False
    updated_items: list[tuple[str, str]] = []
    for key, value in query_items:
        if key == "return" and value:
            updated_items.append((key, _obfuscate_return_value(value, public_domain)))
            changed = True
        else:
            updated_items.append((key, value))

    if not changed:
        return url

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated_items), parts.fragment))


def _obfuscate_return_in_text(text: str, public_domain: str) -> str:
    marker = '"return":"'
    cursor = 0
    out = text
    while True:
        idx = out.find(marker, cursor)
        if idx == -1:
            break
        value_start = idx + len(marker)
        value_end = out.find('"', value_start)
        if value_end == -1:
            break

        current = out[value_start:value_end]
        replaced = _obfuscate_return_value(current, public_domain)
        out = out[:value_start] + replaced + out[value_end:]
        cursor = value_start + len(replaced)

    return out


def create_app(config_path: str = "config/gateway.yml") -> FastAPI:
    cfg = load_config(config_path)
    docs_enabled = cfg.raw.get("project", {}).get("docs_enabled", False)
    app = FastAPI(
        title="VPN Gateway",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    mirror_manager = MirrorManager()
    templates = Jinja2Templates(directory="app/templates")

    @app.api_route("/health", methods=["GET", "HEAD"])
    async def health():
        return {"ok": True}

    # Раздаём статику (favicon, future assets) — до catch-all роута!
    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    # /favicon.ico → редирект на SVG (браузеры тоже делают GET /favicon.ico)
    @app.api_route("/favicon.ico", methods=["GET", "HEAD"])
    async def favicon_ico():
        return RedirectResponse(url="/static/favicon.svg", status_code=301)

    @app.api_route("/docs", methods=["GET", "HEAD"])
    @app.api_route("/redoc", methods=["GET", "HEAD"])
    @app.api_route("/openapi.json", methods=["GET", "HEAD"])
    async def hidden_docs_routes():
        return Response(status_code=404)

    landing_cfg = cfg.raw.get("landing", {})
    pages = landing_cfg.get("pages") or []
    if not pages:
        raise ValueError("В конфиге landing.pages должен быть задан минимум один маршрут лендинга")

    default_target = cfg.raw.get("project", {}).get("default_target")
    if not default_target:
        raise ValueError("В конфиге project.default_target должно быть задано значение по умолчанию для /start")

    landing_mode = landing_cfg.get("mode", "template")

    for page in pages:
        page_path = page.get("path", "/")

        if landing_mode == "mirror_redirect":
            async def render_page(request: Request, page_data: dict = page):
                target = page_data.get("mirror_target") or page_data.get("primary_target") or default_target
                return RedirectResponse(
                    url=_build_start_destination(request, default_target=default_target, target_override=target),
                    status_code=302,
                )
        else:
            async def render_page(request: Request, page_data: dict = page):
                start_target = page_data.get("primary_target", default_target)
                start_link = f"/start?target={start_target}"
                return templates.TemplateResponse(request, "landing.html", {"start_link": start_link, "page": page_data})

        app.add_api_route(page_path, render_page, methods=["GET", "HEAD"], response_class=HTMLResponse)

    @app.api_route("/start", methods=["GET", "HEAD"])
    async def start(request: Request):
        return RedirectResponse(url=_build_start_destination(request, default_target=default_target), status_code=302)

    @app.api_route("/_r/{token}", methods=["GET", "HEAD"])
    async def return_unwrap(token: str):
        fallback = cfg.raw["project"].get("fallback_url", "/")
        public_domain = (cfg.raw.get("project", {}) or {}).get("public_domain", "")
        try:
            target = _b64url_decode(token)
            parsed = urlsplit(target)
            if parsed.scheme not in ("http", "https") or parsed.netloc != public_domain:
                return RedirectResponse(url=fallback, status_code=302)
            return RedirectResponse(url=target, status_code=302)
        except Exception:
            return RedirectResponse(url=fallback, status_code=302)

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def catch_all(request: Request, full_path: str):
        path = "/" + full_path
        route = match_route(path, [r.__dict__ for r in cfg.routing.routes])
        pool = cfg.upstreams[route["upstream_pool"]]

        if pool.strategy == "first_alive":
            await mirror_manager.refresh(pool.targets, timeout_ms=pool.healthcheck.get("timeout_ms", 1500))
            selected = mirror_manager.pick_first_alive(pool.targets)
        else:
            selected = pool.targets[0] if pool.targets else None

        if not selected:
            fallback = cfg.raw["project"].get("fallback_url", "/")
            return RedirectResponse(url=fallback, status_code=302)

        target_url = _build_target(
            base=selected,
            path=path,
            query=request.url.query,
            preserve_path=cfg.routing.preserve_path,
            preserve_query=cfg.routing.preserve_query,
        )

        if cfg.raw["project"].get("mode") == "redirect":
            return RedirectResponse(url=target_url, status_code=302)

        body = await request.body()
        headers = dict(request.headers)
        headers.pop("host", None)
        upstream_response = await forward_request(request.method, target_url, headers=headers, body=body)

        response_headers = dict(upstream_response.headers)
        hop_by_hop = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization", "te", "trailers"}
        for h in list(response_headers.keys()):
            if h.lower() in hop_by_hop:
                response_headers.pop(h, None)

        if cfg.raw.get("security", {}).get("strip_server_header", True):
            response_headers.pop("server", None)
        response_headers.pop("date", None)
        response_headers.pop("content-length", None)
        response_headers.pop("content-encoding", None)

        public_domain = (cfg.raw.get("project", {}) or {}).get("public_domain", "")
        origin_domain = (cfg.raw.get("quick_setup", {}) or {}).get("origin_domain", "")
        hide_payment_return = cfg.raw.get("security", {}).get("hide_payment_return", False)

        location = response_headers.get("location")
        if location and public_domain and origin_domain:
            rewritten_location = location.replace(origin_domain, public_domain)
            if hide_payment_return:
                rewritten_location = _obfuscate_return_in_url(rewritten_location, public_domain)
            response_headers["location"] = rewritten_location

        body_content = upstream_response.content
        content_type = (upstream_response.headers.get("content-type") or "").lower()
        textual_types = ("text/", "application/json", "application/javascript", "application/xml")
        if any(t in content_type for t in textual_types):
            if public_domain and origin_domain:
                body_content = body_content.replace(origin_domain.encode("utf-8"), public_domain.encode("utf-8"))
            if public_domain and hide_payment_return:
                text_body = body_content.decode("utf-8", errors="ignore")
                body_content = _obfuscate_return_in_text(text_body, public_domain).encode("utf-8")

        return Response(
            content=body_content,
            status_code=upstream_response.status_code,
            headers=response_headers,
        )

    return app


app = create_app()
