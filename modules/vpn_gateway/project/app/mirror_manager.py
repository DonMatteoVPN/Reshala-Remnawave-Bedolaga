from dataclasses import dataclass, field
from time import time
import httpx

_REFRESH_TTL_SEC = 10


@dataclass
class MirrorState:
    alive: dict[str, bool] = field(default_factory=dict)
    last_check: float = 0.0


class MirrorManager:
    def __init__(self):
        self.state = MirrorState()

    async def refresh(self, targets: list[str], timeout_ms: int = 1500) -> None:
        new_state: dict[str, bool] = {}
        timeout = timeout_ms / 1000
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            for target in targets:
                try:
                    response = await client.get(target)
                    new_state[target] = response.status_code < 500
                except Exception:
                    new_state[target] = False
        self.state.alive = new_state
        self.state.last_check = time()

    async def refresh_if_stale(self, targets: list[str], timeout_ms: int = 1500) -> None:
        """Обновляет health-check не чаще раза в _REFRESH_TTL_SEC секунд."""
        if time() - self.state.last_check > _REFRESH_TTL_SEC:
            await self.refresh(targets, timeout_ms)

    def pick_first_alive(self, targets: list[str]) -> str | None:
        for target in targets:
            if self.state.alive.get(target, True):
                return target
        return None
