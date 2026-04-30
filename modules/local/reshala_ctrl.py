#!/usr/bin/env python3
# ============================================================ #
# ==        RESHALA eBPF TRAFFIC LIMITER CONTROLLER         == #
# ==              reshala_ctrl.py  v4.0 (Multi-Rule)        == #
# ============================================================ #
#
# Управляет BPF-картами шейпера через pinned path.
# Поддерживает несколько независимых правил (Multi-Rule).
# Правила сохраняются в rules.json для восстановления после перезапуска.
#

import sys
import struct
import subprocess
import argparse
import os
import json
import ipaddress

# Принудительно ставим UTF-8, чтобы не было UnicodeEncodeError в systemd и урезанных SSH-сессиях
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

DEFAULT_PIN_DIR   = "/sys/fs/bpf/reshala/maps"
DEFAULT_RULES_FILE = "/etc/reshala/traffic_limiter/rules.json"
MAX_PORTS  = 32   # Must match shaper.bpf.c #define MAX_PORTS
MAX_RULES  = 32   # Must match shaper.bpf.c #define MAX_RULES

# ────────────────────────────────────────────────────────────
# Утилиты
# ────────────────────────────────────────────────────────────

def parse_ports(ports_str):
    """'443,80,0' → [443, 80, 0] | '0' → [0]"""
    try:
        parts = [int(p.strip()) for p in str(ports_str).split(',') if p.strip()]
    except ValueError:
        return []
    return [p for p in parts if 0 <= p <= 65535][:MAX_PORTS]

def run_cmd(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, check=check,
                                capture_output=True, text=True)
        return result.stdout.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Ошибка команды: {cmd}\nStderr: {e.stderr.strip()}")
        sys.exit(1)

def bpftool_map_update(pin_dir, map_name, key_hex, value_hex):
    pin_path = os.path.join(pin_dir, map_name)
    if not os.path.exists(pin_path):
        print(f"❌ BPF map не найден: {pin_path}")
        print(f"   Убедись что сервис запущен: systemctl status reshala-traffic-limiter")
        sys.exit(1)
    run_cmd(f"bpftool map update pinned {pin_path} key hex {key_hex} value hex {value_hex}")

def bpftool_map_delete(pin_dir, map_name, key_hex):
    pin_path = os.path.join(pin_dir, map_name)
    if not os.path.exists(pin_path):
        return
    run_cmd(f"bpftool map delete pinned {pin_path} key hex {key_hex}", check=False)

def bpftool_map_dump(pin_dir, map_name):
    pin_path = os.path.join(pin_dir, map_name)
    if not os.path.exists(pin_path):
        return []
    out, rc = run_cmd(f"bpftool map dump pinned {pin_path} -j", check=False)
    if not out or rc != 0:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []

def format_bytes(n):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"

def to_byte(x):
    if isinstance(x, int): return x
    try: return int(x, 16)
    except: return 0

# ────────────────────────────────────────────────────────────
# Сериализация struct rule_config (C layout, little-endian)
# struct rule_config {
#   __u32 mode;                         4   offset 0
#   __u32 num_ports;                    4   offset 4
#   __u32 ports[MAX_PORTS=32];        128   offset 8
#   __u64 down_rate_bps;                8   offset 136
#   __u64 up_rate_bps;                  8   offset 144
#   __u64 penalty_rate_bps;             8   offset 152
#   __u64 burst_bytes_limit;            8   offset 160
#   __u64 window_time_ns;               8   offset 168
#   __u64 penalty_time_ns;              8   offset 176
#   Total = 184 bytes
# }
# ────────────────────────────────────────────────────────────

RULE_STRUCT_FMT = f"<I I {MAX_PORTS}I Q Q Q Q Q Q"
RULE_STRUCT_SIZE = struct.calcsize(RULE_STRUCT_FMT)

def pack_rule(mode, ports_list, d_bps, u_bps, pen_bps, burst_bytes, win_ns, pen_ns):
    num_ports = len(ports_list)
    padded    = ports_list + [0] * (MAX_PORTS - len(ports_list))
    return struct.pack(RULE_STRUCT_FMT,
                       mode, num_ports, *padded,
                       d_bps, u_bps, pen_bps, burst_bytes, win_ns, pen_ns)

def unpack_rule(data):
    """Returns dict with rule fields, or None if mode==0."""
    if len(data) < RULE_STRUCT_SIZE:
        return None
    fields = struct.unpack_from(RULE_STRUCT_FMT, data)
    mode      = fields[0]
    num_ports = fields[1]
    ports     = [fields[2 + i] for i in range(min(num_ports, MAX_PORTS)) if fields[2+i] > 0]
    d_bps     = fields[2 + MAX_PORTS + 0]
    u_bps     = fields[2 + MAX_PORTS + 1]
    pen_bps   = fields[2 + MAX_PORTS + 2]
    burst     = fields[2 + MAX_PORTS + 3]
    win_ns    = fields[2 + MAX_PORTS + 4]
    pen_ns    = fields[2 + MAX_PORTS + 5]
    return {
        'mode': mode, 'ports': ports,
        'down_mbs':  d_bps   / (1024*1024),
        'up_mbs':    u_bps   / (1024*1024),
        'pen_mbs':   pen_bps / (1024*1024),
        'burst_mb':  burst   / (1024*1024),
        'win_sec':   win_ns  / 1_000_000_000,
        'pen_sec':   pen_ns  / 1_000_000_000,
    }

# ────────────────────────────────────────────────────────────
# Rules JSON persistence
# ────────────────────────────────────────────────────────────

def load_rules_file(path=DEFAULT_RULES_FILE):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}

def save_rules_file(rules_dict, path=DEFAULT_RULES_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(rules_dict, f, indent=2, ensure_ascii=False)

# ────────────────────────────────────────────────────────────
# Rule management
# ────────────────────────────────────────────────────────────

def get_mode_str(mode):
    if mode == 1: return "Статика"
    elif mode == 2: return "Динамика"
    elif mode == 3: return "Общее ограничение"
    return "Выкл"

def get_mode_str_color(mode):
    if mode == 1: return "\033[0;32mСтатика\033[0m"
    elif mode == 2: return "\033[0;33mДинамика\033[0m"
    elif mode == 3: return "\033[0;36mОбщее ограничение\033[0m"
    return "\033[0;31mВыкл\033[0m"

def u32_key_hex(n):
    return " ".join(f"{b:02x}" for b in struct.pack("<I", n))

def set_rule(pin_dir, rule_id, mode, ports_str, d_mbs, u_mbs,
             burst_mb, win_sec, pen_sec, pen_mbs=None, rules_file=DEFAULT_RULES_FILE):
    """Добавляет/обновляет правило rule_id. Возвращает True при успехе."""
    if rule_id < 0 or rule_id >= MAX_RULES:
        print(f"❌ rule_id должен быть 0..{MAX_RULES-1}")
        return False

    ports_list = parse_ports(ports_str)
    if not ports_list and ports_str.strip() not in ('0', ''):
        print("❌ Нет корректных портов в указанной строке.")
        return False

    # Конвертация
    d_bps      = int(d_mbs   * 1024 * 1024)
    u_bps      = int(u_mbs   * 1024 * 1024)
    burst_b    = int(burst_mb  * 1024 * 1024)
    win_ns     = int(win_sec   * 1_000_000_000)
    pen_ns     = int(pen_sec   * 1_000_000_000)
    if pen_mbs is None:
        pen_mbs = 0.1
    pen_bps    = int(pen_mbs  * 1024 * 1024)

    # Проверка конфликта портов в port_rule_map
    port_map_entries = bpftool_map_dump(pin_dir, "port_rule_map")
    occupied = {}  # port → existing_rule_id
    for entry in port_map_entries:
        k = entry.get('key', {})
        v = entry.get('value', {})
        port_val = 0
        if isinstance(k, dict):
            port_val = list(k.values())[0] if k else 0
        elif isinstance(k, list):
            port_val = to_byte(k[0]) | (to_byte(k[1]) << 8) | \
                       (to_byte(k[2]) << 16) | (to_byte(k[3]) << 24)
        rid_val = 0
        if isinstance(v, dict):
            rid_val = list(v.values())[0] if v else 0
        elif isinstance(v, list):
            rid_val = to_byte(v[0]) | (to_byte(v[1]) << 8) | \
                      (to_byte(v[2]) << 16) | (to_byte(v[3]) << 24)
        if port_val > 0:
            occupied[port_val] = rid_val

    # Найти конфликты (порт занят ДРУГИМ правилом)
    conflicts = {p: occupied[p] for p in ports_list
                 if p in occupied and occupied[p] != rule_id}
    if conflicts:
        rules_saved = load_rules_file(rules_file)
        print("\n⚠️  Некоторые порты уже заняты другими правилами:\n")
        for port, rid in conflicts.items():
            saved = rules_saved.get(str(rid), {})
            mode_str = get_mode_str(saved.get('mode'))
            ports_str2 = ", ".join(str(p) for p in saved.get('ports', []))
            dl = saved.get('down_mbs', '?')
            ul = saved.get('up_mbs',   '?')
            print(f"  Порт {port} → Правило #{rid}: режим={mode_str}, "
                  f"порты=[{ports_str2}], DL={dl} МБ/с, UL={ul} МБ/с")
        print()
        answer = input("  Переназначить эти порты на новое правило? [y/N]: ").strip().lower()
        if answer not in ('y', 'да', 'yes'):
            print("  Отмена. Правило не применено.")
            return False

    # Удалить СТАРЫЕ порты ЭТОГО правила из port_rule_map  
    rules_saved = load_rules_file(rules_file)
    old_rule = rules_saved.get(str(rule_id), {})
    for old_port in old_rule.get('ports', []):
        bpftool_map_delete(pin_dir, "port_rule_map", u32_key_hex(old_port))

    # Записать конфиг правила в config_map[rule_id]
    payload = pack_rule(mode, ports_list, d_bps, u_bps, pen_bps, burst_b, win_ns, pen_ns)
    payload_hex = " ".join(f"{b:02x}" for b in payload)
    bpftool_map_update(pin_dir, "config_map", u32_key_hex(rule_id), payload_hex)

    # Прописать порты в port_rule_map
    rid_hex = u32_key_hex(rule_id)
    for port in ports_list:
        bpftool_map_update(pin_dir, "port_rule_map", u32_key_hex(port), rid_hex)

    # Сохранить в JSON
    rules_saved[str(rule_id)] = {
        'rule_id': rule_id, 'mode': mode,
        'ports': ports_list,
        'down_mbs': d_mbs, 'up_mbs': u_mbs, 'pen_mbs': pen_mbs,
        'burst_mb': burst_mb, 'win_sec': win_sec, 'pen_sec': pen_sec,
    }
    save_rules_file(rules_saved, rules_file)

    ports_display = ", ".join(str(p) for p in ports_list) if ports_list else "ВСЕ ПОРТЫ"
    print(f"\n✅ Правило #{rule_id} применено:")
    print(f"   Режим   : {get_mode_str(mode)}")
    print(f"   Порты   : {ports_display}")
    print(f"   Download: {d_mbs} МБ/с  = {d_mbs*8:.0f} Мбит/с")
    print(f"   Upload  : {u_mbs} МБ/с  = {u_mbs*8:.0f} Мбит/с")
    if mode == 2:
        print(f"   Burst   : {burst_mb} МБ  в окне {win_sec}с")
        print(f"   Штраф   : {pen_mbs} МБ/с  на {pen_sec}с")
    return True


def delete_rule(pin_dir, rule_id, rules_file=DEFAULT_RULES_FILE):
    """Удаляет правило: обнуляет config_map, удаляет порты из port_rule_map."""
    rules_saved = load_rules_file(rules_file)
    rule_key = str(rule_id)
    if rule_key not in rules_saved:
        print(f"⚠️  Правило #{rule_id} не найдено в конфиге.")
        return

    old_rule = rules_saved[rule_key]
    for port in old_rule.get('ports', []):
        bpftool_map_delete(pin_dir, "port_rule_map", u32_key_hex(port))

    # Записать нулевой режим в config_map (mode=0 = off)
    zero_payload = pack_rule(0, [], 0, 0, 0, 0, 0, 0)
    zero_hex = " ".join(f"{b:02x}" for b in zero_payload)
    bpftool_map_update(pin_dir, "config_map", u32_key_hex(rule_id), zero_hex)

    del rules_saved[rule_key]
    save_rules_file(rules_saved, rules_file)
    print(f"✅ Правило #{rule_id} удалено.")


def restore_rules(pin_dir, rules_file=DEFAULT_RULES_FILE):
    """Восстанавливает все правила из rules.json. Используется при старте сервиса."""
    rules = load_rules_file(rules_file)
    if not rules:
        print("ℹ️  Нет сохранённых правил для восстановления.")
        return
    print(f"ℹ️  Восстанавливаю {len(rules)} правил(о)...")
    for rid_str, r in rules.items():
        set_rule(
            pin_dir       = pin_dir,
            rule_id       = int(rid_str),
            mode          = r['mode'],
            ports_str     = ",".join(str(p) for p in r['ports']),
            d_mbs         = r['down_mbs'],
            u_mbs         = r['up_mbs'],
            burst_mb      = r['burst_mb'],
            win_sec       = r['win_sec'],
            pen_sec       = r['pen_sec'],
            pen_mbs       = r.get('pen_mbs', 0.1),
            rules_file    = rules_file,
        )

# ────────────────────────────────────────────────────────────
# Whitelist (Белый список)
# ────────────────────────────────────────────────────────────

def ip_to_key_hex(ip_str):
    """Конвертирует строковый IP в 16-байтный hex-ключ (4x u32 LE)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            # IPv4: 4 bytes + 12 bytes zeros
            return " ".join(f"{b:02x}" for b in ip.packed) + " 00 00 00 00 00 00 00 00 00 00 00 00"
        else:
            # IPv6: 16 bytes
            return " ".join(f"{b:02x}" for b in ip.packed)
    except ValueError:
        return None

def sync_whitelist(pin_dir, whitelist_file):
    """Синхронизирует BPF-карту whitelist_map с содержимым файла."""
    map_name = "whitelist_map"
    pin_path = os.path.join(pin_dir, map_name)
    if not os.path.exists(pin_path):
        print(f"ℹ️  BPF map {map_name} не найден. Пропуск.")
        return

    # Очистка текущей карты
    existing = bpftool_map_dump(pin_dir, map_name)
    for entry in existing:
        k = entry.get('key')
        if isinstance(k, list):
            k_hex = " ".join(f"{b:02x}" if isinstance(b, int) else b for b in k)
            bpftool_map_delete(pin_dir, map_name, k_hex)

    if not os.path.exists(whitelist_file):
        print(f"ℹ️  Файл белого списка не существует: {whitelist_file}. Создаем пустой.")
        # Create empty template
        os.makedirs(os.path.dirname(whitelist_file), exist_ok=True)
        with open(whitelist_file, "w", encoding="utf-8") as f:
            f.write("# Белый список IP-адресов (Whitelist)\n")
            f.write("# Указанные здесь IP будут полностью игнорировать шейпер (скачивание/отдача на максимальной скорости).\n")
            f.write("# Формат: IP-адрес # Комментарий (необязательно)\n")
            f.write("# Пример:\n")
            f.write("# 192.168.1.100 # Мой компьютер\n")
            f.write("# 2001:db8::1   # Мой IPv6 сервер\n")
        return

    count = 0
    with open(whitelist_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Извлекаем IP (всё, что до первого символа '#')
            ip_part = line.split("#")[0].strip()
            
            key_hex = ip_to_key_hex(ip_part)
            if key_hex:
                # 01 = просто флаг, что IP в белом списке
                bpftool_map_update(pin_dir, map_name, key_hex, "01")
                count += 1
            else:
                print(f"⚠️  Неверный IP-адрес в белом списке: {ip_part}")
                
    print(f"✅ В белый список (whitelist) загружено IP-адресов: {count}")



def list_rules(pin_dir, rules_file=DEFAULT_RULES_FILE):
    """Показывает сводку всех активных правил."""
    rules = load_rules_file(rules_file)
    sep = "─" * 62
    ok  = "✔"
    print(f"\n  \033[1;37mАктивные правила шейпера:\033[0m")
    print(f"  {sep}")
    if not rules:
        print("  Нет настроенных правил. Используй 'set' для добавления.")
        print(f"  {sep}")
        return
    for rid_str, r in sorted(rules.items(), key=lambda x: int(x[0])):
        mode_str  = get_mode_str_color(r['mode'])
        ports_str = ", ".join(str(p) for p in r['ports']) if r['ports'] else "ВСЕ ПОРТЫ"
        print(f"  {ok} Правило \033[1;37m#{rid_str}\033[0m | {mode_str}")
        print(f"    Порты : {ports_str}")
        print(f"    DL/UL : {r['down_mbs']} / {r['up_mbs']} МБ/с")
        if r['mode'] == 2:
            print(f"    Burst : {r['burst_mb']} МБ в {r['win_sec']}с | Штраф: {r.get('pen_mbs',0.1)} МБ/с на {r['pen_sec']}с")
        print(f"  {sep}")

# ────────────────────────────────────────────────────────────
# Статистика
# ────────────────────────────────────────────────────────────

def get_ip_from_rule_key(key):
    """Разбирает struct user_rule_key (24 байта: addr[4]+rule_id+_pad)."""
    if isinstance(key, dict):
        addr = key.get('addr', [0, 0, 0, 0])
        rule_id = int(key.get('rule_id', 0))
        parts = []
        for w in addr:
            parts.append(int(w))
    elif isinstance(key, list):
        # 24 bytes raw: addr[0..3] as 4 u32 LE, then rule_id u32 LE, then _pad u32
        def rb(x): return x if isinstance(x, int) else int(x, 16)
        def r32(lst, off): return rb(lst[off])|(rb(lst[off+1])<<8)|(rb(lst[off+2])<<16)|(rb(lst[off+3])<<24)
        addr = [r32(key, i*4) for i in range(4)]
        rule_id = r32(key, 16)
        parts = addr
    else:
        return "?.?.?.?", 0

    # Определяем IPv4 или IPv6
    is_ipv4_mapped = (parts[1] == 0 and parts[2] == 0 and parts[3] == 0)
    if is_ipv4_mapped:
        a = parts[0]
        ip_str = f"{a & 0xFF}.{(a>>8) & 0xFF}.{(a>>16) & 0xFF}.{(a>>24) & 0xFF}"
    else:
        ip_parts = []
        for w in parts:
            ip_parts.append(f"{(w >> 16) & 0xFFFF:04x}:{w & 0xFFFF:04x}")
        ip_str = ":".join(ip_parts)

    return ip_str, rule_id


def get_user_state_value(value, field, byte_offset, byte_size=8):
    """Читает поле из value — поддерживает BTF-dict и raw-list."""
    if isinstance(value, dict):
        v = value.get(field, 0)
        return int(v) if isinstance(v, (int, float)) else 0
    elif isinstance(value, list):
        def rb(x): return x if isinstance(x, int) else int(x, 16)
        chunk = value[byte_offset:byte_offset + byte_size]
        result = 0
        for i, b in enumerate(chunk):
            result |= rb(b) << (8 * i)
        return result
    return 0


def dump_stats(pin_dir, rule_filter=None, full=False, rules_file=DEFAULT_RULES_FILE):
    """Выводит статистику с разбивкой по правилам."""
    rules_saved = load_rules_file(rules_file)
    sep   = "─" * 62
    sep_h = "═" * 62
    dl    = "↓"
    ul    = "↑"
    ok    = "✔"
    warn  = "⚡"

    # Читаем оба user_state map
    entries_down = bpftool_map_dump(pin_dir, "user_state_map_down")
    entries_up   = bpftool_map_dump(pin_dir, "user_state_map_up")

    # struct user_state offsets:
    # bytes_in_window[0:8], window_start[8:16], penalty_end[16:24],
    # last_departure[24:32], total_bytes[32:40], is_penalized[40:44]

    # Группируем по {rule_id → {ip → {down, up, pen_d, pen_u}}}
    stats_by_rule = {}

    for entry in entries_down:
        ip, rule_id = get_ip_from_rule_key(entry.get('key', {}))
        if ip.startswith('?'): continue
        total     = get_user_state_value(entry['value'], 'total_bytes',  32, 8)
        penalized = get_user_state_value(entry['value'], 'is_penalized', 40, 4)
        stats_by_rule.setdefault(rule_id, {})
        stats_by_rule[rule_id].setdefault(ip, {'down': 0, 'up': 0, 'pen_d': 0, 'pen_u': 0})
        stats_by_rule[rule_id][ip]['down']  = total
        stats_by_rule[rule_id][ip]['pen_d'] = penalized

    for entry in entries_up:
        ip, rule_id = get_ip_from_rule_key(entry.get('key', {}))
        if ip.startswith('?'): continue
        total     = get_user_state_value(entry['value'], 'total_bytes',  32, 8)
        penalized = get_user_state_value(entry['value'], 'is_penalized', 40, 4)
        stats_by_rule.setdefault(rule_id, {})
        stats_by_rule[rule_id].setdefault(ip, {'down': 0, 'up': 0, 'pen_d': 0, 'pen_u': 0})
        stats_by_rule[rule_id][ip]['up']    = total
        stats_by_rule[rule_id][ip]['pen_u'] = penalized

    # Заголовок с правилами
    print(f"\n  \033[0;36m{sep_h}\033[0m")
    print(f"  \033[0;33m  Настроенные правила:\033[0m")
    if not rules_saved:
        print("    Нет активных правил.")
    for rid_str, r in sorted(rules_saved.items(), key=lambda x: int(x[0])):
        rid = int(rid_str)
        if rule_filter is not None and rid != rule_filter:
            continue
        mode_str  = get_mode_str_color(r['mode'])
        ports_str = ", ".join(str(p) for p in r['ports']) if r['ports'] else "ВСЕ ПОРТЫ"
        n_users   = len(stats_by_rule.get(rid, {}))
        print(f"  {ok} Правило \033[1;37m#{rid_str}\033[0m | {mode_str} | "
              f"порты: {ports_str} | DL/UL: {r['down_mbs']}/{r['up_mbs']} МБ/с | "
              f"активных IP: {n_users}")
    print(f"  \033[0;36m{sep_h}\033[0m")

    # Статистика по каждому правилу
    for rule_id_str in sorted(rules_saved.keys(), key=lambda x: int(x)):
        rule_id = int(rule_id_str)
        if rule_filter is not None and rule_id != rule_filter:
            continue
            
        rule_info = rules_saved.get(rule_id_str, {})
        mode      = rule_info.get('mode', 0)
        d_mbs     = rule_info.get('down_mbs', 0)
        pen_mbs   = rule_info.get('pen_mbs', 0.1)
        ports_d   = ", ".join(str(p) for p in rule_info.get('ports', [])) or "ВСЕ"
        mode_str  = get_mode_str(mode)

        ips_data  = stats_by_rule.get(rule_id, {})
        if not ips_data:
            print(f"\n  \033[1;37mПравило #{rule_id}\033[0m"
                  f"  [{mode_str} | порты: {ports_d}]  — Нет трафика:")
            print(f"  {sep}")
            print("  Трафик через данное правило ещё не проходил.")
            print(f"  {sep}")
            continue

        all_sorted = sorted(ips_data.keys(),
                            key=lambda x: ips_data[x]['down'] + ips_data[x]['up'],
                            reverse=True)
        display   = all_sorted if full else all_sorted[:10]
        total_ips = len(all_sorted)

        label = f"Весь список ({total_ips} IP)" if full else f"Топ-{min(10,total_ips)} из {total_ips}"
        print(f"\n  \033[1;37mПравило #{rule_id}\033[0m"
              f"  [{mode_str} | порты: {ports_d}]  — {label}:")
        print(f"  {sep}")
        hdr = f"  {'IP-адрес':<30} {dl+' Скачано':<13} {ul+' Загружено':<13} {'Лимит'}"
        print(f"\033[0;90m{hdr}\033[0m")
        print(f"  {sep}")

        for idx, ip in enumerate(display):
            s = ips_data[ip]
            is_pen = s['pen_d'] or s['pen_u']

            if mode == 2 and is_pen:
                limit = f"\033[0;31m{warn} ШТРАФ {pen_mbs:.1f} МБ/с\033[0m"
            elif d_mbs:
                limit = f"\033[0;32m{ok} {d_mbs:.1f} МБ/с\033[0m"
            else:
                limit = "⚠ неизв."

            print(f"  {ip:<30} {format_bytes(s['down']):<13} "
                  f"{format_bytes(s['up']):<13} {limit}")

            if full and (idx + 1) % 40 == 0 and (idx + 1) < len(display):
                try:
                    input(f"\n  [Ещё {len(display)-(idx+1)} IP. Enter — продолжить, Ctrl+C — стоп]")
                except (KeyboardInterrupt, EOFError):
                    print("\n  Остановлено.")
                    break

        print(f"  {sep}")
        print(f"  Всего уникальных IP в правиле #{rule_id}: {total_ips}")

# ────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description="Reshala eBPF Traffic Limiter Controller v4.0 (Multi-Rule)")
    parser.add_argument("--pin-dir",    default=DEFAULT_PIN_DIR)
    parser.add_argument("--rules-file", default=DEFAULT_RULES_FILE)

    sub = parser.add_subparsers(dest="command")

    # set — добавить/обновить правило
    p_set = sub.add_parser("set", help="Добавить/обновить правило")
    p_set.add_argument("--rule-id", type=int, required=True, help="ID правила (0..31)")
    p_set.add_argument("--mode",    type=int, choices=[1, 2, 3], required=True)
    p_set.add_argument("--ports",   type=str, default="0",
                       help="Порты через запятую (0=нет фильтрации)")
    p_set.add_argument("--down",    type=float, required=True, help="Download МБ/с")
    p_set.add_argument("--up",      type=float, required=True, help="Upload МБ/с")
    p_set.add_argument("--pen",     type=float, default=0.1,   help="Штрафная скорость МБ/с")
    p_set.add_argument("--burst",   type=float, default=70.0,  help="Burst МБайт")
    p_set.add_argument("--win",     type=int,   default=10,    help="Окно burst (сек)")
    p_set.add_argument("--pen-sec", type=int,   default=60,    help="Длительность штрафа (сек)")

    # delete — удалить правило
    p_del = sub.add_parser("delete", help="Удалить правило")
    p_del.add_argument("--rule-id", type=int, required=True)

    # rules — список правил
    sub.add_parser("rules", help="Показать все активные правила")

    # whitelist-sync — синхронизировать белый список
    p_wl = sub.add_parser("whitelist-sync", help="Синхронизировать белый список IP из файла")
    p_wl.add_argument("--file", type=str, required=True, help="Путь к файлу белого списка")

    # restore — восстановить правила из JSON (для ExecStart сервиса)
    sub.add_parser("restore", help="Восстановить все правила из rules.json")

    # status — статистика
    p_stat = sub.add_parser("status", help="Показать статистику")
    p_stat.add_argument("--rule-id", type=int, default=None,
                        help="Показать только это правило")
    p_stat.add_argument("--full", action="store_true",
                        help="Показать весь список IP (не топ-10)")

    return parser


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Ошибка: скрипт должен запускаться от root.")
        sys.exit(1)

    parser = build_parser()
    args   = parser.parse_args()
    pin    = args.pin_dir
    rf     = args.rules_file

    if args.command == "set":
        set_rule(pin, args.rule_id, args.mode, args.ports,
                 args.down, args.up, args.burst, args.win, args.pen_sec,
                 pen_mbs=args.pen, rules_file=rf)

    elif args.command == "delete":
        delete_rule(pin, args.rule_id, rules_file=rf)

    elif args.command == "rules":
        list_rules(pin, rules_file=rf)

    elif args.command == "whitelist-sync":
        sync_whitelist(pin, whitelist_file=args.file)

    elif args.command == "restore":
        restore_rules(pin, rules_file=rf)

    elif args.command == "status":
        dump_stats(pin,
                   rule_filter=args.rule_id,
                   full=getattr(args, 'full', False),
                   rules_file=rf)
    else:
        parser.print_help()
