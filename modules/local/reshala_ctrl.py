#!/usr/bin/env python3
# ============================================================ #
# ==        RESHALA eBPF TRAFFIC LIMITER CONTROLLER         == #
# ==              reshala_ctrl.py  v3.3                     == #
# ============================================================ #
#
# Управляет BPF-картами шейпера через pinned path (/sys/fs/bpf/reshala/maps/).
# --pin-dir может стоять ДО или ПОСЛЕ subcommand (set/status).
#

import sys
import struct
import subprocess
import argparse
import os
import json

DEFAULT_PIN_DIR = "/sys/fs/bpf/reshala/maps"
MAX_PORTS = 32  # Must match #define MAX_PORTS in shaper.bpf.c

def parse_ports(ports_str):
    """Парсит строку портов '443,80,0' -> [443, 80] | '0' -> []"""
    try:
        parts = [int(p.strip()) for p in str(ports_str).split(',') if p.strip()]
    except ValueError:
        return []
    # 0 = все порты (пустой список = нет фильтрации)
    ports = [p for p in parts if 0 < p <= 65535]
    return ports[:MAX_PORTS]

def run_cmd(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        return result.stdout.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {cmd}")
        print(f"Stderr: {e.stderr.strip()}")
        sys.exit(1)

def bpftool_map_update(pin_dir, map_name, key_hex, value_hex):
    """Обновляет карту через pinned path."""
    pin_path = os.path.join(pin_dir, map_name)
    if not os.path.exists(pin_path):
        print(f"❌ BPF map pin не найден: {pin_path}")
        print(f"   Убедись что сервис запущен: systemctl status reshala-traffic-limiter")
        sys.exit(1)
    cmd = f"bpftool map update pinned {pin_path} key hex {key_hex} value hex {value_hex}"
    run_cmd(cmd)

def bpftool_map_dump(pin_dir, map_name):
    """Читает карту через pinned path."""
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

def set_config(pin_dir, mode, ports_str, d_mbs, u_mbs, burst_mb, win_sec, pen_sec):
    # МБ/с → байт/с
    d_bps = int(d_mbs * 1024 * 1024)
    u_bps = int(u_mbs * 1024 * 1024)
    burst_bytes = int(burst_mb * 1024 * 1024)
    win_ns = int(win_sec * 1_000_000_000)
    pen_ns = int(pen_sec * 1_000_000_000)

    # Парсим и дополняем до MAX_PORTS нулями
    ports_list = parse_ports(ports_str)
    num_ports = len(ports_list)
    ports_padded = ports_list + [0] * (MAX_PORTS - len(ports_list))

    # struct config_data (C-layout):
    #   __u32 mode                     4 bytes  offset 0
    #   __u32 num_ports                4 bytes  offset 4
    #   __u32 ports[MAX_PORTS=16]     64 bytes  offset 8
    #   __u64 normal_rate_bps          8 bytes  offset 72
    #   __u64 penalty_rate_bps         8 bytes  offset 80
    #   __u64 burst_bytes_limit        8 bytes  offset 88
    #   __u64 window_time_ns           8 bytes  offset 96
    #   __u64 penalty_time_ns          8 bytes  offset 104
    #   Total: 112 bytes
    fmt = f"<I I {MAX_PORTS}I Q Q Q Q Q"
    d_payload = struct.pack(fmt, mode, num_ports, *ports_padded, d_bps, d_bps, burst_bytes, win_ns, pen_ns)
    u_payload = struct.pack(fmt, mode, num_ports, *ports_padded, u_bps, u_bps, burst_bytes, win_ns, pen_ns)

    d_hex = " ".join([f"{b:02x}" for b in d_payload])
    u_hex = " ".join([f"{b:02x}" for b in u_payload])

    bpftool_map_update(pin_dir, "config_map", "00 00 00 00", d_hex)
    bpftool_map_update(pin_dir, "config_map", "01 00 00 00", u_hex)

    ports_display = ", ".join(str(p) for p in ports_list) if ports_list else "ВСЕ ПОРТЫ"
    print(f"✅ Конфигурация применена:")
    print(f"   Режим   : {'Статика' if mode == 1 else 'Динамика'}")
    print(f"   Порты   : {ports_display}")
    print(f"   Download: {d_mbs} МБ/с  = {d_mbs * 8} Мбит/с  ({d_bps:,} байт/с)")
    print(f"   Upload  : {u_mbs} МБ/с  = {u_mbs * 8} Мбит/с  ({u_bps:,} байт/с)")
    if mode == 2:
        print(f"   Burst   : {burst_mb} МБ в окне {win_sec}с")
        print(f"   Штраф   : {pen_sec}с")


def format_bytes(n):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} ПБ"

def get_ip(key):
    """Разбирает struct ip_key.
    bpftool может выдавать:
    - BTF-формат:  {"addr": [int, int, int, int]}
    - Raw-формат:  [b0, b1, ..., b15]  (16 байт, 4x u32 little-endian)
    """
    if isinstance(key, dict):
        ip_parts = key.get('addr', [0, 0, 0, 0])
    elif isinstance(key, list) and len(key) >= 16:
        # bpftool raw format: каждый элемент может быть int или hex-строкой ("0a")
        def to_byte(x):
            if isinstance(x, int): return x
            return int(x, 16)  # "0a" → 10
        ip_parts = []
        for i in range(4):
            val = to_byte(key[i*4]) | (to_byte(key[i*4+1]) << 8) | \
                  (to_byte(key[i*4+2]) << 16) | (to_byte(key[i*4+3]) << 24)
            ip_parts.append(val)
    else:
        return str(key)

    if ip_parts[1] == 0 and ip_parts[2] == 0 and ip_parts[3] == 0:
        raw = ip_parts[0]
        return f"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}"
    # IPv6
    parts = []
    for p in ip_parts:
        parts.append(f"{(p >> 16) & 0xFFFF:04x}:{p & 0xFFFF:04x}")
    return ":".join(parts)

def get_value_field(value, field_name, byte_offset, byte_size=8):
    """Читает поле из value — поддерживает BTF-dict и raw-list.
    
    bpftool может вернуть:
    - BTF-формат:  {"total_bytes": 12345, ...}  → dict с именованными полями
    - Raw-формат:  ["0a", "00", "b3", ...]       → список hex-строк (без BTF)
    - Raw-формат:  [10, 0, 179, ...]             → список int (редко)
    """
    if isinstance(value, dict):
        v = value.get(field_name, 0)
        # Иногда BTF возвращает вложенный dict или список для составных типов
        if isinstance(v, (int, float)):
            return int(v)
        return 0
    elif isinstance(value, list):
        def to_byte(x):
            if isinstance(x, int): return x
            try: return int(x, 16)   # "0a" → 10
            except (ValueError, TypeError): return 0
        chunk = value[byte_offset:byte_offset + byte_size]
        result = 0
        for i, b in enumerate(chunk):
            result |= to_byte(b) << (8 * i)
        return result
    return 0

def dump_stats(pin_dir):
    users_d = bpftool_map_dump(pin_dir, "user_state_map_down")
    users_u = bpftool_map_dump(pin_dir, "user_state_map_up")

    # struct user_state field offsets:
    # bytes_in_window[0:8], window_start_time[8:16], penalty_end_time[16:24],
    # last_departure_time[24:32], total_bytes[32:40], is_penalized[40:44]
    stats = {}
    for u in users_d:
        ip = get_ip(u['key'])
        total = get_value_field(u['value'], 'total_bytes', 32, 8)
        penalized = get_value_field(u['value'], 'is_penalized', 40, 4)
        stats[ip] = {"down": total, "up": 0, "pen_d": penalized, "pen_u": 0}

    for u in users_u:
        ip = get_ip(u['key'])
        total = get_value_field(u['value'], 'total_bytes', 32, 8)
        penalized = get_value_field(u['value'], 'is_penalized', 40, 4)
        if ip not in stats:
            stats[ip] = {"down": 0, "up": 0, "pen_d": 0, "pen_u": 0}
        stats[ip]["up"] = total
        stats[ip]["pen_u"] = penalized

    if not stats:
        print("Нет данных. Трафик ещё не проходил через шейпер.")
        return

    sorted_ips = sorted(stats.keys(), key=lambda x: stats[x]['down'] + stats[x]['up'], reverse=True)
    print(f"{'IP-адрес':<40} | {'Скачано':<15} | {'Загружено':<15} | Штраф")
    print("-" * 95)
    for ip in sorted_ips:
        s = stats[ip]
        pen = "ДА ⚠️" if (s['pen_d'] or s['pen_u']) else "нет"
        print(f"{ip:<40} | {format_bytes(s['down']):<15} | {format_bytes(s['up']):<15} | {pen}")


def build_parser():
    parser = argparse.ArgumentParser(description="Reshala eBPF Traffic Limiter Controller v3.3")
    # --pin-dir определён на КОРНЕВОМ парсере — должен идти ПЕРЕД subcommand
    parser.add_argument("--pin-dir", default=DEFAULT_PIN_DIR,
                        help=f"Путь к пинам BPF-карт (default: {DEFAULT_PIN_DIR})")

    subparsers = parser.add_subparsers(dest="command")

    set_parser = subparsers.add_parser("set", help="Применить конфигурацию")
    set_parser.add_argument("--mode", type=int, choices=[1, 2], required=True)
    set_parser.add_argument("--ports", type=str, default="0",
                            help="Порты через запятую (0=все порты). Пример: 443,80,8080")
    set_parser.add_argument("--down", type=float, required=True, help="Download (МБ/с)")
    set_parser.add_argument("--up", type=float, required=True, help="Upload (МБ/с)")
    set_parser.add_argument("--burst", type=float, default=70.0)
    set_parser.add_argument("--win", type=int, default=10)
    set_parser.add_argument("--pen", type=int, default=60)

    subparsers.add_parser("status", help="Показать статистику по IP")
    return parser


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Ошибка: скрипт должен запускаться от root.")
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "set":
        set_config(args.pin_dir, args.mode, args.ports, args.down, args.up,
                   args.burst, args.win, args.pen)
    elif args.command == "status":
        dump_stats(args.pin_dir)
    else:
        parser.print_help()
