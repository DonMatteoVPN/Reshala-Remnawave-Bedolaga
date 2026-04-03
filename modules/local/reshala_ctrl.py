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

def set_config(pin_dir, mode, port, d_mbps, u_mbps, burst_mb, win_sec, pen_sec):
    # Конвертация: Мбит/с → байт/с, МБ → байт, с → нс
    d_bps = int((d_mbps * 1024 * 1024) / 8)
    u_bps = int((u_mbps * 1024 * 1024) / 8)
    burst_bytes = int(burst_mb * 1024 * 1024)
    win_ns = int(win_sec * 1_000_000_000)
    pen_ns = int(pen_sec * 1_000_000_000)

    # struct config_data: __u32 mode, __u32 target_port,
    #   __u64 normal_rate_bps, __u64 penalty_rate_bps,
    #   __u64 burst_bytes_limit, __u64 window_time_ns, __u64 penalty_time_ns
    d_payload = struct.pack("<I I Q Q Q Q Q", mode, port, d_bps, d_bps, burst_bytes, win_ns, pen_ns)
    u_payload = struct.pack("<I I Q Q Q Q Q", mode, port, u_bps, u_bps, burst_bytes, win_ns, pen_ns)

    d_hex = " ".join([f"{b:02x}" for b in d_payload])
    u_hex = " ".join([f"{b:02x}" for b in u_payload])

    # Index 0 = Download, Index 1 = Upload
    bpftool_map_update(pin_dir, "config_map", "00 00 00 00", d_hex)
    bpftool_map_update(pin_dir, "config_map", "01 00 00 00", u_hex)

    print(f"✅ Конфигурация применена:")
    print(f"   Режим   : {'Статика' if mode == 1 else 'Динамика'}")
    print(f"   Порт    : {port if port != 0 else 'Все'}")
    print(f"   Download: {d_mbps} Мбит/с  ({d_bps} байт/с)")
    print(f"   Upload  : {u_mbps} Мбит/с  ({u_bps} байт/с)")
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
    """Распаковывает struct ip_key { __u32 addr[4]; }."""
    ip_parts = key['addr']
    if ip_parts[1] == 0 and ip_parts[2] == 0 and ip_parts[3] == 0:
        raw = ip_parts[0]
        return f"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}"
    # IPv6
    parts = []
    for p in ip_parts:
        parts.append(f"{(p >> 16) & 0xFFFF:04x}:{p & 0xFFFF:04x}")
    return ":".join(parts)

def dump_stats(pin_dir):
    users_d = bpftool_map_dump(pin_dir, "user_state_map_down")
    users_u = bpftool_map_dump(pin_dir, "user_state_map_up")

    stats = {}
    for u in users_d:
        ip = get_ip(u['key'])
        stats[ip] = {
            "down": int(u['value']['total_bytes']),
            "up": 0,
            "pen_d": int(u['value']['is_penalized']),
            "pen_u": 0
        }
    for u in users_u:
        ip = get_ip(u['key'])
        if ip not in stats:
            stats[ip] = {"down": 0, "up": 0, "pen_d": 0, "pen_u": 0}
        stats[ip]["up"] = int(u['value']['total_bytes'])
        stats[ip]["pen_u"] = int(u['value']['is_penalized'])

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
    set_parser.add_argument("--port", type=int, default=0)
    set_parser.add_argument("--down", type=float, required=True, help="Download (Мбит/с)")
    set_parser.add_argument("--up", type=float, required=True, help="Upload (Мбит/с)")
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
        set_config(args.pin_dir, args.mode, args.port, args.down, args.up,
                   args.burst, args.win, args.pen)
    elif args.command == "status":
        dump_stats(args.pin_dir)
    else:
        parser.print_help()
