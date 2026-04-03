#!/usr/bin/env python3
import sys
import struct
import subprocess
import argparse
import os
import json

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {cmd}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)

def set_config(mode, port, d_mbps, u_mbps, burst_mb, win_sec, pen_sec):
    # Convert units: Mbps/MB -> Bytes/Ns
    d_bps = int((d_mbps * 1024 * 1024) / 8)
    u_bps = int((u_mbps * 1024 * 1024) / 8)
    burst_bytes = int(burst_mb * 1024 * 1024)
    win_ns = int(win_sec * 1000000000)
    pen_ns = int(pen_sec * 1000000000)

    # Pack into C-style structure (struct config_data)
    # <I I Q Q Q Q Q
    d_payload = struct.pack("<I I Q Q Q Q Q", mode, port, d_bps, d_bps, burst_bytes, win_ns, pen_ns)
    u_payload = struct.pack("<I I Q Q Q Q Q", mode, port, u_bps, u_bps, burst_bytes, win_ns, pen_ns)
    
    d_hex = " ".join([f"{b:02x}" for b in d_payload])
    u_hex = " ".join([f"{b:02x}" for b in u_payload])
    
    try:
        # Index 0: Download
        run_cmd(f"bpftool map update name config_map key hex 00 00 00 00 value hex {d_hex}")
        # Index 1: Upload
        run_cmd(f"bpftool map update name config_map key hex 01 00 00 00 value hex {u_hex}")
        
        print(f"✅ Configuration applied:")
        print(f"   Mode: {'Static' if mode == 1 else 'Dynamic'}")
        print(f"   Port: {port if port != 0 else 'All'}")
        print(f"   Download: {d_mbps} Mbps")
        print(f"   Upload: {u_mbps} Mbps")
        if mode == 2:
            print(f"   Burst Limit: {burst_mb} MB in {win_sec}s window")
            print(f"   Penalty Time: {pen_sec}s")
    except Exception as e:
        print(f"❌ Failed to update BPF map: {e}")
        sys.exit(1)

def format_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if n < 1024: return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} EB"

def get_ip(key):
    ip_parts = key['addr']
    if ip_parts[1] == 0 and ip_parts[2] == 0 and ip_parts[3] == 0:
        raw = ip_parts[0]
        return f"{raw & 0xFF}.{(raw >> 8) & 0xFF}.{(raw >> 16) & 0xFF}.{(raw >> 24) & 0xFF}"
    return ":".join([f"{p:08x}" for p in ip_parts])

def dump_stats():
    try:
        data_d_raw = run_cmd("bpftool map dump name user_state_map_down -j")
        data_u_raw = run_cmd("bpftool map dump name user_state_map_up -j")
        
        users_d = json.loads(data_d_raw) if data_d_raw else []
        users_u = json.loads(data_u_raw) if data_u_raw else []

        # Merge stats
        stats = {}
        for u in users_d:
            ip = get_ip(u['key'])
            stats[ip] = {"down": int(u['value']['total_bytes']), "up": 0, "pen_d": int(u['value']['is_penalized']), "pen_u": 0}
        
        for u in users_u:
            ip = get_ip(u['key'])
            if ip not in stats: stats[ip] = {"down": 0, "up": 0, "pen_d": 0, "pen_u": 0}
            stats[ip]["up"] = int(u['value']['total_bytes'])
            stats[ip]["pen_u"] = int(u['value']['is_penalized'])

        if not stats:
            print("No active users found.")
            return

        sorted_ips = sorted(stats.keys(), key=lambda x: stats[x]['down'] + stats[x]['up'], reverse=True)

        print(f"{'IP Address':<40} | {'Download':<15} | {'Upload':<15} | {'Penalty'}")
        print("-" * 90)
        
        for ip in sorted_ips:
            s = stats[ip]
            pen_status = "YES" if (s['pen_d'] or s['pen_u']) else "no"
            print(f"{ip:<40} | {format_bytes(s['down']):<15} | {format_bytes(s['up']):<15} | {pen_status}")

    except Exception as e:
        print(f"❌ Failed to dump stats: {e}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Error: This script must be run as root.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Reshala Traffic Limiter Controller")
    subparsers = parser.add_subparsers(dest="command")

    set_parser = subparsers.add_parser("set", help="Apply configuration")
    set_parser.add_argument("--mode", type=int, choices=[1, 2], required=True)
    set_parser.add_argument("--port", type=int, default=0)
    set_parser.add_argument("--down", type=float, required=True, help="Download rate (Mbps)")
    set_parser.add_argument("--up", type=float, required=True, help="Upload rate (Mbps)")
    set_parser.add_argument("--burst", type=float, default=70.0)
    set_parser.add_argument("--win", type=int, default=10)
    set_parser.add_argument("--pen", type=int, default=60)

    subparsers.add_parser("status", help="Show current user statistics")

    args = parser.parse_args()

    if args.command == "set":
        set_config(args.mode, args.port, args.down, args.up, args.burst, args.win, args.pen)
    elif args.command == "status":
        dump_stats()
    else:
        parser.print_help()
