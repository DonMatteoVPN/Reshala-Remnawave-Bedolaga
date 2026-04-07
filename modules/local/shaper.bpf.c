/*
 * Reshala Traffic Limiter (eBPF + EDT Edition)
 * v4.0: Multi-Rule support — each port group gets its own rate limit.
 *
 * Architecture:
 *   port_rule_map  : port (u32) → rule_id (u32)
 *   config_map     : rule_id (u32) → struct rule_config
 *   user_state_map : {ip[4], rule_id} → struct user_state  (per direction)
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PORTS  32
#define MAX_RULES  32

/* Per-rule configuration */
struct rule_config {
    __u32 mode;                    /* 0=off, 1=static, 2=dynamic */
    __u32 num_ports;               /* info only — routing done via port_rule_map */
    __u32 ports[MAX_PORTS];        /* info only */
    __u64 down_rate_bps;           /* download rate (bytes/s) */
    __u64 up_rate_bps;             /* upload rate  (bytes/s) */
    __u64 penalty_rate_bps;        /* penalty rate (bytes/s) */
    __u64 burst_bytes_limit;       /* burst threshold before penalty */
    __u64 window_time_ns;          /* burst measurement window */
    __u64 penalty_time_ns;         /* how long penalty lasts */
};

/* Key for per-user-per-rule state */
struct user_rule_key {
    __u32 addr[4];   /* IPv4 or IPv6 */
    __u32 rule_id;
    __u32 _pad;      /* alignment */
};

/* Per-user EDT state */
struct user_state {
    __u64 bytes_in_window;
    __u64 window_start_time;
    __u64 penalty_end_time;
    __u64 last_departure_time;
    __u64 total_bytes;
    __u32 is_penalized;
    __u32 _pad;
};

/* port → rule_id  (hash map, keyed by u32 port number) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, __u32);
} port_rule_map SEC(".maps");

/* rule_id → rule_config  (array, indexed by rule_id 0..MAX_RULES-1) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key,   __u32);
    __type(value, struct rule_config);
} config_map SEC(".maps");

/* Download user states  ({ip, rule_id} → user_state) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct user_rule_key);
    __type(value, struct user_state);
} user_state_map_down SEC(".maps");

/* Upload user states  ({ip, rule_id} → user_state) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct user_rule_key);
    __type(value, struct user_state);
} user_state_map_up SEC(".maps");

/*
 * Core shaping function.
 *  direction: 0 = Download (main iface EGRESS → user), 1 = Upload (IFB EGRESS ← user)
 *  user_map:  pointer to user_state_map_down or user_state_map_up
 */
static __always_inline int process_packet(
    struct __sk_buff *skb, __u32 direction, void *user_map)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct user_rule_key user_key = {0};
    __u16 sport = 0, dport = 0;
    __u8  proto = 0;
    void *trans_hdr = NULL;

    /* ── Parse IP header ── */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

        /* DL: shape by daddr (packet going TO user)
         * UL: shape by saddr (packet coming FROM user) */
        if (direction == 0) user_key.addr[0] = ip->daddr;
        else                user_key.addr[0] = ip->saddr;

        proto    = ip->protocol;
        trans_hdr = (void *)ip + (ip->ihl * 4);

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end) return TC_ACT_OK;

        if (direction == 0) __builtin_memcpy(user_key.addr, ipv6->daddr.in6_u.u6_addr32, 16);
        else                __builtin_memcpy(user_key.addr, ipv6->saddr.in6_u.u6_addr32, 16);

        proto    = ipv6->nexthdr;
        trans_hdr = (void *)(ipv6 + 1);
    } else {
        return TC_ACT_OK;
    }

    /* ── Parse transport ports ── */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)trans_hdr;
        if ((void *)(tcp + 1) <= data_end) {
            sport = bpf_ntohs(tcp->source);
            dport = bpf_ntohs(tcp->dest);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)trans_hdr;
        if ((void *)(udp + 1) <= data_end) {
            sport = bpf_ntohs(udp->source);
            dport = bpf_ntohs(udp->dest);
        }
    }

    /* ── Port → Rule lookup ──
     * For DL (server→user): sport = server listening port  → match sport
     * For UL (user→server): dport = server listening port  → match dport
     * We try both so the same port_rule_map works for both directions.
     */
    __u32 *rule_id_p = NULL;
    __u32  s32 = sport, d32 = dport;

    if (s32 > 0) rule_id_p = bpf_map_lookup_elem(&port_rule_map, &s32);
    if (!rule_id_p && d32 > 0) rule_id_p = bpf_map_lookup_elem(&port_rule_map, &d32);
    
    /* Fallback для правила "ВСЕ ПОРТЫ" (порт 0) */
    if (!rule_id_p) {
        __u32 zero = 0;
        rule_id_p = bpf_map_lookup_elem(&port_rule_map, &zero);
    }
    
    if (!rule_id_p) return TC_ACT_OK;   /* port not in any rule → pass */

    __u32 rule_id = *rule_id_p;
    if (rule_id >= MAX_RULES) return TC_ACT_OK;

    /* ── Load rule config ── */
    struct rule_config *conf = bpf_map_lookup_elem(&config_map, &rule_id);
    if (!conf || conf->mode == 0) return TC_ACT_OK;

    /* ── User state (keyed by {ip, rule_id}) ── */
    user_key.rule_id = rule_id;
    if (conf->mode == 3) {
        user_key.addr[0] = 0;
        user_key.addr[1] = 0;
        user_key.addr[2] = 0;
        user_key.addr[3] = 0;
    }

    struct user_state *state = bpf_map_lookup_elem(user_map, &user_key);
    __u64 now        = bpf_ktime_get_ns();
    __u32 packet_len = skb->len;

    if (!state) {
        struct user_state ns = {
            .window_start_time  = now,
            .last_departure_time = now,
            .total_bytes        = packet_len,
        };
        bpf_map_update_elem(user_map, &user_key, &ns, BPF_ANY);
        return TC_ACT_OK;
    }

    if (conf->mode == 3) {
        state->total_bytes += packet_len;
    } else {
        __sync_fetch_and_add(&state->total_bytes, packet_len);
    }

    /* ── Dynamic burst/penalty logic ── */
    if (conf->mode == 2) {
        if (state->is_penalized && now > state->penalty_end_time) {
            state->is_penalized    = 0;
            state->window_start_time = now;
            state->bytes_in_window   = 0;
        }
        if (!state->is_penalized) {
            if (now - state->window_start_time > conf->window_time_ns) {
                state->window_start_time = now;
                state->bytes_in_window   = 0;
            }
            state->bytes_in_window += packet_len;
            if (state->bytes_in_window > conf->burst_bytes_limit) {
                state->is_penalized   = 1;
                state->penalty_end_time = now + conf->penalty_time_ns;
            }
        }
    }

    /* ── EDT shaping ── */
    __u64 rate = (direction == 0) ? conf->down_rate_bps : conf->up_rate_bps;
    if (conf->mode == 2 && state->is_penalized) rate = conf->penalty_rate_bps;
    if (rate == 0) return TC_ACT_SHOT; /* rate 0 = drop packet (full block) */

    if (direction == 0) {
        /* ── Egress (Download): EDT shaping ── */
        __u64 delay_ns       = ((__u64)packet_len * 1000000000ULL) / rate;
        __u64 departure_time = state->last_departure_time;
        if (now > departure_time) departure_time = now;
        departure_time += delay_ns;

        if (departure_time - now > 2000000000ULL) return TC_ACT_SHOT; /* > 2s ahead → drop */

        state->last_departure_time = departure_time;
        skb->tstamp = departure_time;
    } else {
        /* ── Ingress (Upload): Token Bucket Drop ── */
        __u64 delay_ns       = ((__u64)packet_len * 1000000000ULL) / rate;
        __u64 departure_time = state->last_departure_time;
        if (now > departure_time) departure_time = now;
        
        /* 200ms burst buffer. If we push the bucket $>200ms into the future, we drop. */
        if (departure_time - now > 200000000ULL) {
            return TC_ACT_SHOT; /* TCP window reduction */
        }
        
        state->last_departure_time = departure_time + delay_ns;
    }

    return TC_ACT_OK;
}

SEC("handle_down")
int handle_down(struct __sk_buff *skb) {
    return process_packet(skb, 0, &user_state_map_down);
}

SEC("handle_up")
int handle_up(struct __sk_buff *skb) {
    return process_packet(skb, 1, &user_state_map_up);
}

char _license[] SEC("license") = "GPL";
