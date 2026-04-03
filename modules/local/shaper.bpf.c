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

/*
 * Reshala Traffic Limiter (eBPF + EDT Edition)
 * v3.1: Support separate Download/Upload paths.
 */

// Configuration structure
struct config_data {
    __u32 mode;                // 1 = Static, 2 = Dynamic
    __u32 target_port;         // Port to shape (0 = all)
    __u64 normal_rate_bps;     // Normal rate in bytes/sec
    __u64 penalty_rate_bps;    // Penalty rate in bytes/sec
    __u64 burst_bytes_limit;   // Allowed burst before penalty (bytes)
    __u64 window_time_ns;      // Time window for burst check (ns)
    __u64 penalty_time_ns;     // Duration of penalty (ns)
};

// Key for the user state map (supports IPv4/IPv6)
struct ip_key {
    __u32 addr[4];
};

// Per-user state
struct user_state {
    __u64 bytes_in_window;
    __u64 window_start_time;
    __u64 penalty_end_time;
    __u64 last_departure_time;
    __u64 total_bytes;
    __u32 is_penalized;
    __u32 _pad;
};

// Maps for configuration (Index 0 = Down, Index 1 = Up)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct config_data);
} config_map SEC(".maps");

// Maps for user states (Index 0 = Down, Index 1 = Up)
// Using two separate maps for cleaner statistics and faster lookups per path
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_key);
    __type(value, struct user_state);
} user_state_map_down SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_key);
    __type(value, struct user_state);
} user_state_map_up SEC(".maps");

// Internal helper for shaping logic
static __always_inline int process_packet(struct __sk_buff *skb, __u32 config_idx, void *user_map) {
    struct config_data *conf = bpf_map_lookup_elem(&config_map, &config_idx);
    if (!conf || conf->mode == 0) return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct ip_key ip_k = {0};
    __u16 sport = 0, dport = 0;
    __u8 protocol = 0;
    void *trans_hdr = NULL;

    // --- Parse IP ---
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        
        // For Egress: saddr is server IP or user IP depending on interface
        // We use saddr because we care about the source of the packet we are shaping
        // Actually, for VPN:
        // Down (Egress on Physical): saddr = server, daddr = user (WE SHAPE daddr)
        // Up (Egress on IFB0): saddr = user, daddr = destination (WE SHAPE saddr)
        if (config_idx == 0) ip_k.addr[0] = ip->daddr; // Download -> look at DEST
        else ip_k.addr[0] = ip->saddr;                // Upload -> look at SRC
        
        protocol = ip->protocol;
        trans_hdr = (void *)ip + (ip->ihl * 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end) return TC_ACT_OK;
        
        if (config_idx == 0) __builtin_memcpy(ip_k.addr, ipv6->daddr.in6_u.u6_addr32, 16);
        else __builtin_memcpy(ip_k.addr, ipv6->saddr.in6_u.u6_addr32, 16);
        
        protocol = ipv6->nexthdr;
        trans_hdr = (void *)(ipv6 + 1);
    } else {
        return TC_ACT_OK;
    }

    // --- Parse Ports (TCP/UDP) ---
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)trans_hdr;
        if ((void *)(tcp + 1) <= data_end) {
            sport = bpf_ntohs(tcp->source);
            dport = bpf_ntohs(tcp->dest);
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)trans_hdr;
        if ((void *)(udp + 1) <= data_end) {
            sport = bpf_ntohs(udp->source);
            dport = bpf_ntohs(udp->dest);
        }
    }

    // --- Port Filtering ---
    if (conf->target_port != 0) {
        if (sport != conf->target_port && dport != conf->target_port) {
            return TC_ACT_OK; 
        }
    }

    // --- User state management ---
    struct user_state *state = bpf_map_lookup_elem(user_map, &ip_k);
    __u64 now = bpf_ktime_get_ns();
    __u32 packet_len = skb->len;

    if (!state) {
        struct user_state ns = {
            .window_start_time = now,
            .last_departure_time = now,
            .total_bytes = packet_len
        };
        bpf_map_update_elem(user_map, &ip_k, &ns, BPF_ANY);
        return TC_ACT_OK;
    }

    __sync_fetch_and_add(&state->total_bytes, packet_len);

    if (conf->mode == 2) {
        if (state->is_penalized && now > state->penalty_end_time) {
            state->is_penalized = 0;
            state->window_start_time = now;
            state->bytes_in_window = 0;
        }

        if (!state->is_penalized) {
            if (now - state->window_start_time > conf->window_time_ns) {
                state->window_start_time = now;
                state->bytes_in_window = 0;
            }
            state->bytes_in_window += packet_len;
            if (state->bytes_in_window > conf->burst_bytes_limit) {
                state->is_penalized = 1;
                state->penalty_end_time = now + conf->penalty_time_ns;
            }
        }
    }

    __u64 current_rate = conf->normal_rate_bps;
    if (conf->mode == 2 && state->is_penalized) {
        current_rate = conf->penalty_rate_bps;
    }

    if (current_rate == 0) return TC_ACT_OK;

    __u64 delay_ns = ((__u64)packet_len * 1000000000ULL) / current_rate;
    __u64 departure_time = state->last_departure_time;
    if (now > departure_time) departure_time = now;
    departure_time += delay_ns;

    if (departure_time - now > 2000000000ULL) return TC_ACT_SHOT; 

    state->last_departure_time = departure_time;
    skb->tstamp = departure_time; 

    return TC_ACT_OK;
}

SEC("tc")
int handle_down(struct __sk_buff *skb) {
    return process_packet(skb, 0, &user_state_map_down);
}

SEC("tc")
int handle_up(struct __sk_buff *skb) {
    return process_packet(skb, 1, &user_state_map_up);
}

char _license[] SEC("license") = "GPL";
