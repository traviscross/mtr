#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdbool.h>

#include "deconstruct_unix.h"
#include "probe.h"

/*
 * Fuzz handle_received_ip6_packet: parses raw IPv6 ICMPv6 response packets.
 * This is the IPv6 counterpart to the IPv4 handler and exercises ICMPv6
 * header parsing, MPLS extension decoding, and probe matching.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65535) {
        return 0;
    }

    /* Initialize a minimal net_state_t with an empty probe list */
    struct net_state_t net_state;
    memset(&net_state, 0, sizeof(net_state));
    LIST_INIT(&net_state.outstanding_probes);
    net_state.outstanding_probe_count = 0;

    /* Set up a dummy remote address (IPv6) */
    struct sockaddr_storage remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&remote_addr;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = in6addr_loopback;

    /* Set up a timestamp */
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    /* Call the target function with fuzz data as the raw IPv6 packet */
    handle_received_ip6_packet(
        &net_state,
        &remote_addr,
        (const void *)data,
        (int)size,
        &timestamp);

    return 0;
}
