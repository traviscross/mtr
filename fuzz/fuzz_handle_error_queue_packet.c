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
 * Fuzz handle_error_queue_packet: processes packets from the Linux
 * SO_TIMESTAMP error queue. This is another network input entry point
 * that parses ICMP/ICMPv6 error messages received through the error queue.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5 || size > 65535) {
        return 0;
    }

    /* Initialize a minimal net_state_t with an empty probe list */
    struct net_state_t net_state;
    memset(&net_state, 0, sizeof(net_state));
    LIST_INIT(&net_state.outstanding_probes);
    net_state.outstanding_probe_count = 0;

    /* Use first two bytes to vary icmp_result and proto parameters */
    int icmp_result = (int)(int8_t)data[0]; /* small range */
    int proto = (data[1] % 2 == 0) ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    /* Set up a dummy remote address */
    struct sockaddr_storage remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    if (proto == IPPROTO_ICMP) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&remote_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = htonl(0x0A000001);
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&remote_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = in6addr_loopback;
    }

    /* Set up a timestamp */
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    /* Make a mutable copy of packet data (handle_error_queue_packet takes char*) */
    size_t pkt_size = size - 2;
    char *pkt_copy = (char *)malloc(pkt_size);
    if (!pkt_copy) return 0;
    memcpy(pkt_copy, data + 2, pkt_size);

    handle_error_queue_packet(
        &net_state,
        &remote_addr,
        icmp_result,
        proto,
        pkt_copy,
        (int)pkt_size,
        &timestamp);

    free(pkt_copy);
    return 0;
}
