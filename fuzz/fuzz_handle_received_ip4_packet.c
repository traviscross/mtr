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
 * Fuzz handle_received_ip4_packet: parses raw IPv4 packets containing
 * ICMP responses. This is the primary entry point for processing
 * network-received IPv4 data in mtr-packet. Interesting because it
 * strips the IP header and then parses ICMP headers, ICMP extensions,
 * and MPLS labels from untrusted binary data.
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

    /* Set up a dummy remote address (IPv4) */
    struct sockaddr_storage remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&remote_addr;
    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = htonl(0x0A000001); /* 10.0.0.1 */

    /* Set up a timestamp */
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    /* Call the target function with fuzz data as the raw IPv4 packet */
    handle_received_ip4_packet(
        &net_state,
        &remote_addr,
        (const void *)data,
        (int)size,
        &timestamp);

    return 0;
}
