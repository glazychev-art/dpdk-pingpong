#include <signal.h>
#include <stdbool.h>
#include <getopt.h>

#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#define APP "pingpong"

#define ETHER_TYPE_PING 0xFF01
#define ETHER_TYPE_PONG 0xFF02

uint32_t PINGPONG_LOG_LEVEL = RTE_LOG_DEBUG;

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 128

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

int RTE_LOGTYPE_PINGPONG;

struct rte_mempool *pingpong_pktmbuf_pool = NULL;

static volatile bool force_quit;

/* enabled port */
static uint16_t portid = 0;
/* number of packets */
static uint64_t nb_pkts = 100;
/* server mode */
static bool server_mode = true;
/* the client MAC address */
static struct rte_ether_addr client_ether_addr;
/* the server MAC address */
static struct rte_ether_addr server_ether_addr;

static struct rte_eth_dev_tx_buffer *tx_buffer;

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/* Per-port statistics struct */
struct pingpong_port_statistics
{
    uint64_t tx;
    uint64_t rx;
    uint64_t *rtt;
    uint64_t dropped;
} __rte_cache_aligned;
struct pingpong_port_statistics port_statistics;

static inline void
initlize_port_statistics(void)
{
    port_statistics.tx = 0;
    port_statistics.rx = 0;
    port_statistics.rtt = malloc(sizeof(uint64_t) * nb_pkts);
    port_statistics.dropped = 0;
}

static inline void
destroy_port_statistics(void)
{
    free(port_statistics.rtt);
}

static inline void
print_port_statistics(void)
{
    uint64_t i, min_rtt, max_rtt, sum_rtt, avg_rtt;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "====== ping-pong statistics =====\n");
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "tx %" PRIu64 " ping packets\n", port_statistics.tx);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "rx %" PRIu64 " pong packets\n", port_statistics.rx);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "dopped %" PRIu64 " packets\n", port_statistics.dropped);

    min_rtt = 999999999;
    max_rtt = 0;
    sum_rtt = 0;
    avg_rtt = 0;
    for (i = 0; i < nb_pkts; i++)
    {
        sum_rtt += port_statistics.rtt[i];
        if (port_statistics.rtt[i] < min_rtt)
            min_rtt = port_statistics.rtt[i];
        if (port_statistics.rtt[i] > max_rtt)
            max_rtt = port_statistics.rtt[i];
    }
    avg_rtt = sum_rtt / nb_pkts;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "min rtt: %" PRIu64 " us\n", min_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "max rtt: %" PRIu64 " us\n", max_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "average rtt: %" PRIu64 " us\n", avg_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "=================================\n");
}

static const char short_options[] =
    "p:" /* portmask */
    "n:" /* number of packets */
    "s"  /* server mode */
    "c"  /* client mode */
    "S:" /* server MAC address */
    "C:" /* client MAC address */
    ;

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* display usage */
static int
pingpong_usage(const char *prgname)
{
    printf("%s [EAL options] -- [-p PORTID] [-n PACKETS] -s -S SERVER_MAC | -c -C CLIENT_MAC -S SERVER_MAC\n"
           "\t-p PORTID: port to configure\n"
           "\t-n PACKETS: number of packets\n"
	   "\t-s: enable server mode\n"
           "\t-c: enable client mode\n"
	   "\t-S SERVER_MAC: server (remote) MAC address\n"
           "\t-C CLIENT_MAC: client (self) MAC address\n",
           prgname);
    return -1;
}

/* Parse the argument given in the command line of the application */
static int
pingpong_parse_args(int argc, char **argv)
{
    int opt, ret;
    char *prgname = argv[0];
    bool with_mode = false, with_client_addr = false, with_server_addr = false;

    while ((opt = getopt(argc, argv, short_options)) != EOF)
    {
        switch (opt)
        {
        /* port id */
        case 'p':
            portid = (uint16_t)strtol(optarg, NULL, 10);
            break;

        case 'n':
            nb_pkts = (uint64_t)strtoull(optarg, NULL, 10);
            break;

        case 's':
            if (with_mode)
                return pingpong_usage(prgname);
	    with_mode = true;
	    server_mode = true;
	    break;

        case 'c':
	    if (with_mode)
		return pingpong_usage(prgname);
	    with_mode = true;
            server_mode = false;
            break;

        case 'C':
            if (rte_ether_unformat_addr(optarg, &client_ether_addr))
		return pingpong_usage(prgname);
            with_client_addr = true;
            break;

        case 'S':
            if (rte_ether_unformat_addr(optarg, &server_ether_addr))
                return pingpong_usage(prgname);
            with_server_addr = true;
            break;

        default:
            return pingpong_usage(prgname);
        }
    }

    if (!with_mode)
    {
	printf("Expected one of '-c', '-s' modes\n");
	return pingpong_usage(prgname);
    }
    if (server_mode && !with_server_addr)
    {
	printf("Expected server MAC address in server mode\n");
	return pingpong_usage(prgname);
    }
    if (!server_mode && !(with_client_addr && with_server_addr))
    {
	printf("Expected client, server MAC addresses in client mode\n");
	return pingpong_usage(prgname);
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; /* reset getopt lib */
    return ret;
}

/* construct ping packet */
static struct rte_mbuf *
contruct_ping_packet(void)
{
    unsigned pkt_size = 1000U;
    struct rte_mbuf *pkt;
    struct rte_ether_hdr *eth_hdr;

    pkt = rte_pktmbuf_alloc(pingpong_pktmbuf_pool);
    if (!pkt)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PINGPONG, "fail to alloc mbuf for packet\n");

    pkt->data_len = pkt_size;
    pkt->next = NULL;

    /* Initialize Ethernet header. */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    rte_ether_addr_copy(&server_ether_addr, &eth_hdr->d_addr);
    rte_ether_addr_copy(&client_ether_addr, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_PING);

    pkt->nb_segs = 1;
    pkt->pkt_len = pkt_size;
    pkt->l2_len = sizeof(struct rte_ether_hdr);

    return pkt;
}

/* main ping loop */
static void
ping_main_loop(void)
{
    unsigned lcore_id;
    uint64_t ping_tsc, pong_tsc, diff_tsc, rtt_us;
    unsigned i, nb_rx, nb_tx;
    const uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t pkt_idx = 0;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m = NULL;
    struct rte_ether_hdr *eth_hdr;
    struct rte_vlan_hdr *vlan_hdr;
    uint16_t eth_type;
    int l2_len;
    bool pong_received;

    lcore_id = rte_lcore_id();

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "entering ping loop on lcore %u\n", lcore_id);

    m = contruct_ping_packet();
    if (m == NULL)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_PINGPONG, "construct packet failed\n");

    for (pkt_idx = 0; pkt_idx < nb_pkts && !force_quit; pkt_idx++)
    {
        pong_received = false;

        ping_tsc = rte_rdtsc();
        /* do ping */
        nb_tx = rte_eth_tx_burst(portid, 0, &m, 1);
        if (nb_tx)
            port_statistics.tx += nb_tx;

        /* wait for pong */
        while (!pong_received && !force_quit)
        {
            nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
            if (!nb_rx)
               continue;
            pong_tsc = rte_rdtsc();

            /* only 1 packet expected */
            if (nb_rx > 1)
                    rte_log(RTE_LOG_WARNING, RTE_LOGTYPE_PINGPONG, "%u packets received, 1 expected.\n", nb_rx);

            for (i = 0; i < nb_rx; i++)
            {
                m = pkts_burst[i];

                eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                eth_type = rte_cpu_to_be_16(eth_hdr->ether_type);
                l2_len = sizeof(struct rte_ether_hdr);
                if (eth_type == RTE_ETHER_TYPE_VLAN)
                {
                    vlan_hdr = (struct rte_vlan_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
                    l2_len += sizeof(struct rte_vlan_hdr);
                    eth_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
                }
                if (eth_type == ETHER_TYPE_PONG)
                {
                    /* compare mac */
                    if (rte_is_same_ether_addr(&eth_hdr->d_addr, &client_ether_addr))
                    {
                        diff_tsc = pong_tsc - ping_tsc;
                        rtt_us = diff_tsc * US_PER_S / tsc_hz;

                        port_statistics.rtt[port_statistics.rx] = rtt_us;
                        port_statistics.rx += 1;

                        pong_received = true;
                        break;
                    }
                }
            }
        }
    }
    /* print port statistics when ping main loop finishes */
    print_port_statistics();
}

/* main pong loop */
static void
pong_main_loop(void)
{
    unsigned lcore_id;
    unsigned i, nb_rx, nb_tx;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m = NULL;
    struct rte_ether_hdr *eth_hdr;
    struct rte_vlan_hdr *vlan_hdr;
    uint16_t *eth_type_ptr;
    int l2_len;

    lcore_id = rte_lcore_id();

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "entering pong loop on lcore %u\n", lcore_id);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_PINGPONG, "waiting ping packets\n");

    /* wait for ping */
    while (!force_quit)
    {
        nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
        if (nb_rx)
        {
            for (i = 0; i < nb_rx; i++)
            {
                m = pkts_burst[i];

                eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                eth_type_ptr = &eth_hdr->ether_type;
                l2_len = sizeof(struct rte_ether_hdr);
                if (rte_cpu_to_be_16(*eth_type_ptr) == RTE_ETHER_TYPE_VLAN)
                {
                    vlan_hdr = (struct rte_vlan_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
                    l2_len += sizeof(struct rte_vlan_hdr);
                    eth_type_ptr = &vlan_hdr->eth_proto;
                }
                if (rte_cpu_to_be_16(*eth_type_ptr) == ETHER_TYPE_PING)
                {
                    port_statistics.rx += 1;
                    /* do pong */
                    rte_ether_addr_copy(&server_ether_addr, &eth_hdr->s_addr);
                    rte_ether_addr_copy(&client_ether_addr, &eth_hdr->d_addr);
                    *eth_type_ptr = rte_cpu_to_be_16(ETHER_TYPE_PONG);

                    nb_tx = rte_eth_tx_burst(portid, 0, &m, 1);
                    if (nb_tx)
                        port_statistics.tx += nb_tx;
                }
            }
        }
    }
    /* print port statistics when pong main loop finishes */
    print_port_statistics();
}

static int
ping_launch_one_lcore(__attribute__((unused)) void *dummy)
{
    ping_main_loop();
    return 0;
}

static int
pong_launch_one_lcore(__attribute__((unused)) void *dummy)
{
    pong_main_loop();
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    uint16_t nb_ports;
    unsigned int nb_mbufs;
    unsigned int nb_lcores;
    unsigned int lcore_id;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    /* init log */
    RTE_LOGTYPE_PINGPONG = rte_log_register(APP);
    ret = rte_log_set_level(RTE_LOGTYPE_PINGPONG, PINGPONG_LOG_LEVEL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Set log level to %u failed\n", PINGPONG_LOG_LEVEL);
    
    nb_lcores = rte_lcore_count();
    if (nb_lcores < 2)
        rte_exit(EXIT_FAILURE, "Number of CPU cores should be no less than 2.");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports, bye...\n");

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_PINGPONG, "%u port(s) available\n", nb_ports);

    /* parse application arguments (after the EAL ones) */
    ret = pingpong_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid pingpong arguments\n");
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_PINGPONG, "Enabled port: %u\n", portid);
    if (portid > nb_ports - 1)
        rte_exit(EXIT_FAILURE, "Invalid port id %u, port id should be in range [0, %u]\n", portid, nb_ports - 1);

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_mbufs = RTE_MAX((unsigned int)(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE)), 8192U);
    pingpong_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
                                                    MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                    rte_socket_id());
    if (pingpong_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_PINGPONG, "Initializing port %u...\n", portid);
    fflush(stdout);

    /* init port */
    rte_eth_dev_info_get(portid, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    if (server_mode)
    {
        ret = rte_eth_dev_default_mac_addr_set(portid, &server_ether_addr);
    }
    else
    {
        ret = rte_eth_dev_default_mac_addr_set(portid, &client_ether_addr);
    }

    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot set device MAC address: err=%d, port=%u\n",
                 ret, portid);

    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                 ret, portid);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
                                           &nb_txd);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot adjust number of descriptors: err=%d, port=%u\n",
                 ret, portid);

    /* init one RX queue */
    fflush(stdout);
    rxq_conf = dev_info.default_rxconf;

    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                                 rte_eth_dev_socket_id(portid),
                                 &rxq_conf,
                                 pingpong_pktmbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                 ret, portid);

    /* init one TX queue on each port */
    fflush(stdout);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                 rte_eth_dev_socket_id(portid),
                                 &txq_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                 ret, portid);

    /* Initialize TX buffers */
    tx_buffer = rte_zmalloc_socket("tx_buffer",
                                   RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                   rte_eth_dev_socket_id(portid));
    if (tx_buffer == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                 portid);

    rte_eth_tx_buffer_init(tx_buffer, MAX_PKT_BURST);

    ret = rte_eth_tx_buffer_set_err_callback(tx_buffer,
                                             rte_eth_tx_buffer_count_callback,
                                             &port_statistics.dropped);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot set error callback for tx buffer on port %u\n",
                 portid);

    /* Start device */
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                 ret, portid);

    /* initialize port stats */
    initlize_port_statistics();

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_PINGPONG, "Initilize port %u done.\n", portid);

    lcore_id = rte_get_next_lcore(0, true, false);

    ret = 0;
    if (server_mode)
    {
        rte_eal_remote_launch(pong_launch_one_lcore, NULL, lcore_id);
    }
    else
    {
        rte_eal_remote_launch(ping_launch_one_lcore, NULL, lcore_id);
    }

    if (rte_eal_wait_lcore(lcore_id) < 0)
    {
        ret = -1;
    }

    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    destroy_port_statistics();
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_PINGPONG, "Bye.\n");

    return 0;
}
