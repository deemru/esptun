/*
* (C) 2011-2014 Luigi Rizzo, Matteo Landi
*
* BSD license
*
* A netmap client to bridge two network interfaces
* (or one interface and the host stack).
*
* $FreeBSD: head/tools/tools/netmap/bridge.c 228975 2011-12-30 00:04:11Z uqs $
*/

#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

int verbose = 0;

static int do_abort = 0;
static int zerocopy = 1; /* enable zerocopy if possible */
static int threads = 2; // 1 <--> 1
static int reaction = 128;

static void
sigint_h( int sig )
{
    (void)sig;	/* UNUSED */
    do_abort = 1;
    signal( SIGINT, SIG_DFL );
}

#define MAX_RINGS   32

/*
* how many packets on this set of queues ?
*/
int
pkt_queued( struct nm_desc *d, int tx )
{
    u_int i, tot = 0;

    if( tx ) {
        for( i = d->first_tx_ring; i <= d->last_tx_ring; i++ ) {
            tot += nm_ring_space( NETMAP_TXRING( d->nifp, i ) );
        }
    }
    else {
        for( i = d->first_rx_ring; i <= d->last_rx_ring; i++ ) {
            tot += nm_ring_space( NETMAP_RXRING( d->nifp, i ) );
        }
    }
    return tot;
}

#ifdef WINDOWS_CC
#pragma pack( push, 1 )

#define	ETHER_ADDR_LEN      6
#define ETHERTYPE_IP_NBO    0x0008 // 0x0800 network byte order
#define ESP_PROTO	    50
#define UDP_PROTO	    17
#define TCP_PROTO	    6
#define IPV4		    4

struct ether_header {
    u_char	ether_dhost[ETHER_ADDR_LEN];
    u_char	ether_shost[ETHER_ADDR_LEN];
    u_short	ether_type;
};

struct ip {
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

#pragma pack( pop )
#else
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <dlfcn.h>
#endif

#pragma pack( push, 1 )

struct etherip {
    struct ether_header eh;
    struct ip ip;
};

#define ESP_GOST_SHIFT ( sizeof( struct ether_header ) + sizeof( struct ip ) )

#pragma pack( pop )

#define ESPIO_WITH_LOADER
#include "espio.h"
#define SOQUE_WITH_LOADER
#include "soque.h"

static struct etherip etherip;

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

// 20 bytes ipv4 xsum
static uint16_t ipv4_xsum( uint16_t * ipv4 )
{
    uint32_t sum = 0;
    unsigned i;

    for( i = 0; i < 10; i++ )
        sum += ntohs( ipv4[i] );

    sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    return sum;
}

static void init_esppkt()
{
    // eh
    {
        etherip.eh.ether_dhost[0] = 0xFF;
        etherip.eh.ether_dhost[1] = 0xFF;
        etherip.eh.ether_dhost[2] = 0xFF;
        etherip.eh.ether_dhost[3] = 0xFF;
        etherip.eh.ether_dhost[4] = 0xFF;
        etherip.eh.ether_dhost[5] = 0xFF;

        etherip.eh.ether_shost[0] = 0x00;
        etherip.eh.ether_shost[1] = 0x00;
        etherip.eh.ether_shost[2] = 0x00;
        etherip.eh.ether_shost[3] = 0x00;
        etherip.eh.ether_shost[4] = 0x00;
        etherip.eh.ether_shost[5] = 0x00;

        etherip.eh.ether_type = htons( ETHERTYPE_IP );
    }
    // ip
    {
        *(uint8_t *)&etherip.ip = 0x45;
        etherip.ip.ip_tos = 16; // IPTOS_LOWDELAY
        etherip.ip.ip_len = 0;
        etherip.ip.ip_id = 0;
        etherip.ip.ip_off = 0x0040; // htons( IP_DF )
        etherip.ip.ip_ttl = 64; // IPDEFTTL
        etherip.ip.ip_p = IPPROTO_ESP;
        etherip.ip.ip_sum = 0;
        *(unsigned *)&etherip.ip.ip_src = 0x01010101;
        *(unsigned *)&etherip.ip.ip_dst = 0x02020202;
    }

    etherip.ip.ip_sum = ipv4_xsum( (uint16_t *)&etherip.ip );
}

static void finish_esppkt( char * pkt, uint16_t pktlen )
{
    struct etherip * eip = (struct etherip *)pkt;
    uint32_t sum = eip->ip.ip_sum;

    sum += pktlen;

    if( sum > 0xFFFF )
        sum -= 0xFFFF;

    sum = ~sum & 0xFFFF;

    eip->ip.ip_sum = htons( sum );
    eip->ip.ip_len = htons( pktlen );
}

int soque_size;
int tx_index;
int rx_index;

SOQUE_HANDLE sh[2];
SOQUE_THREADS_HANDLE sth;

static void
usage( void )
{
    fprintf( stderr,
        "usage: tunnel [-v] [-i ifa] [-i ifb] [-b burst] [-w wait_time] [iface]\n" );
    exit( 1 );
}

static struct nmreq nmr;
static struct nm_desc * pa = NULL, *pb = NULL;

struct nm_soque_espio
{
    struct netmap_ring * src_rings[MAX_RINGS];
    struct netmap_ring * dst_rings[MAX_RINGS];
    uint32_t src_rings_count;
    uint32_t dst_rings_count;
    int src_fd;
    int dst_fd;
    uint32_t src_slots_per_ring;
    uint32_t dst_slots_per_ring;
    uint32_t src_slots_count;
    uint32_t dst_slots_count;

    char encap;

    // soque helper
    uint32_t push_index;
    uint32_t pop_index;
    uint32_t pop_space;
    uint32_t dst_index;

    unsigned seqnum;
    
    struct etherip etherip;
    
    ESPIO_HANDLE eh;
    ESPIO_IOVEC * iovs;
    uint32_t * ring_indexes;
};

struct nm_soque_espio nms_local, nms_remote;

static inline uint32_t ringnext( uint32_t i, uint32_t s )
{
    return ( unlikely( i + 1 == s ) ? 0 : i + 1 );
}

static uint32_t get_rings_space( struct netmap_ring ** rings, uint32_t rings_count )
{
    uint32_t ri;
    uint32_t rings_space = 0;

    for( ri = 0; ri < rings_count; ri++ )
        rings_space += nm_ring_space( rings[ri] );

    return rings_space;
}

static uint16_t checksum( const void *data, uint16_t len, uint32_t sum )
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for( i = 0; i < ( len & ~1U ); i += 2 ) {
        sum += (uint16_t)ntohs( *( (uint16_t *)( addr + i ) ) );
        if( sum > 0xFFFF )
            sum -= 0xFFFF;
    }
    /*
    * If there's a single byte left over, checksum it, too.
    * Network byte order is big-endian, so the remaining byte is
    * the high byte.
    */
    if( i < len ) {
        sum += addr[i] << 8;
        if( sum > 0xFFFF )
            sum -= 0xFFFF;
    }
    return sum;
}

int SOQUE_CALL netmap_soque_push( struct nm_soque_espio * nms, unsigned batch, char waitable )
{
    uint32_t push_batch;

    uint32_t slots_per_ring = nms->src_slots_per_ring;
    uint32_t slots_count = nms->src_slots_count;
    unsigned rings_count = nms->src_rings_count;
    struct netmap_ring ** rings = nms->src_rings;

    if( waitable )
    {
        struct pollfd pollfd;
        pollfd.fd = nms->src_fd;
        pollfd.events = POLLIN;
        pollfd.revents = 0;
        poll( &pollfd, 1, reaction );
    }
    else
    {
        ioctl( nms->src_fd, NIOCRXSYNC, NULL );
    }

    push_batch = get_rings_space( rings, rings_count );

    if( verbose && push_batch )
    {
        D( "%s:%p: IN: batch = %d, push_space = %d", __FUNCTION__, nms, batch, push_batch );
    }

    if( push_batch )
    {
        struct netmap_ring * ring = NULL;
        uint32_t ring_index = (uint32_t)-1;
        uint32_t ring_space = 0;
        uint32_t index = nms->push_index;
        uint32_t seqnum = nms->seqnum;
        uint32_t i;

        if( push_batch > batch )
            push_batch = batch;

        for( i = 0; i < push_batch; i++ )
        {
            struct netmap_slot * slot;
            ESPIO_IOVEC * iov;

            if( ring_space == 0 )
            {
                do
                {
                    ring = rings[++ring_index];
                    ring_space = nm_ring_space( ring );
                }
                while( ring_space == 0 );
            }

            slot = &ring->slot[ring->cur];

            iov = &nms->iovs[index];
            iov->data = NETMAP_BUF( ring, slot->buf_idx );
            iov->data_len = slot->len;
            iov->seqnum = ++seqnum;
            iov->protocol = 97;
            nms->ring_indexes[index] = ring_index;

            index = ringnext( index, slots_count );
            ring->cur = ringnext( ring->cur, slots_per_ring );
            ring_space--;

            if( verbose == 2 && nms->encap )
                printf( "encap crc = 0x%04X (%d)\n", checksum( iov->data, iov->data_len, 0 ), iov->data_len );
        }
   
        nms->seqnum = seqnum;
        nms->push_index = index;
    }

    if( verbose && push_batch )
    {
        D( "%s:%p:OUT: batch = %d, push_space = %d", __FUNCTION__, nms, batch, push_batch );
    }

    return push_batch;
}

void SOQUE_CALL netmap_soque_proc( struct nm_soque_espio * nms, unsigned batch, unsigned start_index )
{
    uint32_t i;
    uint32_t index;
    uint32_t size = nms->src_slots_count;

    if( nms->encap )
    {
        if( start_index + batch <= size )
        {
            eio->espio_encrypt( nms->eh, batch, &nms->iovs[start_index] );
        }
        else
        {
            uint32_t first_batch = size - start_index;

            eio->espio_encrypt( nms->eh, first_batch, &nms->iovs[start_index] );
            eio->espio_encrypt( nms->eh, batch - first_batch, &nms->iovs[0] );
        }

        for( i = 0, index = start_index;; )
        {
            ESPIO_IOVEC * iov = &nms->iovs[index];

            if( iov->code == ESPIO_ABSORB )
            {
                iov->code++;
                iov->code--;
            }

            if( iov->code == ESPIO_ERROR )
            {
                iov->code++;
                iov->code--;
            }

            if( ++i == batch )
                break;

            index = ringnext( index, size );
        }
    }
    else // decap
    {
        for( i = 0, index = start_index;; )
        {
            ESPIO_IOVEC * iov = &nms->iovs[index];

            iov->data += ESP_GOST_SHIFT;
            iov->data_len -= ESP_GOST_SHIFT;
            iov->code = -1;

            if( ++i == batch )
                break;

            index = ringnext( index, size );
        }

        if( start_index + batch <= size )
        {
            eio->espio_decrypt( nms->eh, batch, &nms->iovs[start_index] );
        }
        else
        {
            uint32_t first_batch = size - start_index;

            eio->espio_decrypt( nms->eh, first_batch, &nms->iovs[start_index] );
            eio->espio_decrypt( nms->eh, batch - first_batch, &nms->iovs[0] );
        }

        for( i = 0, index = start_index;; )
        {
            ESPIO_IOVEC * iov = &nms->iovs[index];

            if( iov->code != ESPIO_PASS )
            {
                iov->code++;
                iov->code--;
            }

            if( ++i == batch )
                break;

            index = ringnext( index, size );
        }
    }
}

int SOQUE_CALL netmap_soque_pop( struct nm_soque_espio * nms, unsigned batch, char waitable )
{
    uint32_t pop_space;

    (void)waitable; // pop_space power

    pop_space = nms->pop_space;

    if( verbose && pop_space )
    {
        D( "%s:%p: IN: batch = %d, pop_space = %d", __FUNCTION__, nms, batch, pop_space );
    }

    if( batch > pop_space )
        batch = pop_space;

    if( batch )
    {
        struct netmap_ring * dst_ring = nms->dst_rings[0];
        uint32_t pop_index = nms->pop_index;
        uint32_t dst_index = nms->dst_index;

        if( verbose )
        {
            D( "%s:%p: IN: pop_index = %d", __FUNCTION__, nms, pop_index );
        }

        unsigned i;
        unsigned total_src = nms->src_slots_count;
        unsigned size_src = nms->src_slots_per_ring;
        unsigned size_dst = nms->dst_slots_per_ring;

        for( i = 0; i < batch; i++ )
        {
            ESPIO_IOVEC * iov = &nms->iovs[pop_index];
            uint32_t ring_index = nms->ring_indexes[pop_index];
            struct netmap_slot * dst_slot = &dst_ring->slot[dst_index];
            char * dst_buf = NETMAP_BUF( dst_ring, dst_slot->buf_idx );

            if( iov->code == ESPIO_PASS )
            {
                if( nms->encap )
                {
                    unsigned shift;

                    memcpy( dst_buf, &nms->etherip, sizeof( nms->etherip ) );
                    shift = sizeof( nms->etherip );

                    memcpy( dst_buf + shift, iov->prolog, iov->prolog_len );
                    shift += iov->prolog_len;

                    memcpy( dst_buf + shift, iov->data, iov->data_len );
                    shift += iov->data_len;

                    memcpy( dst_buf + shift, iov->epilog, iov->epilog_len );
                    shift += iov->epilog_len;

                    dst_slot->len = shift;

                    finish_esppkt( dst_buf, shift - sizeof( etherip.eh ) );
                }
                else
                {
                    memcpy( dst_buf, iov->data + iov->data_dec_shift, iov->data_dec_len );
                    dst_slot->len = iov->data_dec_len;

                    if( verbose == 2 )
                        printf( "decap crc = 0x%04X (%d)\n", checksum( dst_buf, dst_slot->len, 0 ), dst_slot->len );
                }

                dst_index = ringnext( dst_index, size_dst );
            }

            nms->src_rings[ring_index]->head = ringnext( nms->src_rings[ring_index]->head, size_src );
            pop_index = ringnext( pop_index, total_src );
        }

        nms->dst_index = dst_index;
        nms->dst_rings[0]->head = dst_index;
        nms->dst_rings[0]->cur = dst_index;

        nms->pop_index = pop_index;

        if( verbose )
        {
            D( "%s:%p:OUT: pop_index = %d", __FUNCTION__, nms, pop_index );
        }
    }

    ioctl( nms->dst_fd, NIOCTXSYNC, NULL );
    pop_space = get_rings_space( nms->dst_rings, 1 );

    nms->pop_space = pop_space;

    if( verbose && pop_space )
    {
        D( "%s:%p:OUT: batch = %d, pop_space = %d", __FUNCTION__, nms, batch, pop_space );
    }

    return batch;
}

void info__ifp( struct netmap_if * nifp )
{
    D( "nifp->ni_name:      %s", nifp->ni_name );
    D( "nifp->ni_tx_rings:  %d", nifp->ni_tx_rings );
    D( "nifp->ni_rx_rings:  %d", nifp->ni_rx_rings );
}

void info__req( struct nmreq * nmreq )
{
    D( "nmreq->nr_name:     %s", nmreq->nr_name );
    D( "nmreq->nr_offset:   %d", nmreq->nr_offset );
    D( "nmreq->nr_memsize:  %d", nmreq->nr_memsize );
    D( "nmreq->nr_tx_slots: %d", nmreq->nr_tx_slots );
    D( "nmreq->nr_rx_slots: %d", nmreq->nr_rx_slots );
    D( "nmreq->nr_tx_rings: %d", nmreq->nr_tx_rings );
    D( "nmreq->nr_rx_rings: %d", nmreq->nr_rx_rings );
    D( "nmreq->nr_ringid:   %d", nmreq->nr_ringid );
}

void info_ring( struct netmap_ring * ring )
{
    D( "ring->buf_ofs:      %p", (void *)(uintptr_t)ring->buf_ofs );
    D( "ring->num_slots:    %d", ring->num_slots );
    D( "ring->nr_buf_size:  %d", ring->nr_buf_size );
    D( "ring->ringid:       %d", ring->ringid );
    D( "ring->dir:          %d", ring->dir );
    D( "ring->head:         %d", ring->head );
    D( "ring->cur:          %d", ring->cur );
    D( "ring->tail:         %d", ring->tail );
}

void info_desc( struct nm_desc * nmd )
{
    D( "nmd->fd:            %d", nmd->fd );
    D( "nmd->mem:           %p", nmd->mem );
    D( "nmd->memsize:       %d", nmd->memsize );
    D( "nmd->done_mmap:     %d", nmd->done_mmap );
    info__ifp( nmd->nifp );
    D( "nmd->first_tx_ring: %d", nmd->first_tx_ring );
    D( "nmd->last_tx_ring:  %d", nmd->last_tx_ring );
    D( "nmd->cur_tx_ring:   %d", nmd->cur_tx_ring );
    D( "nmd->first_rx_ring: %d", nmd->first_rx_ring );
    D( "nmd->last_rx_ring:  %d", nmd->last_rx_ring );
    D( "nmd->cur_rx_ring:   %d", nmd->cur_rx_ring );
    info__req( &nmd->req );
    info_ring( nmd->some_ring );
}

char nmd_to_nms( struct nm_desc * nmdfrom, struct nm_desc * nmdto, struct nm_soque_espio * nms, char encap )
{
    uint16_t i, ri;
    uint16_t first_ring;
    uint16_t last_ring;
    uint32_t slots_count;
    struct netmap_if * nifp;
    struct netmap_ring ** rings;

    memset( nms, 0, sizeof( struct nm_soque_espio ) );

    // FROM / RX
    nifp = nmdfrom->nifp;
    first_ring = nmdfrom->first_rx_ring;
    last_ring = nmdfrom->last_rx_ring;
    slots_count = NETMAP_RXRING( nifp, first_ring )->num_slots;
    rings = nms->src_rings;

    for( i = 0, ri = first_ring; ri <= last_ring; i++, ri++ )
    {
        rings[i] = NETMAP_RXRING( nifp, ri );

        if( slots_count != rings[i]->num_slots )
        {
            D( "slots_count != rings[i]->num_slots" );
            return 0;
        }

        nms->src_rings_count++;
    }
    nms->src_slots_per_ring = slots_count;
    nms->src_slots_count = slots_count * nms->src_rings_count;

    nms->iovs = malloc( nms->src_slots_count * sizeof( ESPIO_IOVEC ) );
    nms->ring_indexes = malloc( nms->src_slots_count * sizeof( uint32_t ) );

    // TO / DST
    nifp = nmdto->nifp;
    first_ring = nmdto->first_tx_ring;
    last_ring = nmdto->last_tx_ring;
    slots_count = NETMAP_TXRING( nifp, first_ring )->num_slots;
    rings = nms->dst_rings;

    for( i = 0, ri = first_ring; ri <= last_ring; i++, ri++ )
    {
        rings[i] = NETMAP_TXRING( nifp, ri );

        if( slots_count != rings[i]->num_slots )
        {
            D( "slots_count != rings[i]->num_slots" );
            return 0;
        }

        nms->dst_rings_count++;
    }
    nms->dst_slots_per_ring = slots_count;
    nms->dst_slots_count = slots_count * nms->dst_rings_count;

    nms->src_fd = nmdfrom->fd;
    nms->dst_fd = nmdto->fd;
    nms->seqnum = 1;
    memcpy( &nms_local.etherip, &etherip, sizeof( etherip ) );
    nms->pop_space = get_rings_space( nms->dst_rings, 1 );
    nms->encap = encap;

    return 1;
}

/*
* tunnel if1 if2
*/
int main( int argc, char ** argv )
{
    int ch;
    u_int batch = 16, wait_link = 4;
    char *ifa = NULL, *ifb = NULL;
    char ifabuf[64] = { 0 };
    char bind = 0;
    uint32_t threshold = 4096;
    
    init_esppkt();

    if( !soque_load() || !espio_load() )
        return 1;

    fprintf( stderr, "%s built %s %s\n",
        argv[0], __DATE__, __TIME__ );

    while( ( ch = getopt( argc, argv, "t:b:ci:vdw:h:" ) ) != -1 ) {
        switch( ch ) {
        default:
            D( "bad option %c %s", ch, optarg );
            usage();
            break;
        case 't':
            threads = atoi( optarg );
            break;
        case 'b':	/* batch */
            batch = atoi( optarg );
            break;
        case 'i':	/* interface */
            if( ifa == NULL )
                ifa = optarg;
            else if( ifb == NULL )
                ifb = optarg;
            else
                D( "%s ignored, already have 2 interfaces",
                    optarg );
            break;
        case 'c':
            zerocopy = 0; /* do not zerocopy */
            break;
        case 'v':
            verbose++;
            break;
        case 'd':
            bind++;
            break;
        case 'w':
            wait_link = atoi( optarg );
            break;
        case 'h':	/* threshold */
            threshold = atoi( optarg );
            break;
        }

    }

    argc -= optind;
    argv += optind;

    if( argc > 1 )
        ifa = argv[1];
    if( argc > 2 )
        ifb = argv[2];
    if( argc > 3 )
        batch = atoi( argv[3] );
    if( !ifb )
        ifb = ifa;
    if( !ifa ) {
        D( "missing interface" );
        usage();
    }
    if( batch < 1 || batch > 8192 ) {
        D( "invalid burst %d, set to 1024", batch );
        batch = 32;
    }
    if( wait_link > 100 ) {
        D( "invalid wait_link %d, set to 4", wait_link );
        wait_link = 4;
    }
    if( !strcmp( ifa, ifb ) ) {
        D( "same interface, endpoint 0 goes to host" );
        snprintf( ifabuf, sizeof( ifabuf ) - 1, "%s^", ifa );
        ifa = ifabuf;
    }
    else {
        /* two different interfaces. Take all rings on if1 */
    }

    memset( &nmr, 0, sizeof( nmr ) );
    nmr.nr_rx_slots = nmr.nr_tx_slots = 4096;
    nmr.nr_rx_rings = nmr.nr_tx_rings = 1;

    D( "nmr.nr_rx_slots = nmr.nr_tx_slots = %d", nmr.nr_rx_slots );
    D( "nm_open( %s )", ifa );
    pa = nm_open( ifa, &nmr, NETMAP_NO_TX_POLL, NULL );
    if( pa == NULL ) {
        D( "cannot open %s", ifa );
        return ( 1 );
    }
    D( "%s opened", ifa );
    info_desc( pa );

    memset( &nmr, 0, sizeof( nmr ) );
    nmr.nr_rx_slots = nmr.nr_tx_slots = 4096;
    nmr.nr_rx_rings = nmr.nr_tx_rings = 1;

    D( "nm_open( %s )", ifb );
    pb = nm_open( ifb, &nmr, NETMAP_NO_TX_POLL, NULL );
    if( pb == NULL ) {
        D( "cannot open %s", ifb );
        nm_close( pb );
        return ( 1 );
    }
    D( "%s opened", ifb );
    info_desc( pb );

    D( "Wait %d secs for link to come up...", wait_link );
    sleep( wait_link );
    D( "Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
        pa->req.nr_name, pa->first_rx_ring, pa->req.nr_rx_rings,
        pb->req.nr_name, pb->first_rx_ring, pb->req.nr_rx_rings );

    /* main loop */
    signal( SIGINT, sigint_h );

    init_esppkt();
    nmd_to_nms( pa, pb, &nms_local, 1 );
    nmd_to_nms( pb, pa, &nms_remote, 0 );

    sh[0] = soq->soque_open( nms_local.src_slots_count, &nms_local, (soque_push_cb)netmap_soque_push, (soque_proc_cb)netmap_soque_proc, (soque_pop_cb)netmap_soque_pop );
    sh[1] = soq->soque_open( nms_remote.src_slots_count, &nms_remote, (soque_push_cb)netmap_soque_push, (soque_proc_cb)netmap_soque_proc, (soque_pop_cb)netmap_soque_pop );

    nms_local.eh = eio->espio_open( "pa", "pb", threads );
    nms_remote.eh = eio->espio_open( "pb", "pa", threads );
    {
        ESPIO_INFO info;
        eio->espio_info( nms_local.eh, &info );
        info.spi_in = 0;
    }
    sth = soq->soque_threads_open( threads, bind, sh, 2 );
    soq->soque_threads_tune( sth, batch, threshold, reaction );

    D( "espio_open( %d ) = %p", threads, nms_local.eh );
    D( "soque_threads_open( %d ) = %p", threads, sth );

    while( !do_abort )
        sleep( 1 );

    D( "exiting" );

    soq->soque_threads_done( sth );
    nm_close( pb );
    nm_close( pa );

    return ( 0 );
}
