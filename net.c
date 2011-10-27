/*
 * MultiFS Distributing Multicast Filesystem
 * Copyright (c) 2011 Wouter Coene <wouter@irdc.nl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "multifs.h"
#include "list.h"
#include "bytesex.h"

#include <alloca.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef HAVE_SYS_SELECT
# include <sys/select.h>
#else
# include <sys/time.h>
#endif

#include <io/loop.h>
#include <io/event.h>
#include <io/endpoint.h>
#include <io/queue.h>
#include <io/socket.h>

/* size of the packet header */
#define HEADERSZ	(1 + 1 + sizeof(uint16_t) + sizeof(uint64_t))

/* unknown sequence */
#define UNKNOWN_SEQUENCE UINT64_MAX

/* maximum send queue length */
#define MAXSENDQ	16

/* token state */
enum state {
	STATE_ASKING_TOKEN,	/* we're asking for the token */
	STATE_ASKING_TOKEN2,	/* still asking */
	STATE_SEARCHING_TOKEN,	/* we're searching for the token */
	STATE_SEARCHING_TOKEN2,	/* still searching */
	STATE_FOUND_TOKEN,	/* we know where the token is */
	STATE_HAS_TOKEN,	/* we have the token */
	STATE_WITHOUT_TIMEOUT	= STATE_FOUND_TOKEN
};

/* packet */
struct packet {
	LIST_ENTRY(, packet)	 packetq;	/* in-order linked list of messages */
	struct ioendpoint	*from;		/* sender */
	enum msg		 msg;		/* packet message */
	uint64_t		 sequence;	/* sequence number */
	size_t			 len;		/* packet length */
	char			 buf[1];	/* packet contents */
};

/* networking state */
struct net {
	struct multifs		*multifs;
	struct ioqueue		*mcast;
	int			 fsfd;
	struct ioloop		*ioloop;
	struct ioevent		*fs_recv_ev,
				*mcast_recv_ev,
				*mcast_send_ev,
				*mcast_purge_ev,
				*timeout_ev,
				*resend_ev;
	enum state		 state;
	uint64_t		 sequence;
	struct ioendpoint	*multicast,
				*owner,
				*self;
	LIST_HEAD(, packet)	 sendq,		/* packets still to be sent,
						 * waiting for us to gain
						 * the token */
				 resendq;	/* packets already sent,
				 		 * being kept around to
				 		 * service NACKs */
	LIST_HEAD(, packet)	 recvq;		/* packets received but not
						 * yet processed (eg.
						 * because they were
						 * received out-of-sequence */
	unsigned int		 sendqlen;	/* length of the sendq */
	unsigned int		 resendqlen;	/* length of the resendq */
};

/*
 * Reliably perform I/O on a file descriptor, dealing with short
 * reads/writes.
 */
static ssize_t
reliable_io(int fd, const struct iovec *iov, int iovcnt,
            ssize_t (*iofn)(int, const struct iovec *, int))
{
	ssize_t n, total;
	struct iovec *i = NULL;

	total = 0;
	while (1) {
		/* perform the operation */
		n = iofn(fd, iov, iovcnt);
		if (n < 0 || (total == 0 && n == 0))
			return total == 0? n : total;

		/* figure out how much we have processed */
		total += n;
		while (iovcnt > 0 && (size_t) n >= iov->iov_len) {
			n -= (iov++)->iov_len;
			iovcnt--;
		}

		/* are we done? */
		if (iovcnt == 0)
			break;

		/* we won't overwrite our arguments, so check if we need to
		 * allocate a new buffer to hold the remaining iovecs */
		if (i == NULL) {
			i = alloca(sizeof(*iov) * iovcnt);
			memcpy(i, iov, sizeof(*iov) * iovcnt);
			iov = i;
		} else {
			/* adjust pointer */
			i = (struct iovec *) iov;
		}

		/* adjust for partial read */
		i->iov_base = (char *) i->iov_base + n;
		i->iov_len -= n;
	}

	return total;
}

/*
 * Create the server socket and bind it to the specified local port
 */
static struct ioqueue *
make_socket(int port)
{
	static const struct ioparam_init
	init[] = {
		{ &ioqueue_socket_v6only,	true },
		{ &ioqueue_mcast_loop,		false },
		{ &ioqueue_socket_mcast_hops,	255 },
		{ &ioqueue_socket_reuselocal,	true }
	};

	struct sockaddr_in6 sin6;
	struct ioendpoint *endp;
	struct ioqueue *queue;

	/* create the the local endpoint */
	memset(&sin6, '\0', sizeof(sin6));
	sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_SA_LEN */
	sin6.sin6_port = htons(port);
	endp = ioendpoint_alloc_sockaddr((struct sockaddr *) &sin6);
	if (endp == NULL)
		fatal(1, "ioendpoint_alloc_sockaddr");

	/* create the socket */
	queue = ioqueue_alloc_socket(AF_INET6, NULL, endp, init, nitems(init));
	if (queue == NULL)
		fatal(1, "ioqueue_alloc_socket(AF_INET6)");

	ioendpoint_release(endp);

	return queue;
}

/*
 * Create the multicast address for the specified name and port
 */
static struct ioendpoint *
make_addr(const char *restrict name, size_t namelen, int port)
{
	hashval_t h;
	struct sockaddr_in6 sin6;
	struct ioendpoint *endp;

	/* hash the name */
	h = hash((const uint8_t *) name, namelen, port);
	h.low = hton64(h.low);
	h.high = hton64(h.high);

	/* determine the address */
	memset(&sin6, '\0', sizeof(sin6));
	sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_SA_LEN */
	sin6.sin6_port = htons(NET_PORT);
	memcpy(&sin6.sin6_addr, &h, sizeof(sin6.sin6_addr));
	sin6.sin6_addr.s6_addr[0] = 0xff;
	sin6.sin6_addr.s6_addr[1] = 0x15;

	/* allocate the endpoint */
	endp = ioendpoint_alloc_sockaddr((struct sockaddr *) &sin6);
	if (endp == NULL)
		fatal(1, "ioendpoint_alloc_sockaddr");

	return endp;
}

/*
 * Get own address.
 */
static struct ioendpoint *
getmyaddr(int port)
{
	struct ifaddrs *ifap, *i;
	struct ioendpoint *endp = NULL;

	if (getifaddrs(&ifap) < 0)
		fatal(1, "getifaddrs");

	for (i = ifap; i != NULL; i = i->ifa_next) {
		struct sockaddr_in6 sin6;

		/* skip non-IPv6 interfaces */
		if (i->ifa_addr->sa_family != AF_INET6)
			continue;

		/* skip local addresses */
		sin6 = *(struct sockaddr_in6 *) i->ifa_addr;
		if (IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr) ||
		    IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
			continue;

		/* get the address */
		sin6.sin6_port = htons(port);
		endp = ioendpoint_alloc_sockaddr((struct sockaddr *) &sin6);
		if (endp == NULL)
			fatal(1, "ioendpoint_alloc_sockaddr");

		break;
	}

	freeifaddrs(ifap);

	return endp;
}

/*
 * Log an error message to syslog
 */
static void
syslog_err(const char *str, size_t len, enum error error)
{
	int priority;

	switch (error) {
	case ERROR_FATAL:	priority = LOG_ERR;	break;
	case ERROR_WARNING:	priority = LOG_WARNING;	break;
	case ERROR_TRACE:	priority = LOG_DEBUG;	break;
	}

	openlog(getprogname(), LOG_PID, LOG_DAEMON);
	syslog(priority, "%*s\n", (int) len, str);
	closelog();
}

/*
 * Does sending a packet need the token?
 */
static bool
needs_token(const struct packet *packet)
{
	return packet->msg >= MSG_WITH_SEQUENCE &&
	       packet->sequence == UNKNOWN_SEQUENCE;
}

/*
 * Set state
 */
static void
set_state(struct net *net, enum state state)
{
	/* does this state require timeout processing? */
	if (net->state >= STATE_WITHOUT_TIMEOUT &&
	    state < STATE_WITHOUT_TIMEOUT)
		ioevent_attach(net->timeout_ev, net->ioloop);

	net->state = state;
}

/*
 * Free a packet
 */
static void
packet_free(struct packet *packet)
{
	if (packet != NULL)
		ioendpoint_release(packet->from);
	free(packet);
}


/***************************************************************************
 *** Sending multicast packets *********************************************
 ***************************************************************************/

/*
 * Place a packet to be sent into the queue
 */
static void
mcast_send_queue(struct net *net, struct packet *packet)
{
	/* we have something to send */
	ioevent_attach(net->mcast_send_ev, net->ioloop);

	if (!needs_token(packet))
		LIST_INSERT_FIRST(&net->sendq, packet, packetq);		
	else
		LIST_INSERT_LAST(&net->sendq, packet, packetq);
	net->sendqlen++;
}

/*
 * Place a message to be sent into the queue
 */
static void
mcast_send_msg(struct net *net, enum msg msg, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	struct packet *packet;

	/* determine required packet length */
	va_start(ap, fmt);
	len = vpack(NULL, 0, fmt, ap);
	va_end(ap);

	/* allocate memory for the packet */
	packet = malloc(offsetof(struct packet, buf) + len);
	if (packet == NULL) {
		warning("mcast_send: malloc(%zu)", sizeof(*packet) - sizeof(packet->buf) + len);
		return;
	}

	/* initialise the packet */
	memset(packet, '\0', offsetof(struct packet, buf));
	packet->msg = msg;
	packet->len = len;
	packet->sequence = UNKNOWN_SEQUENCE;

	/* pack the contents */
	va_start(ap, fmt);
	vpack(packet->buf, len, fmt, ap);
	va_end(ap);

	/* put it in the queue */
	mcast_send_queue(net, packet);
}

/*
 * Actually send a packet
 */
static void
mcast_send_process(struct net *net, struct packet *packet)
{
	char header[HEADERSZ];
	struct iobuf buf[2];

	assert(pack(NULL, 0, "bbwq", NET_VERSION, 0, 0, (uint64_t) 0) == HEADERSZ);

	/* create the header */
	buf[0].base = header;
	buf[0].len = pack(header, sizeof(header), "bbwq",
	    NET_VERSION, packet->msg, (int) packet->len, packet->sequence);
	buf[1].base = packet->buf;
	buf[1].len = packet->len;

	/* send the packet */
	if (ioqueue_sendv(net->mcast, nitems(buf), buf, net->multicast) < 0)
		warning("mcast_send_process: ioqueue_sendv");
}

/*
 * Send a packet
 */
static void
mcast_send(int UNUSED(dummy), struct net *net)
{
	struct packet *packet;

	/* do we have something to send? */
	packet = LIST_FIRST(&net->sendq, packetq);
	if (packet == NULL)
		goto detach;

	/* does the next packet need the token? */
	if (needs_token(packet)) {
		/* do we know where it is? */
		if (net->state == STATE_FOUND_TOKEN) {
			set_state(net, STATE_ASKING_TOKEN);
			mcast_send_msg(net, MSG_TOKEN_ASK, "");

			/* this changes the packet to be sent */
			packet = LIST_FIRST(&net->sendq, packetq);
		} else if (net->state != STATE_HAS_TOKEN) {
			goto detach;
		}
	}

	/* remove from the list */
	LIST_REMOVE_FIRST(&net->sendq, packetq);
	net->sendqlen--;

	assert(net->state == STATE_HAS_TOKEN || !needs_token(packet));

	/* is the next packet a token grant? */
	if (packet->msg == MSG_TOKEN_GIVE) {
		struct sockaddr_in6 sin6;
		struct ioendpoint *endp;

		/* record the new owner */
		sin6.sin6_family = AF_INET6;
		unpack(packet->buf, packet->len, "*b",
		    sizeof(sin6.sin6_addr), &sin6.sin6_addr);
		sin6.sin6_port = htons(NET_PORT);
		endp = ioendpoint_alloc_sockaddr((struct sockaddr *) &sin6);
		if (endp != NULL) {
			ioendpoint_release(net->owner);
			net->owner = endp;
		} else {
			warning("ioendpoint_alloc_sockaddr");
		}

		set_state(net, STATE_FOUND_TOKEN);
	}

	/* give the packet a sequence number of needed */
	if (packet->msg >= MSG_WITH_SEQUENCE &&
	    packet->sequence == UNKNOWN_SEQUENCE) {
		if (net->sequence == UNKNOWN_SEQUENCE)
			net->sequence = 0;
		packet->sequence = ++net->sequence;
	}

	/* send it */
	mcast_send_process(net, packet);

	/* place the packet on the list of sent packets */
	LIST_INSERT_LAST(&net->resendq, packet, packetq);
	net->resendqlen++;

	/* disable the fuse worker when we have a lot going on */
	if (net->resendqlen > MAXSENDQ * 2)
		ioevent_detach(net->fs_recv_ev);

	return;

detach:
	ioevent_detach(net->mcast_send_ev);
}

/*
 * Purge the resend queue
 */
static void
mcast_send_purge(int UNUSED(num), void *arg)
{
	struct net *net = (struct net *) arg;
	struct packet *packet;

	/* reduce queue length */
	while (net->resendqlen > MAXSENDQ) {
		packet = LIST_FIRST(&net->resendq, packetq);
		LIST_REMOVE_FIRST(&net->resendq, packetq);
		packet_free(packet);
		net->resendqlen--;
	}

	/* re-enable the fuse worker */
	ioevent_attach(net->fs_recv_ev, net->ioloop);
}


/***************************************************************************
 *** Receiving multicast packets *******************************************
 ***************************************************************************/

/*
 * Request resends for missing packets
 */
static void
mcast_recv_resend(int UNUSED(dummy), struct net *net)
{
	uint64_t sequence;

	/* request resends for missing packets */
	if (!LIST_EMPTY(&net->recvq)) {
		for (sequence = net->sequence + 1;
		     sequence < LIST_FIRST(&net->recvq, packetq)->sequence;
		     sequence++)
			mcast_send_msg(net, MSG_RESEND, "q", sequence);
	} else {
		ioevent_detach(net->resend_ev);
	}
}

/*
 * Queue a received packet
 */
static void
mcast_recv_queue(struct net *net, struct packet *packet)
{
	struct packet *pos;

	/* determine the position at which to insert the packet */
	LIST_FOREACH(pos, &net->recvq, packetq)
		if (pos->sequence > packet->sequence)
			break;

	/* insert here */
	if (pos != NULL)
		LIST_INSERT_BEFORE(&net->recvq, pos, packet, packetq);
	else
		LIST_INSERT_LAST(&net->recvq, packet, packetq);

	/* request resends */
	ioevent_attach(net->resend_ev, net->ioloop);
}

/*
 * Process a received packet
 */
static void
mcast_recv_process(struct net *net, struct packet *packet)
{
	/* process the packet */
	switch (packet->msg) {
	case MSG_RESEND: {
		uint64_t sequence;
		struct packet *sent;

		/* get sequence */
		if (unpack(packet->buf, packet->len, "q", &sequence) < 0)
			warning("mcast_recv_process: unpack");

		/* check if we have the packet */
		LIST_FOREACH(sent, &net->resendq, packetq) {
			if (sent->sequence == sequence) {
				/* resend this packet */
				LIST_REMOVE(&net->resendq, sent, packetq);
				net->resendqlen--;
				mcast_send_queue(net, sent);

				break;
			}
		}
		break;
	}

	case MSG_TOKEN_WHERE:
		if (net->state == STATE_HAS_TOKEN)
			/* we have the token; tell the others so */
			mcast_send_msg(net, MSG_TOKEN_HERE, "");
		break;

	case MSG_TOKEN_HERE:
		if (net->owner != NULL &&
		    !ioendpoint_equals(net->owner, packet->from)) {
			/* log spurious owner changes */
			if (net->state == STATE_FOUND_TOKEN)
				warningx("mcast_recv_process: spurious token owner change: %s -> %s",
				    ioendpoint_format(net->owner), ioendpoint_format(packet->from));
		}

		/* record the new owner */
		set_state(net, STATE_FOUND_TOKEN);
		net->owner = ioendpoint_retain(packet->from);
		break;

	case MSG_TOKEN_ASK:	/* somebody's requesting the token */
		/* if we have the token, grant it */
		if (net->state == STATE_HAS_TOKEN) {
			struct sockaddr_storage addr;

			ioendpoint_sockaddr(packet->from, &addr);
			mcast_send_msg(net, MSG_TOKEN_GIVE, "*b",
			    sizeof(struct in6_addr),
			    &((struct sockaddr_in6 *) &addr)->sin6_addr);
		}
		break;

	case MSG_TOKEN_GIVE: {	/* token was granted to another owner */
		struct sockaddr_in6 sin6;
		struct ioendpoint *endp;

		/* record the new owner */
		sin6.sin6_family = AF_INET6;
		unpack(packet->buf, packet->len, "*b",
		    sizeof(sin6.sin6_addr), &sin6.sin6_addr);
		sin6.sin6_port = htons(NET_PORT);
		endp = ioendpoint_alloc_sockaddr((struct sockaddr *) &sin6);
		if (endp != NULL) {
			ioendpoint_release(net->owner);
			net->owner = endp;

			set_state(net, ioendpoint_equals(net->owner, net->self)?
			    STATE_HAS_TOKEN : STATE_FOUND_TOKEN);

			/* start sending */
			if (net->state == STATE_HAS_TOKEN &&
			    !LIST_EMPTY(&net->sendq))
				ioevent_attach(net->mcast_send_ev, net->ioloop);
		} else {
			warning("ioendpoint_alloc_sockaddr");
		}

		break;
	}

	default:
		if (multifs_process(net->multifs, packet->msg, packet->buf, packet->len) == 0)
			warningx("mcast_recv_process: unknown message %d", packet->msg);
	}
}

/*
 * Dequeue received packets
 */
static void
mcast_recv_dequeue(struct net *net)
{
	struct packet *packet;

	/* process all packets that are in-order wrt. the sequence */
	while (!LIST_EMPTY(&net->recvq) &&
	    LIST_FIRST(&net->recvq, packetq)->sequence == net->sequence + 1) {
		/* take off the packet */
		packet = LIST_FIRST(&net->recvq, packetq);
		LIST_REMOVE_FIRST(&net->recvq, packetq);

		/* log spurious packets with sequence from hosts not holding
		 * the token */
		if (net->owner != NULL &&
		    !ioendpoint_equals(net->owner, packet->from)) {
			warningx("mcast_recv_process: packet with sequence not "
			    "from token owner");
			packet_free(packet);
			continue;
		}

		/* update the sequence */
		net->sequence = packet->sequence;

		/* process the packet */
		mcast_recv_process(net, packet);
		packet_free(packet);
	}
}

/*
 * Receive a single packet
 */
static void
mcast_recv(int UNUSED(dummy), struct net *net)
{
	ssize_t len;
	struct iobuf buf[2];
	char header[HEADERSZ];
	struct packet *packet;
	struct ioendpoint *from;
	uint8_t version;
	uint16_t plen;

	/* get packet length */
	len = ioqueue_nextsize(net->mcast);
	if (len < 0) {
		warning("mcast_recv: ioqueue_nextsize");
		return;
	}

	/* handle packets that are too small */
	if (len < (ssize_t) sizeof(header)) {
		/* receive */
		if (ioqueue_recv(net->mcast, header, sizeof(header), &from) < 0) {
			warning("mcast_recv: ioqueue_recvfrom");
			goto out;
		}

		warningx("mcast_recv: packet too small (%d) from %s",
		    len, ioendpoint_format(from));
		ioendpoint_release(from);

		return;
	}

	len -= sizeof(header);

	/* allocate memory for the packet */
	packet = malloc(offsetof(struct packet, buf) + len);
	if (packet == NULL) {
		warning("mcast_recv: malloc(%zu)",
		    offsetof(struct packet, buf) + len);
		return;
	}
	memset(packet, '\0', offsetof(struct packet, buf));

	/* set up structures */
	buf[0].base = header;
	buf[0].len = sizeof(header);
	buf[1].base = packet->buf;
	buf[1].len = len;

	/* receive */
	if (ioqueue_recvv(net->mcast, nitems(buf), buf, &from) < 0) {
		warning("mcast_recv: ioqueue_recvv");
		goto out;
	}

	/* initialise the packet and parse the header */
	packet->len = len;
	packet->from = from;
	if (unpack(header, sizeof(header), "bbwq",
	    &version, &packet->msg, &plen, &packet->sequence) < 0) {
		warning("mcast_recv: unpack");
		goto out;
	}

	/* check version */
	if (version != NET_VERSION) {
		warningx("mcast_recv: bad version %d from %s", version,
		    ioendpoint_format(from));
		goto out;
	}

	/* check for truncated packets and correct the packet length; this
	 * works around broken FIONREAD implementations (I'm looking at you,
	 * FreeBSD & Mac OS X) */
	if (packet->len < plen) {
		warningx("mcast_recv: truncated packet (got %d, expected %d)",
		    len, plen);
		goto out;
	}
	packet->len = plen;

	/* must this packet be processed in-sequence? */
	if (packet->msg >= MSG_WITH_SEQUENCE) {
		/* is the sequence as of yet unknown? */
		if (net->sequence == UNKNOWN_SEQUENCE)
			net->sequence = packet->sequence - 1;

		/* is this a resend of a packet we have already processed? */
		else if (packet->sequence <= net->sequence)
			goto out;

		/* queue this packet */
		mcast_recv_queue(net, packet);

		/* process receive queue */
		mcast_recv_dequeue(net);
	} else {
		mcast_recv_process(net, packet);
		goto out;
	}

	return;

out:
	packet_free(packet);
}


/***************************************************************************
 *** Communicating with the filesystem *************************************
 ***************************************************************************/

/*
 * Process a single packet from the filesystem
 */
static void
fs_recv(int UNUSED(dummy), struct net *net)
{
	size_t len;
	struct packet *packet;
	struct iovec iov[2];

	/* read the message length */
	if (read(net->fsfd, &len, sizeof(len)) != sizeof(len)) {
		/* short read or read error, connection was closed; meaning
		 * we ought to terminate as well */
		ioloop_break(net->ioloop);
		return;
	}

	/* allocate memory for the packet */
	packet = malloc(offsetof(struct packet, buf) + len);
	if (packet == NULL) {
		warning("fs_recv: malloc(%zu)", offsetof(struct packet, buf) + len);
		return;
	}

	/* initialise the packet */
	memset(packet, '\0', offsetof(struct packet, buf));
	packet->len = len;
	packet->sequence = UNKNOWN_SEQUENCE;

	/* set up structures */
	iov[0].iov_base = &packet->msg;
	iov[0].iov_len = sizeof(packet->msg);
	iov[1].iov_base = packet->buf;
	iov[1].iov_len = len;

	/* receive the packet */
	if (reliable_io(net->fsfd, iov, nitems(iov), readv) < 0) {
		warning("fs_recv: readv");
		packet_free(packet);
		return;
	}

	/* queue the packet */
	mcast_send_queue(net, packet);
}

/*
 * Send a single packet to the networking worker
 */
int
net_send(int netfd, enum msg msg, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	struct iovec iov[3];

	/* determine packet size */
	va_start(ap, fmt);
	len = vpack(NULL, 0, fmt, ap);
	va_end(ap);

	/* set up iovecs */
	iov[0].iov_base = &len;
	iov[0].iov_len = sizeof(len);
	iov[1].iov_base = &msg;
	iov[1].iov_len = sizeof(msg);

	/* allocate a buffer and format the packet */
	iov[2].iov_base = alloca(len);
	iov[2].iov_len = len;
	va_start(ap, fmt);
	vpack(iov[2].iov_base, len, fmt, ap);
	va_end(ap);

	if (reliable_io(netfd, iov, nitems(iov), writev) < 0) {
		warning("%s: reliable_io", __func__);
		return -1;
	}

	return 0;
}


/***************************************************************************
 *** Timeout processing ****************************************************
 ***************************************************************************/

static void
timeout(int UNUSED(dummy), void *arg)
{
	struct net *net = (struct net *) arg;

	switch (net->state) {
	case STATE_ASKING_TOKEN:
		mcast_send_msg(net, MSG_TOKEN_ASK, "");
		net->state++;
		break;

	case STATE_ASKING_TOKEN2:
		mcast_send_msg(net, MSG_TOKEN_WHERE, "");
		net->state++;
		break;

	case STATE_SEARCHING_TOKEN:
		mcast_send_msg(net, MSG_TOKEN_WHERE, "");
		net->state++;
		break;

	case STATE_SEARCHING_TOKEN2:
		trace("token not found, taking ownership");

		/* nobody responded on our request, so unilaterally declare
		 * that we have the token (ie. steal it) */
		mcast_send_msg(net, MSG_TOKEN_HERE, "");
		net->state = STATE_HAS_TOKEN;
		net->owner = ioendpoint_retain(net->self);
		break;

	default:
		/* no timeout processing necessary */
		break;
	}

	/* can we do without at timeout? */
	if (net->state >= STATE_WITHOUT_TIMEOUT)
		ioevent_detach(net->timeout_ev);
}


/***************************************************************************
 *** Initialisation and main loop ******************************************
 ***************************************************************************/

/*
 * Initialise networking
 */
void
net_init(struct multifs *multifs)
{
	int fd[2];
	struct net net;
	struct timeval tv;

	/* create the server socket */
	memset(&net, '\0', sizeof(net));
	net.multifs = multifs;
	net.mcast = make_socket(NET_PORT);
	net.sequence = UNKNOWN_SEQUENCE;
	net.self = getmyaddr(NET_PORT);

	/* set it to multicast */
	net.multicast = make_addr(multifs->fsname, multifs->fsnamelen, NET_PORT);
	if (ioqueue_mcast_join(net.mcast, net.multicast) < 0)
		fatal(1, "ioqueue_mcast_join");

	/* determine maximum message length */
	multifs->maxmsglen = ioqueue_maxsize(net.mcast);
	if (multifs->maxmsglen < 0)
		fatal(1, "ioqueue_maxsize");
	multifs->maxmsglen -= HEADERSZ;

	trace("using multicast group %s", ioendpoint_format(net.multicast));

	/* create the sockets the fuse worker uses to communicate with the
	 * networking worker */
	if (pipe(fd) < 0)
		fatal(1, "pipe");

	/* create the I/O loop */
	net.ioloop = ioloop_alloc(IOEVENT_READ | IOEVENT_WRITE | IOEVENT_TIMER | IOEVENT_FLAG);
	if (net.ioloop == NULL)
		fatal(1, "ioloop_alloc");

	/* create I/O events */
	net.fs_recv_ev = ioevent_read(fd[0], (ioevent_cb_t *) fs_recv, &net, 0);
	if (net.fs_recv_ev == NULL)
		fatal(1, "ioevent_read");

	net.mcast_recv_ev = ioqueue_recv_event(net.mcast, (ioevent_cb_t *) mcast_recv, &net, 0);
	if (net.mcast_recv_ev == NULL)
		fatal(1, "ioqueue_recv_event");

	net.mcast_send_ev = ioqueue_send_event(net.mcast, (ioevent_cb_t *) mcast_send, &net, 0);
	if (net.mcast_send_ev == NULL)
		fatal(1, "ioqueue_send_event");

	tv = (struct timeval) { 1, 0 };
	net.mcast_purge_ev = ioevent_timer(&tv, mcast_send_purge, &net, 0);
	if (net.mcast_purge_ev == NULL)
		fatal(1, "ioevent_timer");

	tv = (struct timeval) { 2, 0 };
	net.timeout_ev = ioevent_timer(&tv, timeout, &net, 0);
	if (net.timeout_ev == NULL)
		fatal(1, "ioevent_timer");

	tv = (struct timeval) { 1, 0 };
	net.resend_ev = ioevent_timer(&tv, (ioevent_cb_t *) mcast_recv_resend, &net, 0);
	if (net.resend_ev == NULL)
		fatal(1, "ioevent_timer");

	/* attach all */
	if (ioevent_attach(net.fs_recv_ev, net.ioloop) < 0 ||
	    ioevent_attach(net.mcast_recv_ev, net.ioloop) < 0 ||
	    ioevent_attach(net.mcast_send_ev, net.ioloop) < 0 ||
	    ioevent_attach(net.mcast_purge_ev, net.ioloop) < 0 ||
	    ioevent_attach(net.timeout_ev, net.ioloop) < 0 ||
	    ioevent_attach(net.resend_ev, net.ioloop) < 0 ||
	    ioqueue_attach(net.mcast, net.ioloop) < 0)
		fatal(1, "ioevent_attach");

	switch (multifs->netpid = fork()) {
	case -1:
		fatal(1, "fork");

	case 0:
		/* in child, continues below */
		close(fd[1]);
		net.fsfd = fd[0];
		break;

	default:
		/* in parent, close descriptors we no longer need here */
		close(fd[0]);
		ioqueue_free(net.mcast);
		multifs->netfd = fd[1];
		return;
	}

	/* set signal handlers to default, otherwise they'll invoke fuse
	 * functions that have no meaning in this child */
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);

	/* redirect everything from now to syslog */
	if (!multifs->debug)
		error_redirect(syslog_err);

	/* try to find out who has the token */
	net.state = STATE_SEARCHING_TOKEN;
	mcast_send_msg(&net, MSG_TOKEN_WHERE, "");

	/* process socket events */
	if (ioloop_run(net.ioloop) < 0)
		warning("ioloop_run");

	exit(0);
}
