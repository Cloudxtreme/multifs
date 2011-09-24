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

/*
 * TODO:
 * - resends (request and acknowledge)
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef HAVE_SYS_SELECT
# include <sys/select.h>
#else
# include <sys/time.h>
#endif

/* length of an IPv6 address encoded as a string, plus terminating NUL character */
#define MAX6ADDR	40

/* size of the packet header */
#define HEADERSZ	(1 + 1 + sizeof(uint16_t) + sizeof(uint64_t))

/* unknown sequence */
#define UNKNOWN_SEQUENCE UINT64_MAX

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
	struct in6_addr		 from;		/* sender */
	enum msg		 msg;		/* packet message */
	uint64_t		 sequence;	/* sequence number */
	size_t			 len;		/* packet length */
	char			 buf[1];	/* packet contents */
};

/* networking state */
struct net {
	struct multifs		*multifs;
	bool			 exit;
	int			 mcastfd;
	int			 fsfd;
	enum state		 state;
	uint64_t		 sequence;
	struct sockaddr_in6	 multicast;
	struct in6_addr		 self,
				 owner;
	char			 ipbuf[64];
	LIST_HEAD(, packet)	 waitq,		/* packets still to be sent,
						 * waiting for us to gain
						 * the token */
				 sendq;		/* packets already sent,
				 		 * being kept around to
				 		 * service NACKs */
	LIST_HEAD(, packet)	 recvq;		/* packets received but not
						 * yet processed (eg.
						 * because they were
						 * received out-of-sequence */
};

/* empty owner */
static const struct in6_addr
in6_addr_any = IN6ADDR_ANY_INIT;

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
static int
make_socket(int port)
{
	int mcastfd, opt;
	struct sockaddr_in6 sin6;

	/* create the socket */
	mcastfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (mcastfd < 0)
		err(1, "socket");

	/* set options */
	opt = 1;
#if defined(SO_REUSEPORT)
	if (setsockopt(mcastfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
		err(1, "setsockopt(SOL_SOCKET, SO_REUSEPORT)");
#elif defined(HAVE_REUSEADDR_LIKE_REUSEPORT)
	if (setsockopt(mcastfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
		err(1, "setsockopt(SOL_SOCKET, SO_REUSEADDR)");
#endif

	opt = 1;
	if (setsockopt(mcastfd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0)
		err(1, "setsockopt(IPPROTO_IPV6, IPV6_V6ONLY)");

	opt = 0;
	if (setsockopt(mcastfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &opt, sizeof(opt)) < 0)
		err(1, "setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS)");
	opt = 255;
	if (setsockopt(mcastfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &opt, sizeof(opt)) < 0)
		err(1, "setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS)");

	/* bind to the local port */
	memset(&sin6, '\0', sizeof(sin6));
	sin6.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_SA_LEN */
	sin6.sin6_port = htons(port);
	if (bind(mcastfd, (const struct sockaddr *) &sin6, sizeof(sin6)) < 0)
		err(1, "bind");

	return mcastfd;
}

/*
 * Create the multicast address for the specified name and port
 */
static void
make_addr(const char *restrict name, size_t namelen, int port,
          struct sockaddr_in6 *sin6)
{
	hashval_t h;

	/* hash the name */
	h = hash((const uint8_t *) name, namelen, port);
	h.low = hton64(h.low);
	h.high = hton64(h.high);

	/* determine the address */
	memset(sin6, '\0', sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_SA_LEN */
	sin6->sin6_port = htons(NET_PORT);
	memcpy(&sin6->sin6_addr, &h, sizeof(sin6->sin6_addr));
	sin6->sin6_addr.s6_addr[0] = 0xff;
	sin6->sin6_addr.s6_addr[1] = 0x15;
}

/*
 * Make the server socket a multicast socket
 */
static void
make_multicast(int mcastfd, const struct sockaddr_in6 *addr)
{
	struct ipv6_mreq mreq;

	/* join the multicast group */
	mreq.ipv6mr_multiaddr = addr->sin6_addr;
	mreq.ipv6mr_interface = 0;
	if (setsockopt(mcastfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
		err(1, "setsockopt(IPV6_JOIN_GROUP)");
}

/*
 * Get own address.
 */
static void
getmyaddr(struct in6_addr *self)
{
	struct ifaddrs *ifap, *i;

	if (getifaddrs(&ifap) < 0)
		err(1, "getifaddrs");

	for (i = ifap; i != NULL; i = i->ifa_next) {
		const struct in6_addr *addr;

		/* skip non-IPv6 interfaces */
		if (i->ifa_addr->sa_family != AF_INET6)
			continue;

		/* skip local addresses */
		addr = &((struct sockaddr_in6 *) i->ifa_addr)->sin6_addr;
		if (IN6_IS_ADDR_LOOPBACK(addr) || IN6_IS_ADDR_LINKLOCAL(addr))
			continue;

		/* get the address */
		*self = ((struct sockaddr_in6 *) i->ifa_addr)->sin6_addr;
		break;
	}

	freeifaddrs(ifap);
}

/*
 * Log an error message to syslog
 */
static void
syslog_err(const char *str, size_t len, enum err err)
{
	int priority;

	switch (err) {
	case ERR_ERR:	priority = LOG_ERR;	break;
	case ERR_WARN:	priority = LOG_WARNING;	break;
	case ERR_TRACE:	priority = LOG_DEBUG;	break;
	}

	openlog(getprogname(), LOG_PID, LOG_DAEMON);
	syslog(priority, "%*s\n", (int) len, str);
	closelog();
}

/*
 * Format an address as a string
 */
static const char *
net_addr(struct net *net, const struct sockaddr_in6 *sin6)
{
	size_t len;

	/* format the address */
	net->ipbuf[0] = '[';
	inet_ntop(AF_INET6, &sin6->sin6_addr, net->ipbuf + 1, sizeof(net->ipbuf) - 1);
	len = strlen(net->ipbuf);

	/* append the port */
	snprintf(net->ipbuf + len, sizeof(net->ipbuf) - len, "]:%d", ntohs(sin6->sin6_port));

	return net->ipbuf;
}


/***************************************************************************
 *** Sending multicast packets *********************************************
 ***************************************************************************/

/*
 * Queue a packet waiting to be sent
 */
static void
mcast_send_queue(struct net *net, struct packet *packet)
{
	LIST_INSERT_LAST(&net->waitq, packet, packetq);
}

/*
 * Process a packet to be sent
 */
static void
mcast_send_process(struct net *net, struct packet *packet)
{
	char header[HEADERSZ];
	struct iovec iov[2];
	struct msghdr msghdr;

	assert(pack(NULL, 0, "bbwq", NET_VERSION, 0, 0, (uint64_t) 0) == HEADERSZ);

	/* is this a token grant? */
	if (packet->msg == MSG_TOKEN_GIVE) {
		/* record the new owner */
		unpack(packet->buf, packet->len, "*b",
		    sizeof(net->owner), &net->owner);
		net->state = STATE_FOUND_TOKEN;
	}

	/* create the header */
	iov[0].iov_base = header;
	iov[0].iov_len = pack(header, sizeof(header), "bbwq",
	    NET_VERSION, packet->msg, (int) packet->len, packet->sequence);
	iov[1].iov_base = packet->buf;
	iov[1].iov_len = packet->len;

	memset(&msghdr, '\0', sizeof(msghdr));
	msghdr.msg_name = &net->multicast;
	msghdr.msg_namelen = sizeof(net->multicast);
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = nitems(iov);

	/* send the packet */
	if (sendmsg(net->mcastfd, &msghdr, 0) < 0)
		warn("mcast_send_process: sendmsg");

	/* place the packet on the list of sent packets, to be expunged at a
	 * later moment */
	LIST_INSERT_LAST(&net->sendq, packet, packetq);
}

static void
mcast_send(struct net *net, enum msg msg, const char *fmt, ...);

/*
 * Dequeue packets to be sent
 */
static void
mcast_send_dequeue(struct net *net)
{
	int i;
	struct packet *packet;

	/* do we have packets to send? */
	if (LIST_EMPTY(&net->waitq)) 
		return;

	/* do we know where the token is? */
	if (net->state == STATE_FOUND_TOKEN) {
		/* ask for the token */
		net->state = STATE_ASKING_TOKEN;
		mcast_send(net, MSG_TOKEN_ASK, "");
		return;
	} else if (net->state != STATE_HAS_TOKEN) {
		/* timeout() will solve this */
		return;
	}

	/* don't hog the network too much */
	for (i = 0;
	     i < 10 &&
	      !LIST_EMPTY(&net->waitq) &&
	      net->state == STATE_HAS_TOKEN;
	     i++) {
		/* remove a packet from the list */
		packet = LIST_FIRST(&net->waitq, packetq);
		LIST_REMOVE_FIRST(&net->waitq, packetq);

		/* give it a sequence number and send it */
		packet->sequence = ++net->sequence;
		mcast_send_process(net, packet);
	}
}

/*
 * Send a packet
 */
static void
mcast_send(struct net *net, enum msg msg, const char *fmt, ...)
{
	va_list ap;
	size_t len;
	struct packet *packet;

	/* determine required packet length */
	va_start(ap, fmt);
	len = vpack(NULL, 0, fmt, ap);
	va_end(ap);

	/* allocate memory for the packet */
	packet = malloc(sizeof(*packet) - sizeof(packet->buf) + len);
	if (packet == NULL) {
		warn("mcast_send: malloc(%zu)", sizeof(*packet) - sizeof(packet->buf) + len);
		return;
	}

	/* initialise the packet */
	memset(packet, '\0', offsetof(struct packet, buf));
	packet->msg = msg;
	packet->len = len;

	/* pack the contents */
	va_start(ap, fmt);
	vpack(packet->buf, len, fmt, ap);
	va_end(ap);

	/* must this packet be processed in-sequence? */
	if (packet->msg >= MSG_WITH_SEQUENCE)
		mcast_send_queue(net, packet);
	else
		mcast_send_process(net, packet);
}


/***************************************************************************
 *** Receiving multicast packets *******************************************
 ***************************************************************************/

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
}

/*
 * Process a received packet
 */
static void
mcast_recv_process(struct net *net, struct packet *packet)
{
	char buf1[MAX6ADDR], buf2[MAX6ADDR];

	/* process the packet */
	switch (packet->msg) {
	case MSG_TOKEN_WHERE:
		if (net->state == STATE_HAS_TOKEN)
			/* we have the token; tell the others so */
			mcast_send(net, MSG_TOKEN_HERE, "");
		break;

	case MSG_TOKEN_HERE:
		if (memcmp(&net->owner, &packet->from, sizeof(net->owner)) != 0) {
			/* log spurious owner changes */
			if (net->state == STATE_FOUND_TOKEN)
				warnx("mcast_recv_process: spurious token owner change: %s -> %s",
				    inet_ntop(AF_INET6, &net->owner, buf1, sizeof(buf1)),
				    inet_ntop(AF_INET6, &packet->from, buf2, sizeof(buf2)));
		}

		/* record the new owner */
		net->state = STATE_FOUND_TOKEN;
		net->owner = packet->from;
		break;

	case MSG_TOKEN_ASK:	/* somebody's requesting the token */
		/* if we have the token, grant it */
		if (net->state == STATE_HAS_TOKEN) {
			mcast_send(net, MSG_TOKEN_GIVE, "*b",
			    sizeof(packet->from), &packet->from);
		}
		break;

	case MSG_TOKEN_GIVE:	/* token was granted to another owner */
		/* get the new owner */
		if (unpack(packet->buf, packet->len, "*b",
		    sizeof(net->owner), &net->owner) < 0)
			warn("mcast_recv_process: unpack");
		net->state = memcmp(&net->owner, &net->self, sizeof(net->owner)) == 0?
		    STATE_HAS_TOKEN : STATE_FOUND_TOKEN;

		break;

	default:
		if (multifs_process(net->multifs, packet->msg, packet->buf, packet->len) == 0)
			warnx("mcast_recv_process: unknown message %d", packet->msg);
	}

	free(packet);
}

/*
 * Dequeue received packets
 */
static void
mcast_recv_dequeue(struct net *net)
{
	struct packet *packet;

	/* process all packets that are in-order wrt. the sequence */
	while (LIST_FIRST(&net->recvq, packetq) != NULL &&
	    LIST_FIRST(&net->recvq, packetq)->sequence == net->sequence + 1) {
		/* take off the packet */
		packet = LIST_FIRST(&net->recvq, packetq);
		LIST_REMOVE_FIRST(&net->recvq, packetq);

		/* log spurious packets with sequence from hosts not holding
		 * the token */
		if (memcmp(&net->owner, &packet->from,
		    sizeof(net->owner)) != 0) {
			warnx("mcast_recv_process: packet with sequence not "
			    "from token owner");
			free(packet);
			continue;
		}

		/* update the sequence */
		net->sequence = packet->sequence;

		/* process the packet */
		mcast_recv_process(net, packet);
	}
}

/*
 * Receive a single packet
 */
static void
mcast_recv(struct net *net)
{
	unsigned int len;
	struct iovec iov[2];
	struct msghdr msghdr;
	char header[HEADERSZ];
	struct packet *packet;
	struct sockaddr_in6 from;
	uint8_t version;
	uint16_t plen;

	/* get packet length */
	len = 0;
	if (ioctl(net->mcastfd, FIONREAD, &len) < 0) {
		warn("mcast_recv: ioctl(FIONREAD)");
		return;
	}

	/* handle packets that are too small */
	if (len < sizeof(header)) {
		/* set up structures */
		iov[0].iov_base = header;
		iov[0].iov_len = sizeof(header);

		memset(&msghdr, '\0', sizeof(msghdr));
		msghdr.msg_name = &from;
		msghdr.msg_namelen = sizeof(from);
		msghdr.msg_iov = iov;
		msghdr.msg_iovlen = 1;

		/* receive */
		if (recvmsg(net->mcastfd, &msghdr, 0) < 0) {
			warn("mcast_recv: recvmsg");
			goto out;
		}

		warnx("mcast_recv: packet too small (%d) from %s",
		    len, net_addr(net, &from));

		return;
	}

	len -= sizeof(header);

	/* allocate memory for the packet */
	packet = malloc(offsetof(struct packet, buf) + len);
	if (packet == NULL) {
		warn("mcast_recv: malloc(%zu)",
		    offsetof(struct packet, buf) + len);
		return;
	}

	/* set up structures */
	iov[0].iov_base = header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = packet->buf;
	iov[1].iov_len = len;

	memset(&msghdr, '\0', sizeof(msghdr));
	msghdr.msg_name = &from;
	msghdr.msg_namelen = sizeof(from);
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = nitems(iov);

	/* receive */
	if (recvmsg(net->mcastfd, &msghdr, 0) < 0) {
		warn("mcast_recv: recvmsg");
		goto out;
	}

	/* initialise the packet and parse the header */
	memset(packet, '\0', offsetof(struct packet, buf));
	packet->len = len;
	packet->from = from.sin6_addr;
	if (unpack(header, sizeof(header), "bbwq",
	    &version, &packet->msg, &plen, &packet->sequence) < 0) {
		warn("mcast_recv: unpack");
		goto out;
	}

	/* check version */
	if (version != NET_VERSION) {
		warnx("mcast_recv: bad version %d from %s", version,
		    net_addr(net, &from));
		goto out;
	}

	/* check for truncated packets and correct the packet length; this
	 * works around broken FIONREAD implementations (I'm looking at you,
	 * FreeBSD & Mac OS X) */
	if (packet->len < plen) {
		warnx("mcast_recv: truncated packet (got %d, expected %d)",
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

		mcast_recv_queue(net, packet);
	} else {
		mcast_recv_process(net, packet);
	}

	return;

out:
	free(packet);
}


/***************************************************************************
 *** Communicating with the filesystem *************************************
 ***************************************************************************/

/*
 * Process a single packet from the filesystem
 */
static void
fs_recv(struct net *net)
{
	size_t len;
	struct packet *packet;
	struct iovec iov[2];

	/* read the message length */
	if (read(net->fsfd, &len, sizeof(len)) != sizeof(len)) {
		/* short read or read error, connection was closed; meaning
		 * we ought to terminate as well */
		net->exit = true;
		return;
	}

	/* allocate memory for the packet */
	packet = malloc(offsetof(struct packet, buf) + len);
	if (packet == NULL) {
		warn("fs_recv: malloc(%zu)", offsetof(struct packet, buf) + len);
		return;
	}

	/* initialise the packet */
	memset(packet, '\0', offsetof(struct packet, buf));
	packet->len = len;

	/* set up structures */
	iov[0].iov_base = &packet->msg;
	iov[0].iov_len = sizeof(packet->msg);
	iov[1].iov_base = packet->buf;
	iov[1].iov_len = len;

	/* receive the packet */
	if (reliable_io(net->fsfd, iov, nitems(iov), readv) < 0) {
		warn("fs_recv: readv");
		free(packet);
		return;
	}

	/* must this packet be processed in-sequence? */
	if (packet->msg >= MSG_WITH_SEQUENCE)
		mcast_send_queue(net, packet);
	else
		mcast_send_process(net, packet);
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

	return reliable_io(netfd, iov, nitems(iov), writev);
}


/***************************************************************************
 *** Timeout processing ****************************************************
 ***************************************************************************/

static void
timeout(struct net *net)
{
	switch (net->state) {
	case STATE_ASKING_TOKEN:
		mcast_send(net, MSG_TOKEN_ASK, "");
		net->state++;
		break;

	case STATE_ASKING_TOKEN2:
		mcast_send(net, MSG_TOKEN_WHERE, "");
		net->state++;
		break;

	case STATE_SEARCHING_TOKEN:
		mcast_send(net, MSG_TOKEN_WHERE, "");
		net->state++;
		break;

	case STATE_SEARCHING_TOKEN2:
		trace("token not found, taking ownership");

		/* nobody responded on our request, so unilaterally declare
		 * that we have the token (ie. steal it) */
		mcast_send(net, MSG_TOKEN_HERE, "");
		net->state = STATE_HAS_TOKEN;
		net->owner = net->self;
		break;

	default:
		/* no timeout processing necessary */
		break;
	}
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
	int fd[2], nfds;
	struct net net;
	fd_set fds;
	socklen_t socklen;

	/* create the server socket */
	memset(&net, '\0', sizeof(net));
	net.multifs = multifs;
	net.mcastfd = make_socket(NET_PORT);
	net.sequence = UNKNOWN_SEQUENCE;
	getmyaddr(&net.self);

	/* set it to multicast */
	make_addr(multifs->fsname, multifs->fsnamelen, NET_PORT, &net.multicast);
	make_multicast(net.mcastfd, &net.multicast);

	/* determine maximum message length */
	socklen = sizeof(multifs->maxmsglen);
	if (getsockopt(net.mcastfd, SOL_SOCKET, SO_SNDBUF,
	    &multifs->maxmsglen, &socklen) < 0)
		err(1, "getsockopt(SOL_SOCKET, SO_SNDBUF)");
	multifs->maxmsglen -= HEADERSZ;

	trace("using multicast group %s",
	    net_addr(&net, &net.multicast));

	/* create the sockets the fuse worker uses to communicate with the
	 * networking worker */
	if (pipe(fd) < 0)
		err(1, "pipe");

	switch (multifs->netpid = fork()) {
	case -1:
		err(1, "fork");

	case 0:
		/* in child, continues below */
		close(fd[1]);
		net.fsfd = fd[0];
		break;

	default:
		/* in parent, close descriptors we no longer need here */
		close(fd[0]);
		close(net.mcastfd);
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
		err_redirect(syslog_err);

	/* try to find out who has the token */
	net.state = STATE_SEARCHING_TOKEN;
	mcast_send(&net, MSG_TOKEN_WHERE, "");

	/* set up select */
	FD_ZERO(&fds);
	FD_SET(net.fsfd, &fds);
	FD_SET(net.mcastfd, &fds);
	nfds = max(net.mcastfd, net.fsfd) + 1;

	/* process socket events */
	while (!net.exit) {
		int n;
		fd_set rfds;
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };

		/* wait for an event */
		rfds = fds;
		n = select(nfds, &rfds, NULL, NULL,
		    net.state >= STATE_WITHOUT_TIMEOUT? NULL : &tv);
		if (n < 0) {
			warn("select");
			continue;
		}

		/* handle timeouts */
		if (n == 0) {
			timeout(&net);
		} else {
			/* handle changes from the fuse worker(s) */
			if (FD_ISSET(net.fsfd, &rfds))
				fs_recv(&net);

			/* handle incoming packets */
			if (FD_ISSET(net.mcastfd, &rfds))
				mcast_recv(&net);
		}

		/* process packet queues */
		mcast_recv_dequeue(&net);
		mcast_send_dequeue(&net);
	}

	exit(0);
}
