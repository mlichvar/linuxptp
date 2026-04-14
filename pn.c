/**
 * @file pn.c
 * @note Derived from raw.c.
 * Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include "address.h"
#include "config.h"
#include "contain.h"
#include "ether.h"
#include "missing.h"
#include "pn.h"
#include "pn-ptcp.h"
#include "print.h"
#include "sk.h"
#include "transport_private.h"
#include "util.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * tcpdump -d \
 *  '(ether[12:2]=0x8100 and ether[12+4:2]=0x8892 and '\
 *  ' (ether[14+4:2]=0x0020 or ether[14+4:2]=0x0021 or '\
 *  '  ether[14+4:2]=0x0080 or ether[14+4:2]=0x0081 or '\
 *  '  ether[14+4:2]=0xFF40 or ether[14+4:2]=0xFF41 or ether[14+4:2]=0xFF43)) or '\
 *  '(ether[12:2]=0x8892 and '\
 *  ' (ether[14:2]=0x0020 or ether[14:2]=0x0021 or '\
 *  '  ether[14:2]=0x0080 or ether[14:2]=0x0081 or '\
 *  '  ether[14:2]=0xFF40 or ether[14:2]=0xFF41 or ether[14:2]=0xFF43))'
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2    jf 6
 * (002) ldh      [16]
 * (003) jeq      #0x8892          jt 4    jf 16
 * (004) ldh      [18]
 * (005) jeq      #0x20            jt 15   jf 9
 * (006) jeq      #0x8892          jt 7    jf 16
 * (007) ldh      [14]
 * (008) jeq      #0x20            jt 15   jf 9
 * (009) jeq      #0x21            jt 15   jf 10
 * (010) jeq      #0x80            jt 15   jf 11
 * (011) jeq      #0x81            jt 15   jf 12
 * (012) jeq      #0xff40          jt 15   jf 13
 * (013) jeq      #0xff41          jt 15   jf 14
 * (014) jeq      #0xff43          jt 15   jf 16
 * (015) ret      #262144
 * (016) ret      #0
 */
static struct sock_filter pn_event_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 4, 0x00008100 },
	{ 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 12, 0x00008892 },
	{ 0x28, 0, 0, 0x00000012 },
	{ 0x15, 9, 3, 0x00000020 },
	{ 0x15, 0, 9, 0x00008892 },
	{ 0x28, 0, 0, 0x0000000e },
	{ 0x15, 6, 0, 0x00000020 },
	{ 0x15, 5, 0, 0x00000021 },
	{ 0x15, 4, 0, 0x00000080 },
	{ 0x15, 3, 0, 0x00000081 },
	{ 0x15, 2, 0, 0x0000ff40 },
	{ 0x15, 1, 0, 0x0000ff41 },
	{ 0x15, 0, 1, 0x0000ff43 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

/*
 * tcpdump -d \
 *  '(ether[12:2]=0x8100 and ether[12+4:2]=0x8892 and '\
 *  ' (ether[14+4:2]=0xFF00 or ether[14+4:2]=0xFF01 or ether[14+4:2]=0xFF20 or '\
 *  '  ether[14+4:2]=0xFF21 or ether[14+4:2]=0xFF42)) or '\
 *  '(ether[12:2]=0x8892 and '\
 *  ' (ether[14:2]=0xFF00 or ether[14:2]=0xFF01 or ether[14:2]=0xFF20 or '\
 *  '  ether[14:2]=0xFF21 or ether[14:2]=0xFF42))'
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2	jf 6
 * (002) ldh      [16]
 * (003) jeq      #0x8892          jt 4	jf 14
 * (004) ldh      [18]
 * (005) jeq      #0xff00          jt 13	jf 9
 * (006) jeq      #0x8892          jt 7	jf 14
 * (007) ldh      [14]
 * (008) jeq      #0xff00          jt 13	jf 9
 * (009) jeq      #0xff01          jt 13	jf 10
 * (010) jeq      #0xff20          jt 13	jf 11
 * (011) jeq      #0xff21          jt 13	jf 12
 * (012) jeq      #0xff42          jt 13	jf 14
 * (013) ret      #262144
 * (014) ret      #0
 */
static struct sock_filter pn_general_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 4, 0x00008100 },
	{ 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 10, 0x00008892 },
	{ 0x28, 0, 0, 0x00000012 },
	{ 0x15, 7, 3, 0x0000ff00 },
	{ 0x15, 0, 7, 0x00008892 },
	{ 0x28, 0, 0, 0x0000000e },
	{ 0x15, 4, 0, 0x0000ff00 },
	{ 0x15, 3, 0, 0x0000ff01 },
	{ 0x15, 2, 0, 0x0000ff20 },
	{ 0x15, 1, 0, 0x0000ff21 },
	{ 0x15, 0, 1, 0x0000ff42 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

static int pn_configure(int fd, int event, int index, int enable)
{
	struct packet_mreq mreq;
	struct sock_fprog prg;
	int option;

	if (event) {
		prg.len = ARRAY_SIZE(pn_event_filter);
		prg.filter = pn_event_filter;
	} else {
		prg.len = ARRAY_SIZE(pn_general_filter);
		prg.filter = pn_general_filter;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prg, sizeof(prg))) {
		pr_err("setsockopt SO_ATTACH_FILTER failed: %m");
		return -1;
	}

	option = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

	memset(&mreq, 0, sizeof (mreq));
	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_ALLMULTI;
	mreq.mr_alen = 0;
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	pr_warning("setsockopt PACKET_MR_ALLMULTI failed: %m");

	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;
	memset(&mreq.mr_address, 0, sizeof (mreq.mr_address));
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	pr_warning("setsockopt PACKET_MR_PROMISC failed: %m");

	pr_err("all socket options failed");
	return -1;
}

static int pn_close(struct transport *t, struct fdarray *fda)
{
	close(fda->fd[0]);
	close(fda->fd[1]);
	return 0;
}

static int open_socket(struct interface *iface, int event,
		       enum timestamp_type ts_type)
{
	const char *name = interface_label(iface);
	struct sockaddr_ll addr;
	int fd, index;

	fd = socket(PF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		pr_err("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		pr_err("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}

	if (event) {
		if (sk_timestamping_init(fd, name, ts_type, TRANS_IEEE_802_3,
					 interface_get_vclock(iface)))
			goto no_option;
	} else {
		if (sk_general_init(fd))
			goto no_option;
	}

	if (pn_configure(fd, event, index, 1))
		goto no_option;

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("bind failed: %m");
		goto no_option;
	}

	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

static void addr_to_mac(void *mac, struct address *addr)
{
	memcpy(mac, &addr->sll.sll_addr, MAC_LEN);
}

static int parse_subdomain(const char *str, unsigned char subdomain[SUBD_LEN])
{
	unsigned char buf[SUBD_LEN];
	int c = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:"
		       "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		       &buf[0], &buf[1], &buf[2], &buf[3],
		       &buf[4], &buf[5], &buf[6], &buf[7],
		       &buf[8], &buf[9], &buf[10], &buf[11],
		       &buf[12], &buf[13], &buf[14], &buf[15]);
	if (c != SUBD_LEN) {
		return -1;
	}
	memcpy(subdomain, buf, SUBD_LEN);
	return 0;
}

static int pn_open(struct transport *t, struct interface *iface,
		   struct fdarray *fda, enum timestamp_type ts_type)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	uint16_t log_variance;
	const char *name;
	int efd, gfd;
	char *str;

	name = interface_label(iface);
	str = config_get_string(t->cfg, name, "rh_subdomainUUID");
	if (parse_subdomain(str, pn->subdomain)) {
		pr_err("invalid subdomainUUID %s", str);
		return -1;
	}
	pn->quality.clockClass = config_get_int(t->cfg, NULL, "clockClass");
	pn->quality.clockAccuracy = config_get_int(t->cfg, NULL, "clockAccuracy");
	log_variance = config_get_int(t->cfg, NULL, "offsetScaledLogVariance");
	pn->quality.offsetScaledLogVariance = htons(log_variance);
	pn->priority2 = config_get_int(t->cfg, NULL, "priority2");
	pn->utc_offset = htons(CURRENT_UTC_OFFSET);

	pn->timestamping = config_get_int(t->cfg, NULL, "time_stamping");
	pn->domain = config_get_int(t->cfg, NULL, "domainNumber");
	pn->transportSpecific = config_get_int(t->cfg, name, "transportSpecific");
	pn->logSyncInterval = config_get_int(t->cfg, name, "logSyncInterval");
	pn->logAnnounceInterval = config_get_int(t->cfg, name, "logAnnounceInterval");

	if (sk_interface_macaddr(name, &pn->src_addr))
		goto no_mac;

	efd = open_socket(iface, 1, ts_type);
	if (efd < 0)
		goto no_event;

	gfd = open_socket(iface, 0, ts_type);
	if (gfd < 0)
		goto no_general;

	fda->fd[FD_EVENT] = efd;
	fda->fd[FD_GENERAL] = gfd;
	return 0;

no_general:
	close(efd);
no_event:
no_mac:
	return -1;
}

static int pn_recv(struct transport *t, int fd, void *buf, int buflen,
		   struct address *addr, struct hw_timestamp *hwts)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	struct pn_storage rx_data;
	struct PTCP_PDU *src = &rx_data.pdu;
	unsigned char *ptr = (unsigned char *) src;
	int cnt, hlen, length = sizeof(*src);
	struct ptp_message *dst = buf;
	struct eth_hdr *hdr;

	if (pn->vlan) {
		hlen = sizeof(struct vlan_hdr);
	} else {
		hlen = sizeof(struct eth_hdr);
	}
	ptr    -= hlen;
	length += hlen;
	hdr = (struct eth_hdr *) ptr;

	cnt = sk_receive(fd, ptr, length, addr, hwts, MSG_DONTWAIT);
	if (cnt >= 0) {
		cnt -= hlen;
	}
	if (cnt < 0) {
		return cnt;
	}

	if (pn->vlan) {
		if (ETH_P_PROFINET == ntohs(hdr->type)) {
			pr_notice("pn: disabling VLAN mode");
			pn->vlan = 0;
		}
	} else {
		if (ETH_P_8021Q == ntohs(hdr->type)) {
			pr_notice("pn: switching to VLAN mode");
			pn->vlan = 1;
		}
	}
	cnt = ptcp_to_ptp(src, cnt, dst, pn);
	return cnt;
}

static int pn_send(struct transport *t, struct fdarray *fda,
		   enum transport_event event, int peer, void *buf, int buflen,
		   struct address *addr, struct hw_timestamp *hwts)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	struct pn_storage tx_data;
	struct PTCP_PDU *dst = &tx_data.pdu;
	struct ptp_message *src = buf;
	unsigned char pkt[1600], *ptr;
	struct eth_hdr *hdr;
	int fd, length;
	ssize_t cnt;

	fd = event ? fda->fd[FD_EVENT] : fda->fd[FD_GENERAL];
	ptr = ptp_to_ptcp(src, dst, pn, &length);
	if (!ptr) {
		return -EINVAL;
	}

	hdr = (struct eth_hdr *) ptr;
	addr_to_mac(&hdr->src, &pn->src_addr);
	cnt = send(fd, ptr, length, 0);
	if (cnt < 1) {
		pr_err("send failed: %d %m", errno);
		return cnt;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event == TRANS_EVENT ?
		sk_receive(fd, pkt, sizeof(pkt), NULL, hwts, MSG_ERRQUEUE) : cnt;
}

static void pn_release(struct transport *t)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	free(pn);
}

static int pn_physical_addr(struct transport *t, uint8_t *addr)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	addr_to_mac(addr, &pn->src_addr);
	return MAC_LEN;
}

static int pn_protocol_addr(struct transport *t, uint8_t *addr)
{
	struct pn_info *pn = container_of(t, struct pn_info, t);
	addr_to_mac(addr, &pn->src_addr);
	return MAC_LEN;
}

struct transport *pn_transport_create(void)
{
	struct pn_info *pn;
	pn = calloc(1, sizeof(*pn));
	if (!pn)
		return NULL;
	pn->t.close   = pn_close;
	pn->t.open    = pn_open;
	pn->t.recv    = pn_recv;
	pn->t.send    = pn_send;
	pn->t.release = pn_release;
	pn->t.physical_addr = pn_physical_addr;
	pn->t.protocol_addr = pn_protocol_addr;
	return &pn->t;
}
