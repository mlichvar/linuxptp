/**
 * @file pn-ptcp.c
 * @brief Implements PTCP message types.
 * @note Copyright (C) 2016 linutronix GmbH
 *
 * @note The PTP message construction was based on code from port.c.
 *       Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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
#include <linux/if_ether.h>

#include "missing.h"
#include "pn-ptcp.h"
#include "print.h"
#include "util.h"

#define FID_SYFU_CLOCK          0x0020 /* Two-step Sync */
#define FID_SYFU_TIME           0x0021
#define FID_SYNC_CLOCK          0x0080 /* One-step Sync */
#define FID_SYNC_TIME           0x0081
#define FID_ANNO_CLOCK          0xFF00 /* Announce */
#define FID_ANNO_TIME           0xFF01
#define FID_FUP_CLOCK           0xFF20 /* FollowUp */
#define FID_FUP_TIME            0xFF21
#define FID_DELAY_REQ           0xFF40 /* Peer Delay Request */
#define FID_DELAY_RESP          0xFF41 /* Two-step Peer Delay Response */
#define FID_DELAY_RESP_FU       0xFF42 /* Peer Delay Response FollowUp */
#define FID_DELAY_RESP_1        0xFF43 /* One-step Peer Delay Response */

#define MAC_SYFU_CLOCK          0x20
#define MAC_SYFU_TIME           0x21
#define MAC_ANNO_CLOCK          0x00
#define MAC_ANNO_TIME           0x01
#define MAC_FUP_CLOCK           0x40
#define MAC_FUP_TIME            0x41
#define MAC_PEER                0x0E

#define PRIMARY_MASTER          (1 << 0)
#define MASTER_ACTIVE           (1 << 7)
#define MASTER_PRIO_1           (PRIMARY_MASTER | MASTER_ACTIVE)

enum controlField {
       CTL_SYNC,
       CTL_DELAY_REQ,
       CTL_FOLLOW_UP,
       CTL_DELAY_RESP,
       CTL_MANAGEMENT,
       CTL_OTHER,
};

static void tlv_set(void *buf, int tag, int len)
{
	uint16_t word;

	word = htons((tag << 9) | len);
	memcpy(buf, &word, sizeof(word));
}

#define TLV_SET(x, type) \
	tlv_set(&(x).TLVHeader, type, sizeof(x) - 2)

static const unsigned char pn_ptcp_mac[MAC_LEN] = {
	0x01, 0x0E, 0xCF, 0x00, 0x04, 0x00
};

static const unsigned char pn_peer_mac[MAC_LEN] = {
	0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E
};

static void mac_to_pid(eth_addr mac, struct PortIdentity *pid)
{
	pid->clockIdentity.id[0] = mac[0];
	pid->clockIdentity.id[1] = mac[1];
	pid->clockIdentity.id[2] = mac[2];
	pid->clockIdentity.id[3] = 0xFF;
	pid->clockIdentity.id[4] = 0xFE;
	pid->clockIdentity.id[5] = mac[3];
	pid->clockIdentity.id[6] = mac[4];
	pid->clockIdentity.id[7] = mac[5];
}

static void ns_to_Timestamp(uint64_t ns, struct Timestamp *ts)
{
	*ts = tmv_to_Timestamp(nanoseconds_to_tmv(ns));
}

static void pid_to_mac(struct PortIdentity *pid, eth_addr mac)
{
	mac[0] = pid->clockIdentity.id[0];
	mac[1] = pid->clockIdentity.id[1];
	mac[2] = pid->clockIdentity.id[2];
	mac[3] = pid->clockIdentity.id[5];
	mac[4] = pid->clockIdentity.id[6];
	mac[5] = pid->clockIdentity.id[7];
}

static void ptp_to_ptcp_subdomain(struct pn_info *info,
				  struct PortIdentity *pid,
				  struct PTCPSubdomain *s)
{
	TLV_SET(*s, PTCP_SUBDOMAIN);
	pid_to_mac(pid, s->MasterSourceAddress);
	memcpy(s->SubdomainUUID, info->subdomain, SUBD_LEN);
}

static void ptp_to_ptcp_master(struct pn_info *info, struct PTCPMaster *m)
{
	TLV_SET(*m, PTCP_MASTER);
	m->MasterPriority1 = MASTER_PRIO_1;
	m->MasterPriority2 = info->priority2;
	m->ClockClass = info->quality.clockClass;
	m->ClockAccuracy = info->quality.clockAccuracy;
	m->ClockVariance = info->quality.offsetScaledLogVariance;
}

static unsigned char *setup_ethernet_header(unsigned char *ptr,
					    const unsigned char *dst_mac,
					    unsigned char last_mac_byte)
{
	struct eth_hdr *hdr;

	ptr -= sizeof(*hdr);
	hdr = (struct eth_hdr *) ptr;
	memcpy(&hdr->dst, dst_mac, MAC_LEN);
	hdr->dst[MAC_LEN - 1] = last_mac_byte;
	hdr->type = htons(ETH_P_PROFINET);

	return ptr;
}

static uint64_t Timestamp_to_ns(struct Timestamp *ts)
{
	uint64_t sec, nsec, result;
	uint32_t lsb = ntohl(ts->seconds_lsb);
	uint16_t msb = ntohs(ts->seconds_msb);

	sec  = ((uint64_t)lsb) | (((uint64_t)msb) << 32);
	nsec = ntohl(ts->nanoseconds);
	result = sec * NS_PER_SEC + nsec;
	return result;
}

static tmv_t ptcp_time_to_tmv(struct PTCPTime *t)
{
	struct Timestamp ts;

	ts.seconds_msb = t->EpochNumber;
	ts.seconds_lsb = t->Seconds;
	ts.nanoseconds = t->NanoSeconds;

	return nanoseconds_to_tmv(Timestamp_to_ns(&ts));
}

static unsigned char *ptp_sync_to_ptcp(struct ptp_message *msg,
				       struct PTCP_PDU *pdu,
				       struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_SYNC_PDU *sync = &pdu->sync;

	/* Only two-step sync is supported. */
	if (!(msg->header.flagField[0] & TWO_STEP))
		return NULL;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*sync);

	ptr = setup_ethernet_header(ptr, pn_ptcp_mac, MAC_SYFU_TIME);
	pdu->frame_id = htons(FID_SYFU_TIME);

	sync->hdr.SequenceID = msg->header.sequenceId;

	ptp_to_ptcp_subdomain(info, &msg->header.sourcePortIdentity,
			      &sync->pdu.subdomain);

	TLV_SET(sync->pdu.time, PTCP_TIME);
	sync->pdu.time.EpochNumber =
		msg->sync.originTimestamp.seconds_msb;
	sync->pdu.time.Seconds =
		msg->sync.originTimestamp.seconds_lsb;
	sync->pdu.time.NanoSeconds =
		msg->sync.originTimestamp.nanoseconds;

	info->time = sync->pdu.time;

	TLV_SET(sync->pdu.tmext, PTCP_TIME_EXTENSION);
	sync->pdu.tmext.Flags = info->tmext_flags;
	sync->pdu.tmext.CurrentUTCOffset = info->utc_offset;

	ptp_to_ptcp_master(info, &sync->pdu.master);

	return ptr;
}

static unsigned char *ptp_fup_to_ptcp(struct ptp_message *msg,
				      struct PTCP_PDU *pdu,
				      struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_FUP_PDU *fup = &pdu->fup;
	tmv_t actx, estx;
	int32_t corr;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*fup);

	ptr = setup_ethernet_header(ptr, pn_ptcp_mac, MAC_FUP_TIME);
	pdu->frame_id = htons(FID_FUP_TIME);

	fup->hdr.SequenceID = msg->header.sequenceId;

	ptp_to_ptcp_subdomain(info, &msg->header.sourcePortIdentity,
			      &fup->pdu.subdomain);

	fup->pdu.time = info->time;

	estx = ptcp_time_to_tmv(&fup->pdu.time);
	actx = nanoseconds_to_tmv(Timestamp_to_ns(&msg->follow_up.preciseOriginTimestamp));
	corr = tmv_to_nanoseconds(tmv_sub(actx, estx));

	if (corr > INT32_MAX) {
		corr = INT32_MAX;
	} else if (corr < INT32_MIN) {
		corr = INT32_MIN;
	}

	fup->hdr.Delay1ns_FUP = htonl((uint32_t) corr);

	return ptr;
}

static unsigned char *ptp_anno_to_ptcp(struct ptp_message *msg,
				       struct PTCP_PDU *pdu,
				       struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_ANNOUNCE_PDU *anno = &pdu->anno;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*anno);

	ptr = setup_ethernet_header(ptr, pn_ptcp_mac, MAC_ANNO_TIME);
	pdu->frame_id = htons(FID_ANNO_TIME);

	anno->hdr.SequenceID = msg->header.sequenceId;

	ptp_to_ptcp_subdomain(info, &msg->header.sourcePortIdentity,
			      &anno->pdu.subdomain);

	/*
	 * We will need quality, priority2, and friends in the PTCP
	 * Sync message, so we remember the latest values here.
	 */
	info->quality    = msg->announce.grandmasterClockQuality;
	info->priority2  = msg->announce.grandmasterPriority2;
	info->utc_offset = msg->announce.currentUtcOffset;

	if (field_is_set(msg, 1, LEAP_61)) {
		info->tmext_flags = htons(1 << 8);
	} else if (field_is_set(msg, 1, LEAP_59)) {
		info->tmext_flags = htons(2 << 8);
	} else {
		info->tmext_flags = 0;
	}

	ptp_to_ptcp_master(info, &anno->pdu.master);

	return ptr;
}

static unsigned char *ptp_req_to_ptcp(struct ptp_message *msg,
				      struct PTCP_PDU *pdu,
				      struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_DELAY_REQ_PDU *req = &pdu->req;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*req);

	ptr = setup_ethernet_header(ptr, pn_peer_mac, MAC_PEER);
	pdu->frame_id = htons(FID_DELAY_REQ);

	req->hdr.SequenceID = msg->header.sequenceId;

	TLV_SET(req->pdu.param, PTCP_DELAY_PARAMETER);
	pid_to_mac(&msg->header.sourcePortIdentity,
		   req->pdu.param.PortMACAddress);
	/*
	 * The requesting port ID in the PTCP responses does not
	 * include the port number.  Remember the local port number
	 * so that we can fudge it back into the responses.
	 */
	info->portNumber = ntohs(msg->header.sourcePortIdentity.portNumber);

	return ptr;
}

static unsigned char *ptp_resp_to_ptcp(struct ptp_message *msg,
				       struct PTCP_PDU *pdu,
				       struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_DELAY_RSP_PDU *resp = &pdu->resp;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*resp);

	ptr = setup_ethernet_header(ptr, pn_peer_mac, MAC_PEER);
	pdu->frame_id = htons(FID_DELAY_RESP);

	resp->hdr.SequenceID = msg->header.sequenceId;

	TLV_SET(resp->pdu.delay_param, PTCP_DELAY_PARAMETER);
	pid_to_mac(&msg->pdelay_resp.requestingPortIdentity,
		   resp->pdu.delay_param.PortMACAddress);

	TLV_SET(resp->pdu.port_param, PTCP_PORT_PARAMETER);
	/*
	 * We leave T2PortRxDelay and T3PortTxDelay as zero, since
	 * the time stamps are already corrected for ingress/egress
	 * latency at the port layer.
	 */

	TLV_SET(resp->pdu.time, PTCP_PORT_TIME);
	/*
	 * The port layer always sends the pdelay_resp_fup immediately
	 * after the pdelay_resp.  Remember timestamp T2 so that we can
	 * calculate the local residence time for the PTCP follow up.
	 */
	info->tx_t2 = Timestamp_to_ns(&msg->pdelay_resp.requestReceiptTimestamp);
	resp->pdu.time.T2TimeStamp = htonl(info->tx_t2);

	return ptr;
}

static unsigned char *ptp_resfup_to_ptcp(struct ptp_message *msg,
					 struct PTCP_PDU *pdu,
					 struct pn_info *info, int *len)
{
	unsigned char *ptr = (unsigned char *) pdu;
	struct PTCP_DELAY_FU_RSP_PDU *rfp = &pdu->resfup;
	uint64_t diff;

	*len = sizeof(struct eth_hdr) + sizeof(pdu->frame_id) + sizeof(*rfp);

	ptr = setup_ethernet_header(ptr, pn_peer_mac, MAC_PEER);
	pdu->frame_id = htons(FID_DELAY_RESP_FU);

	rfp->hdr.SequenceID = msg->header.sequenceId;

	diff = Timestamp_to_ns(&msg->pdelay_resp_fup.responseOriginTimestamp);
	diff -= info->tx_t2;
	rfp->hdr.Delay1ns = htonl(diff);

	TLV_SET(rfp->pdu.param, PTCP_DELAY_PARAMETER);
	pid_to_mac(&msg->pdelay_resp.requestingPortIdentity,
		   rfp->pdu.param.PortMACAddress);

	return ptr;
}

unsigned char *ptp_to_ptcp(struct ptp_message *msg, struct PTCP_PDU *pdu,
			   struct pn_info *info, int *len)
{
	memset(pdu, 0, sizeof(*pdu));

	switch (msg_type(msg)) {
	case SYNC:
		return ptp_sync_to_ptcp(msg, pdu, info, len);
	case FOLLOW_UP:
		return ptp_fup_to_ptcp(msg, pdu, info, len);
	case PDELAY_REQ:
		return ptp_req_to_ptcp(msg, pdu, info, len);
	case PDELAY_RESP:
		return ptp_resp_to_ptcp(msg, pdu, info, len);
	case PDELAY_RESP_FOLLOW_UP:
		return ptp_resfup_to_ptcp(msg, pdu, info, len);
	case ANNOUNCE:
		return ptp_anno_to_ptcp(msg, pdu, info, len);
	}
	return NULL;
}

static int ptcp_sync_to_ptp(struct PTCP_SYNC_PDU *pdu, int len,
			    struct ptp_message *msg, struct pn_info *info,
			    int two_step)
{
	int pdulen = sizeof(struct sync_msg);

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = SYNC | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;

	mac_to_pid(pdu->pdu.subdomain.MasterSourceAddress,
		   &msg->header.sourcePortIdentity);

	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_SYNC;
	msg->header.logMessageInterval = info->logSyncInterval;

	if (two_step)
		msg->header.flagField[0] |= TWO_STEP;

	if (msg_pre_send(msg)) {
		return -1;
	}

	/* Remember fields to be reported in the announce message. */
	info->tmext_flags = pdu->pdu.tmext.Flags;
	info->utc_offset = pdu->pdu.tmext.CurrentUTCOffset;
	info->priority2 = pdu->pdu.master.MasterPriority2;
	info->quality.clockClass = pdu->pdu.master.ClockClass;
	info->quality.clockAccuracy = pdu->pdu.master.ClockAccuracy;
	info->quality.offsetScaledLogVariance = pdu->pdu.master.ClockVariance;

	return pdulen;
}

static int ptcp_anno_to_ptp(struct PTCP_ANNOUNCE_PDU *pdu, int len,
			    struct ptp_message *msg, struct pn_info *info)
{
	int pdulen = sizeof(struct announce_msg);
	uint16_t flags;

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = ANNOUNCE | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;

	mac_to_pid(pdu->pdu.subdomain.MasterSourceAddress,
		   &msg->header.sourcePortIdentity);

	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = info->logAnnounceInterval;

	flags = ntohs(info->tmext_flags);
	if (flags & (1 << 8)) {
		msg->header.flagField[1] |= LEAP_61;
	} else if (flags & (2 << 8)) {
		msg->header.flagField[1] |= LEAP_59;
	}

	msg->announce.currentUtcOffset        = ntohs(info->utc_offset);
	msg->announce.grandmasterPriority1    = 128;
	msg->announce.grandmasterClockQuality = info->quality;
	msg->announce.grandmasterClockQuality.offsetScaledLogVariance =
		ntohs(info->quality.offsetScaledLogVariance);
	msg->announce.grandmasterPriority2    = info->priority2;
	msg->announce.grandmasterIdentity     =
		msg->header.sourcePortIdentity.clockIdentity;
	msg->announce.stepsRemoved            = 1;
	msg->announce.timeSource              = INTERNAL_OSCILLATOR;

	return msg_pre_send(msg) ? -1 : pdulen;
}

static int ptcp_fup_to_ptp(struct PTCP_FUP_PDU *pdu, int len,
			   struct ptp_message *msg, struct pn_info *info)
{
	int pdulen = sizeof(struct follow_up_msg);
	tmv_t actx, corr, estx;

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = FOLLOW_UP | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;

	mac_to_pid(pdu->pdu.subdomain.MasterSourceAddress,
		   &msg->header.sourcePortIdentity);

	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_FOLLOW_UP;
	msg->header.logMessageInterval = info->logSyncInterval;

	estx = ptcp_time_to_tmv(&pdu->pdu.time);
	corr = nanoseconds_to_tmv(ntohl(pdu->hdr.Delay1ns_FUP));
	actx = tmv_add(estx, corr);

	msg->follow_up.preciseOriginTimestamp = tmv_to_Timestamp(actx);

	return msg_pre_send(msg) ? -1 : pdulen;
}

static int ptcp_req_to_ptp(struct PTCP_DELAY_REQ_PDU *pdu, int len,
			   struct ptp_message *msg, struct pn_info *info)
{
	int pdulen = sizeof(struct pdelay_req_msg);

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = PDELAY_REQ | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;

	mac_to_pid(pdu->pdu.param.PortMACAddress,
		   &msg->header.sourcePortIdentity);

	msg->header.sourcePortIdentity.portNumber = 1;

	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = 0x7f;

	/* Assume this peer is sending responses to our requests as well. */
	info->peer_portid = msg->header.sourcePortIdentity;

	return msg_pre_send(msg) ? -1 : pdulen;
}

static int ptcp_resp_to_ptp(struct PTCP_DELAY_RSP_PDU *pdu, int len,
			    struct ptp_message *msg, struct pn_info *info,
			    int two_step)
{
	int pdulen = sizeof(struct pdelay_resp_msg);

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = PDELAY_RESP | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;
	/*
	 * PTCP doesn't tell us the peer's port ID.  Assume this
	 * message came from the sender of the last received request.
	 */
	msg->header.sourcePortIdentity = info->peer_portid;
	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = 0x7f;

	if (two_step)
		msg->header.flagField[0] |= TWO_STEP;

	mac_to_pid(pdu->pdu.delay_param.PortMACAddress,
		   &msg->pdelay_resp.requestingPortIdentity);

	msg->pdelay_resp.requestingPortIdentity.portNumber = info->portNumber;

	/*
	 * Remember T2 from the payload.  The follow-up will deliver
	 * (T3-T2) instead of T3.  In addition, the payload values are
	 * only 32 bits wide.  We will just construct phony T2 and T3
	 * values without the missing upper bits.
	 */
	info->rx_t2 = ntohl(pdu->pdu.time.T2TimeStamp);
	ns_to_Timestamp(info->rx_t2, &msg->pdelay_resp.requestReceiptTimestamp);

	return msg_pre_send(msg) ? -1 : pdulen;
}

static int ptcp_resfup_to_ptp(struct PTCP_DELAY_FU_RSP_PDU *pdu, int len,
			      struct ptp_message *msg, struct pn_info *info)
{
	int pdulen = sizeof(struct pdelay_resp_fup_msg);
	uint64_t diff;

	if (len < sizeof(*pdu))
	    return -EBADMSG;

	msg->hwts.type = info->timestamping;

	msg->header.tsmt               = PDELAY_RESP_FOLLOW_UP | info->transportSpecific;
	msg->header.ver                = PTP_VERSION;
	msg->header.messageLength      = pdulen;
	msg->header.domainNumber       = info->domain;
	msg->header.sourcePortIdentity = info->peer_portid;
	msg->header.sequenceId         = ntohs(pdu->hdr.SequenceID);
	msg->header.control            = CTL_OTHER;
	msg->header.logMessageInterval = 0x7f;

	mac_to_pid(pdu->pdu.param.PortMACAddress,
		   &msg->pdelay_resp_fup.requestingPortIdentity);

	msg->pdelay_resp_fup.requestingPortIdentity.portNumber = info->portNumber;

	diff = ntohl(pdu->hdr.Delay1ns);
	diff += info->rx_t2;
	ns_to_Timestamp(diff, &msg->pdelay_resp_fup.responseOriginTimestamp);

	return msg_pre_send(msg) ? -1 : pdulen;
}

int ptcp_to_ptp(struct PTCP_PDU *pdu, int len, struct ptp_message *msg,
		struct pn_info *info)
{
	if (len < sizeof(pdu->frame_id))
		return -EBADMSG;
	len -= sizeof(pdu->frame_id);

	switch (ntohs(pdu->frame_id)) {
	case FID_SYFU_TIME:
		return ptcp_sync_to_ptp(&pdu->sync, len, msg, info, 1);
	case FID_SYNC_TIME:
		return ptcp_sync_to_ptp(&pdu->sync, len, msg, info, 0);
	case FID_ANNO_TIME:
		return ptcp_anno_to_ptp(&pdu->anno, len, msg, info);
	case FID_FUP_TIME:
		return ptcp_fup_to_ptp(&pdu->fup, len, msg, info);
	case FID_DELAY_REQ:
		return ptcp_req_to_ptp(&pdu->req, len, msg, info);
	case FID_DELAY_RESP:
		return ptcp_resp_to_ptp(&pdu->resp, len, msg, info, 1);
	case FID_DELAY_RESP_FU:
		return ptcp_resfup_to_ptp(&pdu->resfup, len, msg, info);
	case FID_DELAY_RESP_1:
		return ptcp_resp_to_ptp(&pdu->resp, len, msg, info, 0);
	case FID_SYFU_CLOCK:
	case FID_SYNC_CLOCK:
	case FID_ANNO_CLOCK:
	case FID_FUP_CLOCK:
		pr_debug("ignoring PTCP message %x", ntohs(pdu->frame_id));
		return 0;
	}
	return -1;
}
