/**
 * @file pn-ptcp.h
 * @brief Implements PTCP message types.
 * @note Copyright (C) 2016 linutronix GmbH
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
#ifndef HAVE_PN_PTCP_H
#define HAVE_PN_PTCP_H

#include <stdint.h>

#include "address.h"
#include "ddt.h"
#include "ether.h"
#include "msg.h"
#include "transport_private.h"

#define SUBD_LEN 16

struct PTCP_Header_Sync {
	uint32_t reserved_1;
	uint32_t reserved_2;
	uint32_t Delay10ns;
	uint16_t SequenceID;
	uint8_t  Delay1ns_Byte;
	/* Ensure 32 bit alignment. */
	uint8_t  Padding;
	uint32_t Delay1ns;
} PACKED;

struct PTCP_Header_FUP {
	uint8_t  Padding[12];
	uint16_t SequenceID;
	uint8_t  Padding2[2];
	int32_t  Delay1ns_FUP;
} PACKED;

struct PTCP_Header_Announce {
	uint8_t  Padding[12];
	uint16_t SequenceID;
	uint8_t  Padding2[6];
} PACKED;

struct PTCP_Header_Delay {
	uint8_t  Padding[12];
	uint16_t SequenceID;
	uint8_t  Padding2[2];
	uint32_t Delay1ns;
} PACKED;

enum ptcp_tlv_type {
	PTCP_END,
	PTCP_SUBDOMAIN,
	PTCP_TIME,
	PTCP_TIME_EXTENSION,
	PTCP_MASTER,
	PTCP_PORT_PARAMETER,
	PTCP_DELAY_PARAMETER,
	PTCP_PORT_TIME,
};

struct PTCPSubdomain {
	uint16_t TLVHeader;
	eth_addr MasterSourceAddress;
	uint8_t  SubdomainUUID[SUBD_LEN];
} PACKED;

struct PTCPTime {
	uint16_t TLVHeader;
	uint16_t EpochNumber;
	uint32_t Seconds;
	uint32_t NanoSeconds;
} PACKED;

struct PTCPTimeExtension {
	uint16_t TLVHeader;
	uint16_t Flags;
	int16_t  CurrentUTCOffset;
	/* Ensure 32 bit alignment. */
	uint16_t Padding;
} PACKED;

struct PTCPMaster {
	uint16_t TLVHeader;
	uint8_t  MasterPriority1;
	uint8_t  MasterPriority2;
	uint8_t  ClockClass;
	uint8_t  ClockAccuracy;
	uint16_t ClockVariance;
	/* Ensure 32 bit alignment. */
	/* Padding */
} PACKED;

struct PTCPDelayParameter {
	uint16_t TLVHeader;
	uint8_t  PortMACAddress[6];
} PACKED;

struct PTCPPortParameter {
	uint16_t TLVHeader;
	uint8_t Padding[2];
	uint32_t T2PortRxDelay;
	uint32_t T3PortTxDelay;
} PACKED;

struct PTCPPortTime {
	uint16_t TLVHeader;
	uint8_t Padding[2];
	uint32_t T2TimeStamp;
} PACKED;

struct PTCP_RTSyncPDU {
	struct PTCPSubdomain subdomain;
	struct PTCPTime time;
	struct PTCPTimeExtension tmext;
	struct PTCPMaster master;
	/* PTCPOption */
	uint16_t End;
	/*
	 * Shall be existent, if initially transmitted in the RED
	 * period and may be omitted, if initially transmitted in the
	 * ORANGE or GREEN period:
	 */
	/* APDU_Status */
} PACKED;

struct PTCP_FollowUpPDU {
	struct PTCPSubdomain subdomain;
	struct PTCPTime time;
	/* PTCPOption */
	uint16_t End;
} PACKED;

struct PTCP_AnnouncePDU {
	struct PTCPSubdomain subdomain;
	struct PTCPMaster master;
	/* PTCPOption */
	uint16_t End;
} PACKED;

struct PTCP_DelayReqPDU {
	struct PTCPDelayParameter param;
	/* PTCPOption */
	uint16_t End;
} PACKED;

struct PTCP_DelayResPDU {
	struct PTCPDelayParameter delay_param;
	struct PTCPPortParameter port_param;
	struct PTCPPortTime time;
	/* PTCPOption */
	uint16_t End;
} PACKED;

struct PTCP_DelayFuResPDU {
	struct PTCPDelayParameter param;
	/* PTCPOption */
	uint16_t End;
} PACKED;

struct PTCP_SYNC_PDU {
	struct PTCP_Header_Sync	hdr;
	struct PTCP_RTSyncPDU	pdu;
} PACKED;

struct PTCP_FUP_PDU {
	struct PTCP_Header_FUP hdr;
	struct PTCP_FollowUpPDU pdu;
} PACKED;

struct PTCP_ANNOUNCE_PDU {
	struct PTCP_Header_Announce hdr;
	struct PTCP_AnnouncePDU pdu;
} PACKED;

struct PTCP_DELAY_REQ_PDU {
	struct PTCP_Header_Delay hdr;
	struct PTCP_DelayReqPDU pdu;
} PACKED;

struct PTCP_DELAY_RSP_PDU {
	struct PTCP_Header_Delay hdr;
	struct PTCP_DelayResPDU pdu;
} PACKED;

struct PTCP_DELAY_FU_RSP_PDU {
	struct PTCP_Header_Delay hdr;
	struct PTCP_DelayFuResPDU pdu;
} PACKED;

struct PTCP_PDU {
	uint16_t frame_id;
	union {
		struct PTCP_SYNC_PDU sync;
		struct PTCP_FUP_PDU fup;
		struct PTCP_ANNOUNCE_PDU anno;
		struct PTCP_DELAY_REQ_PDU req;
		struct PTCP_DELAY_RSP_PDU resp;
		struct PTCP_DELAY_FU_RSP_PDU resfup;
	} PACKED;
} PACKED;

/*
 * Head room fits a VLAN Ethernet header, and 'pdu.sync' is 64 bit aligned.
 */
#define PN_HEADROOM 22

struct pn_storage {
	unsigned char reserved[PN_HEADROOM];
	struct PTCP_PDU pdu;
} PACKED;

struct pn_info {
	struct transport t;
	struct address src_addr;
	int vlan;

	/* Peer port ID is not provided by PTCP response or follow-up! */
	struct PortIdentity peer_portid;

	/* Transmit conversion helpers */
	uint64_t tx_t2;

	/* Receive conversion helpers */
	enum timestamp_type timestamping;
	UInteger16 portNumber;
	uint64_t rx_t2;

	/* The following fields are in network byte order. */

	/* Transmit conversion helpers */
	unsigned char subdomain[SUBD_LEN];
	struct ClockQuality quality;
	struct PTCPTime time;
	uint8_t priority2;
	int16_t utc_offset;
	uint16_t tmext_flags;

	/* Receive conversion helpers */
	uint8_t domain;
	UInteger8 transportSpecific;
	Integer8 logSyncInterval;
	Integer8 logAnnounceInterval;
};

unsigned char *ptp_to_ptcp(struct ptp_message *src, struct PTCP_PDU *dst,
			   struct pn_info *info, int *len);

int ptcp_to_ptp(struct PTCP_PDU *src, int len, struct ptp_message *dst,
		struct pn_info *info);

#endif
