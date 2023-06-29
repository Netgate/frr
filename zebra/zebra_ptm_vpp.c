/*
 * Copyright 2020, Rubicon Communications, LLC.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <zebra.h>

#include "bfd.h"
#include "if.h"
#include "stream.h"
#include "vrf.h"
#include "workqueue.h"

#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_ptm_vpp.h"

#include <tnsrinfra/types.h>
#include <tnsrinfra/vec.h>

#include <vppmgmt2/vpp_mgmt2_api.h>
#include <vppmgmt2/vpp_mgmt2_bfd.h>
#include <vppmgmt2/vpp_mgmt2_ip.h>


/*
 * Peers storage functions
 */

struct vpp_bfd_peer {
	vapi_type_address peer_addr;
	vapi_type_address local_addr;
	uint32_t sw_if_index;
	uint32_t ifindex;
	uint8_t multi_hop;
	uint8_t cbit;
};

static struct vpp_bfd_peer *bfd_peers_to_monitor;


static uint32_t
zebra_ptm_vpp_bfd_peer_search(vapi_type_address *peer_addr, uint32_t sw_if_index)
{
	uint32_t index;

	tnsr_vec_foreach_index(index, bfd_peers_to_monitor) {
		struct vpp_bfd_peer *bp;

		bp = tnsr_vec_elt_at_index(bfd_peers_to_monitor, index);
		if (bp->sw_if_index != sw_if_index) {
			continue;
		}
		if (!vmgmt2_ip_address_equal(&bp->peer_addr, peer_addr)) {
			continue;
		}

		return index;
	}

	return ~0U;
}


static struct vpp_bfd_peer *
zebra_ptm_vpp_bfd_get_peer(vapi_type_address *peer_addr, uint32_t sw_if_index)
{
	uint32_t index;

	index = zebra_ptm_vpp_bfd_peer_search(peer_addr, sw_if_index);
	if (index == ~0U) {
		return NULL;
	}

	struct vpp_bfd_peer *bfd_peer;

	bfd_peer = tnsr_vec_elt_at_index(bfd_peers_to_monitor, index);

	return bfd_peer;
}


/*
 * Messages parsing functions
 */

static void
zebra_ptm_vpp_parse_addr(struct stream *msg, vapi_type_address *addr)
{
	uint8_t family;
	STREAM_GETW(msg, family);

	uint8_t addr_len;
	if (family == AF_INET) {
		addr_len = IPV4_MAX_BYTELEN;
		family = ADDRESS_IP4;
	} else if (family == AF_INET6) {
		addr_len = IPV6_MAX_BYTELEN;
		family = ADDRESS_IP6;
	} else {
		zlog_warn("%s: invalid address family: %u", __func__, family);
		return;
	}

	addr->af = family;
	STREAM_GET(&addr->un, msg, addr_len);

stream_failure:
	return;
}


static void
zebra_ptm_vpp_parse_msg(struct stream *msg,
			uint32_t command,
			struct vpp_bfd_peer *bfd_peer)
{
	uint32_t tmp_num;
	uint8_t if_name_len;

	memset(bfd_peer, 0, sizeof(*bfd_peer));
	bfd_peer->sw_if_index = ~0U;
	bfd_peer->ifindex = IFINDEX_INTERNAL;

	/* Skip field: pid. */
	STREAM_GETL(msg, tmp_num);

	/* Read field: family. */
	/* Read field: destination address. */
	zebra_ptm_vpp_parse_addr(msg, &bfd_peer->peer_addr);
	bfd_peer->local_addr.af = bfd_peer->peer_addr.af;

	/* Skip field: min_rx_timer. */
	STREAM_GETL(msg, tmp_num);
	/* Skip field: min_tx_timer. */
	STREAM_GETL(msg, tmp_num);
	/* Skip field: detect_mult. */
	STREAM_GETC(msg, tmp_num);

	/* Read field: is_multihop. */
	STREAM_GETC(msg, bfd_peer->multi_hop);

	/* Read field: family. */
	/* Read field: source address. */
	zebra_ptm_vpp_parse_addr(msg, &bfd_peer->local_addr);

	vmgmt2_ip_refresh_all();
	u32 sw_if_index = vmgmt2_ip_lookup_intf_by_addr(&bfd_peer->local_addr);
	bfd_peer->sw_if_index = sw_if_index;
	if (bfd_peer->sw_if_index == ~0U) {
		zlog_debug("%s: cannot resolve sw_if_index by local address",
			   __func__);
	}

	/* Skip field: ttl. */
	STREAM_GETC(msg, tmp_num);

	/* Read field: ifname length. */
	STREAM_GETC(msg, if_name_len);
	if (if_name_len >= INTERFACE_NAMSIZ) {
		zlog_err("%s: invalid if_name_len: %u", __func__, if_name_len);
		return;
	}

	/* Read field: interface name. */
	if (if_name_len > 0) {
		char if_name[INTERFACE_NAMSIZ];

		STREAM_GET(if_name, msg, if_name_len);
		if_name[if_name_len] = '\0';

		if (bfd_peer->sw_if_index == ~0U) {
			int n;

			n = sscanf(if_name, "vpp%u", &bfd_peer->sw_if_index);
			if (n != 1) {
				bfd_peer->sw_if_index = ~0U;
				zlog_err("%s: cannot parse interface name: %s",
					 __func__, if_name);
				return;
			}

			struct interface *ifp;

			ifp = if_lookup_by_name(if_name, VRF_DEFAULT);
			if (ifp == NULL) {
				zlog_err("%s: cannot lookup interface by "
					 "name: %s", __func__, if_name);
				return;
			}

			bfd_peer->ifindex = ifp->ifindex;
		}
	}

	/* Read field: bfd_cbit. */
	STREAM_GETC(msg, bfd_peer->cbit);

	/* Skip field: profile name length. */
	/* Skip field: profile name. */

stream_failure:
	tmp_num = tmp_num;
	return;
}


/*
 * Messages construction functions
 */

static void
zebra_ptm_vpp_make_addr(struct stream *msg,
			vapi_type_address *addr)
{
	uint8_t af = addr->af;

	if (af == ADDRESS_IP4) {
		stream_putc(msg, AF_INET);
		stream_put(msg, &addr->un, IPV4_MAX_BYTELEN);
		stream_putc(msg, 32);

	} else if (af == ADDRESS_IP6) {
		stream_putc(msg, AF_INET6);
		stream_put(msg, &addr->un, IPV6_MAX_BYTELEN);
		stream_putc(msg, 128);

	} else {
		zlog_warn("%s: invalid address family: %u", __func__, af);
	}
}


static struct stream *zebra_ptm_vpp_make_msg(struct vpp_bfd_peer *bfd_peer,
					     uint8_t bfd_state)
{
	struct stream *msg;

	msg = stream_new(ZEBRA_BFD_DEST_UPD_PACK_SIZE);

	/* Write field: command */
	/* Write field: vrf */
	zclient_create_header(msg, ZEBRA_INTERFACE_BFD_DEST_UPDATE,
			      VRF_DEFAULT);

	/* Write field: interface index */
	if (!bfd_peer->multi_hop) {
		stream_putl(msg, bfd_peer->ifindex);
	} else {
		stream_putl(msg, IFINDEX_INTERNAL);
	}

	/* Write field: family */
	/* Write field: destination address */
	/* Write field: prefix length */
	zebra_ptm_vpp_make_addr(msg, &bfd_peer->peer_addr);

	/* Write field: bfd status */
	switch (bfd_state) {
	case BFD_STATE_API_UP:
		stream_putl(msg, BFD_STATUS_UP);
		zlog_debug("%s: BFD_STATUS_UP", __func__);
		break;

	case BFD_STATE_API_ADMIN_DOWN:
		stream_putl(msg, BFD_STATUS_ADMIN_DOWN);
		zlog_debug("%s: BFD_STATUS_ADMIN_DOWN", __func__);
		break;

	case BFD_STATE_API_DOWN:
	case BFD_STATE_API_INIT:
		stream_putl(msg, BFD_STATUS_DOWN);
		zlog_debug("%s: BFD_STATUS_DOWN", __func__);
		break;

	default:
		stream_putl(msg, BFD_STATUS_UNKNOWN);
		zlog_debug("%s: BFD_STATUS_UNKNOWN", __func__);
		break;
	}

	/* Write field: family. */
	/* Write field: source address. */
	/* Write field: prefix length */
	zebra_ptm_vpp_make_addr(msg, &bfd_peer->local_addr);

	/* Write field: cbit */
	stream_putc(msg, bfd_peer->cbit);

	/* Write packet size. */
	stream_putw_at(msg, 0, stream_get_endp(msg));

	return msg;
}


/*
 * BFD events processing
 */

static struct work_queue *bfd_event_wq;


static void
zebra_ptm_vpp_bfd_event_add(vapi_payload_bfd_udp_session_event *bfd_sess_ev)
{
	vapi_payload_bfd_udp_session_event *bfd_sess_ev_copy;

	bfd_sess_ev_copy = malloc(sizeof(*bfd_sess_ev_copy));
	if (!bfd_sess_ev_copy) {
		return;
	}

	memcpy(bfd_sess_ev_copy, bfd_sess_ev, sizeof(*bfd_sess_ev_copy));

	work_queue_add(bfd_event_wq, bfd_sess_ev_copy);
}


static wq_item_status zebra_ptm_vpp_bfd_event_process(struct work_queue *wq,
						      void *data)
{
	vapi_payload_bfd_udp_session_event *bfd_sess_ev = data;
	struct vpp_bfd_peer *bfd_peer;

	bfd_peer = zebra_ptm_vpp_bfd_get_peer(&bfd_sess_ev->peer_addr,
					      bfd_sess_ev->sw_if_index);

	if (bfd_peer == NULL) {
		zlog_debug("%s: unknown bfd peer", __func__);
		return WQ_SUCCESS;
	}

	struct stream *msg_upd;

	msg_upd = zebra_ptm_vpp_make_msg(bfd_peer, bfd_sess_ev->state);

	zebra_ptm_send_clients_proxy(msg_upd);

	return WQ_SUCCESS;
}


static void zebra_ptm_vpp_bfd_event_clear(struct work_queue *wq, void *data)
{
	free(data);
}


/*
 * Peers registration/deregistration functions
 */

static vapi_payload_bfd_udp_session_details *
zebra_ptm_vpp_bfd_get_sess(vapi_type_address *peer_addr, uint32_t sw_if_index)
{
	vapi_payload_bfd_udp_session_details *bfd_sessions;
	vapi_payload_bfd_udp_session_details *bs;

	bfd_sessions = vmgmt2_bfd_get_sessions_vec();

	tnsr_vec_foreach(bs, bfd_sessions) {
		if (bs->sw_if_index != sw_if_index) {
			continue;
		}
		if (!vmgmt2_ip_address_equal(&bs->peer_addr, peer_addr)) {
			continue;
		}

		return bs;
	}

	return NULL;
}


static void zebra_ptm_vpp_dest_reg(struct vpp_bfd_peer *bfd_peer)
{
	vapi_payload_bfd_udp_session_details *bfd_sess;
	uint32_t index;

	bfd_sess = zebra_ptm_vpp_bfd_get_sess(&bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (bfd_sess) {
		struct stream *msg_upd;

		msg_upd = zebra_ptm_vpp_make_msg(bfd_peer, bfd_sess->state);

		zebra_ptm_send_clients_proxy(msg_upd);
	}

	index = zebra_ptm_vpp_bfd_peer_search(&bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (index == ~0U) {
		tnsr_vec_add1(bfd_peers_to_monitor, *bfd_peer);
	}
}


static void zebra_ptm_vpp_dest_dereg(struct vpp_bfd_peer *bfd_peer)
{
	uint32_t index;

	index = zebra_ptm_vpp_bfd_peer_search(&bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (index == ~0U) {
		zlog_warn("%s: bfd peer not found", __func__);
		return;
	}

	tnsr_vec_del1(bfd_peers_to_monitor, index);
}


void zebra_ptm_vpp_reroute(struct zserv *zs,
			   struct zebra_vrf *zvrf,
			   struct stream *msg,
			   uint32_t command)
{
	int ret = vmgmt2_check_connection();
	if (ret < 0) {
		zlog_err("%s: VPP may be down or API is not responding",
			 __func__);
		return;
	}

	struct vpp_bfd_peer bfd_peer;

	zebra_ptm_vpp_parse_msg(msg, command, &bfd_peer);

	switch (command) {
	case ZEBRA_BFD_DEST_REGISTER:
		zlog_debug("%s: ZEBRA_BFD_DEST_REGISTER", __func__);
		zebra_ptm_vpp_dest_reg(&bfd_peer);
		break;

	case ZEBRA_BFD_DEST_DEREGISTER:
		zlog_debug("%s: ZEBRA_BFD_DEST_[DE]REGISTER", __func__);
		zebra_ptm_vpp_dest_dereg(&bfd_peer);
		break;

	default:
		zlog_warn("%s: unknown bfd command", __func__);
		break;
	}
}


/*
 * Init/finish functions
 */

void zebra_ptm_vpp_init(void)
{
	vmgmt2_bfd_events_register(zebra_ptm_vpp_bfd_event_add, 1);

	bfd_event_wq = work_queue_new(zrouter.master, "bfd_event_wq");
	bfd_event_wq->spec.workfunc = zebra_ptm_vpp_bfd_event_process;
	bfd_event_wq->spec.del_item_data = zebra_ptm_vpp_bfd_event_clear;
	bfd_event_wq->spec.hold = 0;
	bfd_event_wq->spec.max_retries = 0;
}


void zebra_ptm_vpp_finish(void)
{
	vmgmt2_bfd_events_register(zebra_ptm_vpp_bfd_event_add, 0);
	tnsr_vec_free(bfd_peers_to_monitor);
	work_queue_free_and_null(&bfd_event_wq);
}
