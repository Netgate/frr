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

#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ptm_vpp.h"

#include <tnsrinfra/types.h>
#include <tnsrinfra/vec.h>

#include <vppmgmt/vpp_mgmt_api.h>
#include <vnet/bfd/bfd_protocol.h>


extern struct zebra_privs_t zserv_privs;


/*
 * Peers storage functions
 */

struct vpp_bfd_peer {
	uint8_t peer_addr_family;
	uint8_t peer_addr[IPV6_MAX_BYTELEN];
	uint8_t local_addr_family;
	uint8_t local_addr[IPV6_MAX_BYTELEN];
	uint32_t sw_if_index;
	uint32_t ifindex;
	uint8_t multi_hop;
	uint8_t cbit;
};

static struct vpp_bfd_peer *bfd_peers_to_monitor;


static uint32_t zebra_ptm_vpp_bfd_peer_search(uint8_t *peer_addr,
					      uint32_t sw_if_index)
{
	uint32_t index;
	struct vpp_bfd_peer *bp;

	tnsr_vec_foreach_index(index, bfd_peers_to_monitor) {
		bp = tnsr_vec_elt_at_index(bfd_peers_to_monitor, index);

		if (memcmp(bp->peer_addr, peer_addr, IPV6_MAX_BYTELEN) != 0) {
			continue;
		}

		if (bp->sw_if_index != sw_if_index) {
			continue;
		}

		return index;
	}

	return ~0U;
}


static struct vpp_bfd_peer *zebra_ptm_vpp_bfd_get_peer(uint8_t *peer_addr,
						       uint32_t sw_if_index)
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

static void zebra_ptm_vpp_parse_addr(struct stream *msg, uint8_t *family,
				     uint8_t *addr)
{
	uint8_t addr_len;

	STREAM_GETW(msg, *family);

	if (*family == AF_INET) {
		addr_len = IPV4_MAX_BYTELEN;
	} else {
		addr_len = IPV6_MAX_BYTELEN;
	}

	STREAM_GET(addr, msg, addr_len);

stream_failure:
	return;
}


static void zebra_ptm_vpp_parse_msg(struct stream *msg, uint32_t command,
				    struct vpp_bfd_peer *bfd_peer)
{
	uint32_t tmp_num;

	memset(bfd_peer, 0, sizeof(*bfd_peer));

	/* Skip field: pid. */
	STREAM_GETL(msg, tmp_num);

	zebra_ptm_vpp_parse_addr(msg, &bfd_peer->peer_addr_family,
				 bfd_peer->peer_addr);

	if (command != ZEBRA_BFD_DEST_DEREGISTER) {
		/* Skip field: min_rx_timer. */
		STREAM_GETL(msg, tmp_num);

		/* Skip field: min_tx_timer. */
		STREAM_GETL(msg, tmp_num);

		/* Skip field: detect_mult. */
		STREAM_GETC(msg, tmp_num);
	}

	STREAM_GETC(msg, bfd_peer->multi_hop);

	if (bfd_peer->multi_hop) {
		zebra_ptm_vpp_parse_addr(msg, &bfd_peer->local_addr_family,
					 bfd_peer->local_addr);

		/* Skip field: multi_hop_cnt. */
		STREAM_GETC(msg, tmp_num);

		bfd_peer->sw_if_index = vmgmt_intf_get_sw_if_index_by_addr(
			bfd_peer->local_addr,
			(bfd_peer->local_addr_family == AF_INET6));
	} else {
		if (bfd_peer->peer_addr_family == AF_INET6) {
			zebra_ptm_vpp_parse_addr(msg,
						 &bfd_peer->local_addr_family,
						 bfd_peer->local_addr);
		}

		uint8_t if_len;

		STREAM_GETC(msg, if_len);

		if (if_len > 0) {
			char if_name[INTERFACE_NAMSIZ];
			int n;

			STREAM_GET(if_name, msg, if_len);
			if_name[if_len] = '\0';

			n = sscanf(if_name, "vpp%u", &bfd_peer->sw_if_index);
			if (n < 1) {
				bfd_peer->sw_if_index = ~0;
				zlog_warn("%s: cannot parse sw_if_index",
					  __func__);
			}

			struct interface *ifp;

			ifp = if_get_by_name(if_name, VRF_DEFAULT);
			bfd_peer->ifindex = ifp->ifindex;
		} else {
			zlog_err("%s: if_name is not provided, "
				 "cannot determine sw_if_index", __func__);
			bfd_peer->sw_if_index = ~0;
			bfd_peer->ifindex = IFINDEX_INTERNAL;
		}
	}

	STREAM_GETC(msg, bfd_peer->cbit);

stream_failure:
	return;
}


/*
 * Messages construction functions
 */

static void zebra_ptm_vpp_make_addr(struct stream *msg, uint8_t family,
				    uint8_t *addr)
{
	stream_putc(msg, family);

	if (family == AF_INET) {
		stream_put(msg, addr, IPV4_MAX_BYTELEN);
		stream_putc(msg, 32);
	} else {
		stream_put(msg, addr, IPV6_MAX_BYTELEN);
		stream_putc(msg, 128);
	}
}


static struct stream *zebra_ptm_vpp_make_msg(struct vpp_bfd_peer *bfd_peer,
					     uint8_t bfd_state)
{
	struct stream *msg;

	msg = stream_new(ZEBRA_BFD_DEST_UPD_PACK_SIZE);

	zclient_create_header(msg, ZEBRA_INTERFACE_BFD_DEST_UPDATE,
			      VRF_DEFAULT);

	stream_putl(msg, bfd_peer->ifindex);

	zebra_ptm_vpp_make_addr(msg, bfd_peer->peer_addr_family,
				bfd_peer->peer_addr);

	switch (bfd_state) {
	case BFD_STATE_up:
		stream_putl(msg, BFD_STATUS_UP);
		zlog_debug("%s: BFD_STATUS_UP", __func__);
		break;

	case BFD_STATE_admin_down:
		stream_putl(msg, BFD_STATUS_ADMIN_DOWN);
		zlog_debug("%s: BFD_STATUS_ADMIN_DOWN", __func__);
		break;

	case BFD_STATE_down:
	case BFD_STATE_init:
		stream_putl(msg, BFD_STATUS_DOWN);
		zlog_debug("%s: BFD_STATUS_DOWN", __func__);
		break;

	default:
		stream_putl(msg, BFD_STATUS_UNKNOWN);
		zlog_debug("%s: BFD_STATUS_UNKNOWN", __func__);
		break;
	}

	if (bfd_peer->local_addr_family) {
		zebra_ptm_vpp_make_addr(msg, bfd_peer->local_addr_family,
					bfd_peer->local_addr);
	} else {
		/* No local address. Use peer address family and zeroes. */
		zebra_ptm_vpp_make_addr(msg, bfd_peer->peer_addr_family,
					bfd_peer->local_addr);
	}

	stream_putc(msg, bfd_peer->cbit);

	stream_putw_at(msg, 0, stream_get_endp(msg));

	return msg;
}


/*
 * BFD events processing
 */

static void zebra_ptm_vpp_bfd_event_process(struct bfd_session *bfd_sess)
{
	struct vpp_bfd_peer *bfd_peer;

	bfd_peer = zebra_ptm_vpp_bfd_get_peer(bfd_sess->peer_addr,
					      bfd_sess->sw_if_index);

	if (bfd_peer == NULL) {
		zlog_debug("%s: unknown bfd peer", __func__);
		return;
	}

	struct stream *msg_upd;

	msg_upd = zebra_ptm_vpp_make_msg(bfd_peer, bfd_sess->state);

	zebra_ptm_send_clients_proxy(msg_upd);
}


/*
 * Peers registration/deregistration functions
 */

static struct bfd_session *zebra_ptm_vpp_bfd_get_sess(uint8_t *peer_addr,
						      uint32_t sw_if_index)
{
	struct bfd_session *bfd_sessions;
	struct bfd_session *bs;

	bfd_sessions = vmgmt_bfd_get_sessions();

	tnsr_vec_foreach(bs, bfd_sessions) {
		if (memcmp(bs->peer_addr, peer_addr, IPV6_MAX_BYTELEN) != 0) {
			continue;
		}

		if (bs->sw_if_index != sw_if_index) {
			continue;
		}

		return bs;
	}

	return NULL;
}


static void zebra_ptm_vpp_dest_reg(struct vpp_bfd_peer *bfd_peer)
{
	struct bfd_session *bfd_sess;
	uint32_t index;

	bfd_sess = zebra_ptm_vpp_bfd_get_sess(bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (bfd_sess) {
		struct stream *msg_upd;

		msg_upd = zebra_ptm_vpp_make_msg(bfd_peer, bfd_sess->state);

		zebra_ptm_send_clients_proxy(msg_upd);
	}

	index = zebra_ptm_vpp_bfd_peer_search(bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (index == ~0U) {
		tnsr_vec_add1(bfd_peers_to_monitor, *bfd_peer);
	}
}


static void zebra_ptm_vpp_dest_dereg(struct vpp_bfd_peer *bfd_peer)
{
	uint32_t index;

	index = zebra_ptm_vpp_bfd_peer_search(bfd_peer->peer_addr,
					      bfd_peer->sw_if_index);

	if (index == ~0U) {
		zlog_warn("%s: bfd peer not found", __func__);
		return;
	}

	tnsr_vec_del1(bfd_peers_to_monitor, index);
}


void zebra_ptm_vpp_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			   struct stream *msg, uint32_t command)
{
	int ret;

	ret = vmgmt_check_connection();
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
	vmgmt_bfd_events_register(zebra_ptm_vpp_bfd_event_process, 1);
}


void zebra_ptm_vpp_finish(void)
{
	vmgmt_bfd_events_register(zebra_ptm_vpp_bfd_event_process, 0);
	tnsr_vec_free(bfd_peers_to_monitor);
}
