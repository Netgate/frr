/*
 * Copyright 2017-2018, Rubicon Communications, LLC.
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

#ifdef HAVE_LIBVPPMGMT

#include "if.h"
#include "prefix.h"
#include "connected.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/ioctl.h"

#include <tnsrinfra/types.h>
#include <tnsrinfra/mhash.h>
#include <vppmgmt/vpp_mgmt_api.h>

#include "zebra/rt_vpp.h"


extern sw_interface_event_t *vpp_intf_events;
extern struct connected *ifc_add_events;
extern struct connected *ifc_del_events;
extern int vpp_event_fds[2];


/* Interface state may have changed. Cause the interface data to be refreshed
 * if it hasn't been done already in the last INTF_REFRESH_INTERVAL
 * seconds.
 */
#define INTF_REFRESH_INTERVAL 60
static time_t last_intf_update = 0;


static void vpp_intf_mark_dirty(void)
{
	time_t curr_time = time(NULL);

	if (curr_time - last_intf_update > INTF_REFRESH_INTERVAL) {
		last_intf_update = curr_time;
		vmgmt_intf_mark_dirty();
	}
}


u32 vpp_map_ifindex_to_swif(u_int32_t ifindex)
{
	char vpp_name[IF_NAMESIZE] = "";
	int n;
	u32 swif;

	if (ifindex == IFINDEX_INTERNAL) {
		return ~0U;
	}

	if (!if_indextoname(ifindex, vpp_name)) {
		return ~0;
	}

	swif = ~0;
	n = sscanf(vpp_name, "vpp%d", &swif);
	if (n < 1) {
		return ~0;
	}

	return swif;
}


u_int32_t vpp_map_swif_to_ifindex(u32 ifi)
{
#define BUF_SIZE	1000
	FILE *f;
	int n;
	int index;
	char file_name[BUF_SIZE];

	if (ifi == ~0U) {
		return IFINDEX_INTERNAL;
	}

	n = snprintf(file_name, BUF_SIZE, "/sys/class/net/vpp%d/ifindex", ifi);
	if (n >= BUF_SIZE) {
		return IFINDEX_INTERNAL;
	}

	f = fopen(file_name, "r");
	if (!f) {
		return IFINDEX_INTERNAL;
	}

	n = fscanf(f, "%d", &index);
	if (n < 1) {
		fclose(f);
		return IFINDEX_INTERNAL;
	}

	fclose(f);
	return index;
#undef BUF_SIZE
}


/*
 * v4addr is in network byte order
 */
static u_int32_t broadcast_addr_v4(u_int32_t *v4addr, u_int8_t len)
{
	u_int32_t mask;

	if (len > 32) {
		len = 0;
	}

	mask = htonl((1 << (32 - len)) - 1);

	return *v4addr | mask;
}


static void make_link_local_addr_from_mac(u8 *ll_addr, u8 *mac)
{
	ll_addr[0] = 0xfe;
	ll_addr[1] = 0x80;
	ll_addr[2] = 0;
	ll_addr[3] = 0;
	ll_addr[4] = 0;
	ll_addr[5] = 0;
	ll_addr[6] = 0;
	ll_addr[7] = 0;
	ll_addr[8] = mac[0] ^ 0x2;		/* locally admin bit */
	ll_addr[9] = mac[1];
	ll_addr[10] = mac[2];
	ll_addr[11] = 0xff;
	ll_addr[12] = 0xfe;
	ll_addr[13] = mac[3];
	ll_addr[14] = mac[4];
	ll_addr[15] = mac[5];
}


/* VPP returns value in kbps, FRR expects Mbps. Retrieve & convert it */
static uint32_t vpp_intf_link_speed(u32 ifi)
{
	sw_interface_details_t *sw_if= NULL;
	int ret;

	ret = vmgmt_intf_interface_data_get(ifi, NULL, NULL, &sw_if);
	if (ret < 0 || sw_if == NULL) {
		return 0;
	}

	return (sw_if->link_speed / 1000);
}


static int vpp_intf_convert_one_if(u32 ifi)
{
	ip_address_details_t *addr;
	sw_interface_details_t *intf;
	struct interface *ifp;
	u_int64_t flags;
	vrf_id_t vrf_id;
	ip_details_t *ipd_v4;
	ip_details_t *ipd_v6;
	char addrbuf[40];

	if (!ifi) {
		return 0;
	}

	ipd_v4 = ipd_v6 = 0;
	vmgmt_intf_interface_data_get(ifi, &ipd_v4, &ipd_v6, &intf);

	/*
	 * Skip nameless interfaces.
	 */
	if (!intf->interface_name) {
		return 0;
	}

	printf("Interface: %s  VPP Index: %d\n", intf->interface_name, ifi);
	printf("    Admin status: %s\n", intf->admin_up ? "up" : "down");
	printf("    Link status: %s\n", intf->link_up ? "up" : "down");

	if (intf->l2_address_length == 6) {
		printf("    Layer 2 address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		       intf->l2_address[0],
		       intf->l2_address[1],
		       intf->l2_address[2],
		       intf->l2_address[3],
		       intf->l2_address[4],
		       intf->l2_address[5]);
	}

	flags = 0;
	flags |= (intf->admin_up) ? IFF_UP : 0;
	flags |= (intf->link_up) ? IFF_RUNNING : 0;
	flags |= (strncmp((const char *)intf->interface_name, "loop", 4)) ?
		(IFF_BROADCAST | IFF_MULTICAST) : IFF_LOOPBACK;

	/*
	 * FIXME: Zebra VRF in VPP tinkerings.
	 * Perhaps if intf has a valid sub-if, it should be used?
	 */
	vrf_id = VRF_DEFAULT;

	ifp = if_get_by_name((char *)intf->interface_name, vrf_id, 0);
	if_set_index(ifp, vpp_map_swif_to_ifindex(ifi));
	ifp->mtu6 = ifp->mtu = intf->mtu[VMGMT_MTU_L3];
	ifp->metric = 0;
	ifp->flags = flags & 0x0000fffff;
	ifp->ll_type = ZEBRA_LLT_ETHER;
	memcpy(ifp->hw_addr, intf->l2_address, sizeof(intf->l2_address));
	ifp->hw_addr_len = intf->l2_address_length;
	ifp->speed = vpp_intf_link_speed(ifi);

	if_add_update(ifp);

	/*
	 * IPv4 addresses.
	 */
	if (ipd_v4
	    && tnsr_vec_len(ipd_v4->addr) > 0
	    && ipd_v4->present) {
		printf("    IPv4 addresses:\n");
		tnsr_vec_foreach(addr, ipd_v4->addr) {
			u_int32_t bc;

			memset(addrbuf, 0, sizeof(addrbuf));
			inet_ntop(AF_INET, addr->ip, addrbuf, sizeof(addrbuf));
			printf("        %s/%u\n",
			       addrbuf, addr->prefix_length);

			if (addr->prefix_length <= 30) {
				bc = broadcast_addr_v4((u_int32_t *)addr->ip,
							addr->prefix_length);
			} else {
				bc = 0;
			}
			connected_add_ipv4(ifp,
					   0,
					   (struct in_addr *)addr->ip,
					   addr->prefix_length,
					   bc ? (struct in_addr *)&bc : NULL,
					   NULL);
		}
	}

	/*
	 * IPv6 addresses.
	 */
	if (ipd_v6
	    && tnsr_vec_len(ipd_v6->addr) > 0
	    && ipd_v6->present) {
		printf("    IPv6 addresses:\n");
		tnsr_vec_foreach(addr, ipd_v6->addr) {
			memset(addrbuf, 0, sizeof(addrbuf));
			inet_ntop(AF_INET6,
				  addr->ip, addrbuf, sizeof(addrbuf));
			printf("        %s/%u\n",
			       addrbuf, addr->prefix_length);

			connected_add_ipv6(ifp,
					   0,
					   (struct in6_addr *)addr->ip,
					   NULL,
					   addr->prefix_length,
					   NULL);
		}
	}

	/*
	 * Mark all converted IP addresses as if they were zebra configured
	 * in order to be able to remove them from vtysh
	 */
	struct connected *ifc;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);
	}

	u8 ll_addr[16];

	make_link_local_addr_from_mac(ll_addr, ifp->hw_addr);
	connected_add_ipv6(ifp,
			   0,
			   (struct in6_addr *)ll_addr,
			   NULL,
			   128,
			   NULL);
	return 0;
}


/*
 * Convert VPP interfaces to FRR interfaces.
 */
static int vpp_intf_convert_all(struct zebra_ns *zns)
{
	int ret;
	tnsr_mhash_t *mhash_ifi_by_name;
	uword *ifk;
	uword *ifv;

	vmgmt_intf_refresh_all();
	mhash_ifi_by_name = vmgmt_intf_hash_by_name_get();

	/* *INDENT-OFF* */
	tnsr_mhash_foreach(ifk, ifv, mhash_ifi_by_name,
	{
		u32 ifi_v = (int)*ifv;
		(void)ifk;
		ret = vpp_intf_convert_one_if(ifi_v);
		if (ret < 0) {
			return ret;
		}
	});
	/* *INDENT-ON* */

	return 0;
}


void interface_list(struct zebra_ns *zns)
{
	int ret;

	ret = vpp_intf_convert_all(zns);
	if (ret < 0) {
		zlog_err("Unable to fetch VPP interface data\n");
	}
}


int if_set_flags(struct interface *ifp, uint64_t flags)
{
	printf("%s: failed\n", __func__);
	return -1;
}


int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	printf("%s: failed\n", __func__);
	return -1;
}


void if_get_flags(struct interface *ifp)
{
}


int if_set_prefix(struct interface *ifp, struct connected *ifc)
{
	tnsr_vec_add1(ifc_add_events, *ifc);

	if (write(vpp_event_fds[1], "\0", 1) == -1) {
		zlog_err("%s: Unable to write to VPP event fd %d",
			 __func__, vpp_event_fds[1]);
	}

	return 0;
}


int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	tnsr_vec_add1(ifc_del_events, *ifc);

	if (write(vpp_event_fds[1], "\0", 1) == -1) {
		zlog_err("%s: Unable to write to VPP event fd %d",
			 __func__, vpp_event_fds[1]);
	}

	return 0;
}


void if_get_metric(struct interface *ifp)
{
}


void if_get_mtu(struct interface *ifp)
{
}


int if_prefix_add_ipv6(struct interface *ifp, struct connected *ifc)
{
	tnsr_vec_add1(ifc_add_events, *ifc);

	if (write(vpp_event_fds[1], "\0", 1) == -1) {
		zlog_err("%s: Unable to write to VPP event fd %d",
			 __func__, vpp_event_fds[1]);
	}

	return 0;
}


int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
	tnsr_vec_add1(ifc_del_events, *ifc);

	if (write(vpp_event_fds[1], "\0", 1) == -1) {
		zlog_err("%s: Unable to write to VPP event fd %d",
			 __func__, vpp_event_fds[1]);
	}

	return 0;
}


void vpp_link_change(sw_interface_event_t *event)
{
	if (!event) {
		zlog_err("%s: No interface event data", __func__);
	}

	zlog_warn("VPP interface event received");

	/* don't do anything for local0 */
	if (!event->sw_if_index) {
		return;
	}

	tnsr_vec_add1(vpp_intf_events, *event);

	if (write(vpp_event_fds[1], "\0", 1) == -1) {
		zlog_err("%s: Unable to write to VPP event fd %d",
			 __func__, vpp_event_fds[1]);
	}

	/* The interface cache was marked dirty by the event arriving */
	last_intf_update = time(NULL);
}


static void vpp_intf_events_process_subif_link(uint32_t parent_ifi,
					       u_int8_t link_state)
{
	uint32_t *sub_ifis;
	uint32_t *sub_ifi;

	sub_ifis = vmgmt_intf_get_sub_ifis(parent_ifi);

	tnsr_vec_foreach(sub_ifi, sub_ifis) {
		char *if_name;
		struct interface *ifp;

		if_name = vmgmt_intf_get_if_name(*sub_ifi);
		ifp = if_lookup_by_name_all_vrf(if_name);
		if (!ifp) {
			continue;
		}

		if (link_state) {
			if_flags_update(ifp, ifp->flags | IFF_RUNNING);
		} else {
			if_flags_update(ifp, ifp->flags & ~IFF_RUNNING);
		}
	}

	tnsr_vec_free(sub_ifis);
}


void vpp_intf_events_process(sw_interface_event_t *event)
{
	if (event->added) {
		vpp_intf_convert_one_if(event->sw_if_index);
		return;
	}

	struct interface *ifp;

	ifp = if_lookup_by_name_all_vrf((char *)event->interface_name);
	if (!ifp) {
		vpp_intf_convert_one_if(event->sw_if_index);
		return;
	}

	if (event->deleted) {
		if_delete_update(ifp);
		if_delete(ifp);
		return;
	}

	if (event->admin_state || event->link_state) {
		uint64_t flags = ifp->flags;

		if (event->admin_state) {
			flags |= IFF_UP;
		}

		if (event->link_state) {
			flags |= IFF_RUNNING;

			vpp_intf_events_process_subif_link(event->sw_if_index,
							   event->link_state);
		}

		if_flags_update(ifp, flags);
		return;
	}

	sw_interface_details_t *sw_if= NULL;
	int ret;

	ret = vmgmt_intf_interface_data_get(event->sw_if_index,
					    NULL, NULL, &sw_if);
	if (ret < 0 || sw_if == NULL) {
		return;
	}

	if (!sw_if->admin_up) {
		if_flags_update(ifp, ifp->flags & ~IFF_UP);
	}

	if (!sw_if->link_up) {
		if_flags_update(ifp, ifp->flags & ~IFF_RUNNING);

		vpp_intf_events_process_subif_link(event->sw_if_index,
						   sw_if->link_up);
	}
}


void vpp_ifc_events_process(struct connected *ifc, u8 is_del)
{
	if (ifc->address->family == AF_INET) {
		struct prefix_ipv4 *addr_ip4;
		struct in_addr *bc = NULL;

		addr_ip4 = (struct prefix_ipv4 *)ifc->address;

		if (ifc->destination) {
			struct prefix_ipv4 *dst_ip4;

			dst_ip4 = (struct prefix_ipv4 *)ifc->destination;
			bc = &dst_ip4->prefix;
		}

		if (is_del) {
			connected_delete_ipv4(ifc->ifp, ifc->flags,
					      &addr_ip4->prefix,
					      addr_ip4->prefixlen, bc);
		} else {
			connected_add_ipv4(ifc->ifp, ifc->flags,
					   &addr_ip4->prefix,
					   addr_ip4->prefixlen,
					   bc, ifc->label);
		}
	} else {
		struct prefix_ipv6 *addr_ip6;

		addr_ip6 = (struct prefix_ipv6 *)ifc->address;

		if (is_del) {
			connected_delete_ipv6(ifc->ifp, &addr_ip6->prefix,
					      NULL, addr_ip6->prefixlen);
		} else {
			connected_add_ipv6(ifc->ifp, ifc->flags,
					   &addr_ip6->prefix, NULL,
					   addr_ip6->prefixlen, ifc->label);
		}
	}
}


uint32_t kernel_get_speed(struct interface *ifp)
{
	sw_interface_details_t *sw_if = NULL;
	u32 sw_if_index;

	/* Update the interface cache if it hasn't been done in a while */
	vpp_intf_mark_dirty();

	sw_if_index = vpp_map_ifindex_to_swif(ifp->ifindex);

	return vpp_intf_link_speed(sw_if_index);
}
#endif
