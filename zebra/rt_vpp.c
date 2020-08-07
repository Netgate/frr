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

#include "log.h"
#include "if.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "rib.h"
#include "nexthop.h"

#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"

#include <vppmgmt/vpp_mgmt_api.h>

#include "zebra/rt_vpp.h"


void vpp_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
}


void vpp_neigh_read(struct zebra_ns *zns)
{
}


int kernel_neigh_update(int add, int ifindex, uint32_t addr,
			char *lla, int llalen, ns_id_t ns_id)

{
	return -1;
}


int kernel_add_neigh(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac, uint8_t flags)
{
	return -1;
}


int kernel_del_neigh(struct interface *ifp, struct ipaddr *ip)
{
	return -1;
}


int kernel_add_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	return -1;
}


int kernel_del_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	return -1;
}


int kernel_interface_set_master(struct interface *master,
				struct interface *slave)
{
	return -1;
}


int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *mroute)
{
	return -1;
}


int kernel_add_mac(struct interface *ifp, vlanid_t vid,
		   struct ethaddr *mac, struct in_addr vtep_ip,
		   u_char sticky)
{
	return -1;
}


int kernel_del_mac(struct interface *ifp, vlanid_t vid,
		   struct ethaddr *mac, struct in_addr vtep_ip,
		   int local)
{
	return -1;
}


static int route_multipath(u_int8_t is_add,
			   struct prefix *p,
			   struct route_entry *re)
{
	const char *rt_table_name;
	u_int8_t is_ipv6;
	u_int8_t drop;
	u_int8_t unreachable;
	u_int8_t prohibit;
	u_int8_t multipath;
	struct nexthop *nh;

	multipath = 0;
	is_ipv6 = PREFIX_FAMILY(p) == AF_INET6;

	/*
	 * These are the hard-coded default VPP route table names.
	 * FIXME: Need to call vmgmt_route_add_del_table() first.
	 * FIXME: needs to come from re->vrf_id.
	 */
	if (is_ipv6) {
		rt_table_name = ROUTE_DEFAULT_IPV6_NAME;
	} else {
		rt_table_name = ROUTE_DEFAULT_IPV4_NAME;
	}

	for (ALL_NEXTHOPS(re->ng, nh)) {
		u_int8_t *nhaddr;
		struct route_add_del_args rada;
		int ret;

		/* we are always modifying the existing set of paths, not
		 * replacing them
		 */
		multipath = 1;

		if (nh->flags & NEXTHOP_FLAG_RECURSIVE) {
			continue;
		}

		if (is_add && !NEXTHOP_IS_ACTIVE(nh->flags)) {
			continue;
		}

		if (!is_add && !CHECK_FLAG(nh->flags, NEXTHOP_FLAG_FIB)) {
			continue;
		}

		nhaddr = (u_int8_t *)&nh->gate;

		drop = !!(nh->type == NEXTHOP_TYPE_BLACKHOLE
			  && nh->bh_type == BLACKHOLE_NULL);

		unreachable = !!(nh->type == NEXTHOP_TYPE_BLACKHOLE
				 && nh->bh_type == BLACKHOLE_REJECT);

		prohibit = !!(nh->type == NEXTHOP_TYPE_BLACKHOLE
				 && nh->bh_type == BLACKHOLE_ADMINPROHIB);

		memset(&rada, 0, sizeof(rada));

		strncpy(rada.route_table_name, rt_table_name,
			sizeof(rada.route_table_name) - 1);

		/*
		 * FRR sets priority of routes that are added to the kernel
		 * to 20. So kernel (static) routes will take precedence by
		 * default.
		 */
		rada.nh_preference = 20;

		rada.is_add = is_add;
		rada.is_drop = drop;
		rada.is_unreachable = unreachable;
		rada.is_prohibit = prohibit;
		rada.is_multipath = multipath;
		rada.is_ipv6 = is_ipv6;
		rada.dest_mask_len = p->prefixlen;
		rada.nh_ifi = vpp_map_ifindex_to_swif(nh->ifindex);
		memcpy(rada.dest_prefix, &p->u.val, is_ipv6 ? 16 : 4);
		memcpy(rada.nh_addr, nhaddr, is_ipv6 ? 16 : 4);

		ret = vmgmt_route_add_del_args(&rada);
#ifdef DEBUG
		printf("%s: route_add_del ret:%d\n", __func__, ret);
#endif

		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}

#define RIB_SYSTEM_ROUTE(R)	\
	((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

enum dp_req_result kernel_route_rib(struct route_node *rn,
				    const struct prefix *p,
				    const struct prefix *src_p,
				    struct route_entry *re_old,
				    struct route_entry *re_new)
{
	int ret = 0;
	enum dp_req_result pass_fail;

	/*
	 * If there is an old route being replaced, delete its paths if it
	 * is not a kernel or connected route
	 */
	if (re_old && !RIB_SYSTEM_ROUTE(re_old)) {
		ret = route_multipath(0, p, re_old);
		pass_fail = (!ret) ? DP_DELETE_SUCCESS : DP_DELETE_FAILURE;
	}
	if (re_new) {
		ret = route_multipath(1, p, re_new);
		pass_fail = (!ret) ? DP_INSTALL_SUCCESS : DP_INSTALL_FAILURE;
	}

        kernel_route_rib_pass_fail(rn, p,
				   (re_new) ? re_new : re_old,
				   pass_fail);

	if (ret < 0) {
		return DP_REQUEST_FAILURE;
	}

	return DP_REQUEST_SUCCESS;
}


int kernel_address_add_ipv4(struct interface *ifp, struct connected *ifc)
{
	return vmgmt_intf_add_del_address(ifp->ifindex,
					  1 /* add */,
					  0 /* ipv6 */,
					  0 /* delete all */,
					  ifc->address->prefixlen,
					  &ifc->address->u.prefix);
}


int kernel_address_delete_ipv4(struct interface *ifp, struct connected *ifc)
{
	return vmgmt_intf_add_del_address(ifp->ifindex,
					  0 /* delete */,
					  0 /* ipv6 */,
					  0 /* delete all */,
					  ifc->address->prefixlen,
					  &ifc->address->u.prefix);
}

#endif
