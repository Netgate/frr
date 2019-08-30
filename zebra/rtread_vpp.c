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

#include "vty.h"
#include "zebra/zserv.h"
#include "zebra/rt_netlink.h"
#include "zebra/rt.h"

#include <vppinfra/string.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppmgmt/vpp_mgmt_api.h>

#include "zebra/rt_vpp.h"


static void vpp_rt_add_v6_route(ip6_fib_details_t *v6_route,
				 struct zebra_ns *zns)
{
	ip_fib_path_t *fib_path_vec;
	u32 count;
	struct prefix pref;
	u32 p;
	int vrf_id;
	int table_id;
	struct rib *rib;

	fib_path_vec = v6_route->fib_path_vec;
	count = v6_route->count;

	if (!fib_path_vec || !count) {
		return;
	}

	pref.family = AF_INET6;
	pref.prefixlen = v6_route->address_length;
	memcpy(&pref.u.prefix6, v6_route->address, 16);

	/*
	 * FIXME: real VRF ID mechanism needed...
	 * FIXME: real routing table ID mechanism needed...
	 * vrf_id = something based on zns and a lookup?
	 */
	vrf_id = VRF_DEFAULT;
	table_id = RT_TABLE_MAIN;


	for (p = 0; p < count; ++p) {
		ip_fib_path_t *path;
		u_int8_t *ip6nh;
		u_int32_t ifindex;
		struct nexthop nh;

		path = &fib_path_vec[p];

		ip6nh = path->next_hop;
		if (pref.prefixlen == 128
		    && memcmp(&pref.u.prefix6, ip6nh, 16) == 0) {
			continue;
		}

		ifindex = vpp_map_swif_to_ifindex(path->sw_if_index);

		memset(&nh, 0, sizeof(nh));

		if (path->is_drop || path->is_unreach || path->is_prohibit) {
			if (path->is_drop) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_NULL;
			}
			if (path->is_unreach) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_REJECT;
			}
			if (path->is_prohibit) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_ADMINPROHIB;
			}
		} else {
			if (path->sw_if_index != ~0U && !(*ip6nh)) {
				nh.type = NEXTHOP_TYPE_IFINDEX;
			} else if (path->sw_if_index != ~0U && (*ip6nh)) {
				nh.type = NEXTHOP_TYPE_IPV6_IFINDEX;
			} else {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_UNSPEC;
			}
		}

		nh.ifindex = ifindex;
		if (*ip6nh) {
			memcpy(&nh.gate.ipv6.s6_addr, ip6nh, 16);
		}

		if (count == 1) {
			rib_add(AFI_IP6,
				SAFI_UNICAST,
				vrf_id,
				ZEBRA_ROUTE_KERNEL,
				0,	/* source protocol instance */
				0,	/* ZEBRA_FLAG_* */
				&pref,	/* prefix */
				0,	/* src prefix_ipv6 */
				&nh,	/* nexthop */
				table_id,	/* routing table_id */
				0,	/* metric */
				0,	/* mtu */
				0,	/* distance */
				0	/* tag */
				);
		}
	}
}


static int vpp_is_ipv6_default_route(ip_fib_details_t *v6_route)
{
	u_int8_t ip6_zero[16] = {0};

	if (v6_route->address[0] == 0) {
		if (v6_route->address_length == 0
		    || v6_route->address_length == 128) {
			return (memcmp(ip6_zero, v6_route->address, 16) == 0);
		}
	}

	return 0;
}


static int vpp_is_ipv6_fe80_10(ip_fib_details_t *v6_route)
{
	if (v6_route->address[0] == 0xfe
	    && v6_route->address[1] == 0x80
	    && v6_route->address_length == 10) {
		return 1;
	}

	return 0;
}


static void vpp_rt_add_ipv6(ip6_fib_details_t *v6_routes,
			    struct zebra_ns *zns)
{
	u32 n_routes;
	u32 r;
	ip6_fib_details_t *v6_route;

	if (!v6_routes) {
		return;
	}

	n_routes = vec_len(v6_routes);
	if (!n_routes) {
		return;
	}

	for (r = 0; r < n_routes; ++r) {
		v6_route = vec_elt_at_index(v6_routes, r);
		if (!vpp_is_ipv6_default_route(v6_route)
		    && !vpp_is_ipv6_fe80_10(v6_route)) {
			vpp_rt_add_v6_route(v6_route, zns);
		}
	}
}


static void vpp_rt_add_v4_route(ip_fib_details_t *v4_route,
				struct zebra_ns *zns)
{
	ip_fib_path_t *fib_path_vec;
	u32 count;
	struct prefix pref;
	u32 p;
	int vrf_id;
	int table_id;
	struct rib *rib;

	fib_path_vec = v4_route->fib_path_vec;
	count = v4_route->count;

	if (!fib_path_vec || !count) {
		return;
	}

	pref.family = AF_INET;
	pref.prefixlen = v4_route->address_length;
	memcpy(&pref.u.prefix4, v4_route->address, 4);

	/*
	 * FIXME: real VRF ID mechanism needed...
	 * FIXME: real routing table ID mechanism needed...
	 * vrf_id = something based on zns and a lookup?
	 */
	vrf_id = VRF_DEFAULT;
	table_id = RT_TABLE_MAIN;


	rib = NULL;


	for (p = 0; p < count; ++p) {
		ip_fib_path_t *path;
		u_int32_t *ip4nh;
		int ifindex;
		struct nexthop nh;

		path = &fib_path_vec[p];

		ip4nh = (u_int32_t *)path->next_hop;
		if (pref.prefixlen == 32
		    && *(u_int32_t *)&pref.u.prefix4 == *(u_int32_t *)ip4nh) {
			continue;
		}

		ifindex = vpp_map_swif_to_ifindex(path->sw_if_index);

		memset(&nh, 0, sizeof(nh));

		if (path->is_drop || path->is_unreach || path->is_prohibit) {
			if (path->is_drop) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_NULL;
			}
			if (path->is_unreach) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_REJECT;
			}
			if (path->is_prohibit) {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_ADMINPROHIB;
			}
		} else {
			if (path->sw_if_index != ~0U && !(*ip4nh)) {
				nh.type = NEXTHOP_TYPE_IFINDEX;
				nh.ifindex = ifindex;
			} else if (path->sw_if_index != ~0U && (*ip4nh)) {
				nh.type = NEXTHOP_TYPE_IPV4_IFINDEX;
				nh.ifindex = ifindex;
			} else {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_UNSPEC;
			}
		}
		nh.ifindex = ifindex;
		if (*ip4nh) {
			memcpy(&nh.gate, ip4nh, 4);
		}

		if (count == 1) {
			rib_add(AFI_IP,
				SAFI_UNICAST,
				vrf_id,
				ZEBRA_ROUTE_KERNEL,
				0,	/* source protocol instance */
				0,	/* ZEBRA_FLAG_* */
				&pref,	/* prefix */
				0,	/* prefix_ipv6 */
				&nh,	/* nexthop */
				table_id,	/* routing table_id */
				0,	/* metric */
				0,	/* mtu */
				0,	/* distance */
				0	/* tag */
				);

		} else if (v4_route->count > 1) {
#if 0
			if (rib == NULL) {
				rib = XCALLOC(MTYPE_RIB, sizeof(struct rib));
				rib->type = ZEBRA_ROUTE_KERNEL;
				rib->vrf_id = vrf_id;
				rib->table = route->table_id;
				rib->uptime = time(NULL);
			}
			if (ifindex != ~0U) {
				rib_nexthop_ipv4_ifindex_add(rib,
							     (struct in_addr *)
							     path->next_hop,
							     NULL,
							     ifindex);
			} else {
				rib_nexthop_ipv4_add(rib,
						     (struct in_addr *)
						     path->next_hop,
						     NULL);
			}
#endif
		}
	}

#if 0
	if ((route->count > 1) && rib) {
		if (rib->nexthop_num == 0) {
			XFREE(MTYPE_RIB, rib);
		} else {
			rib_add_multipath(AFI_IP, SAFI_UNICAST, &pref, rib);
		}
	}
#endif
}


/*
 * Return true if the fib_path is flagged as DROP.
 */
static vpp_route_is_drop(ip_fib_path_t *fib_path)
{
	if (!fib_path)
		return 0;

	return fib_path[0].is_drop;
}


/*
 * Determine if the IPv4 route is one of VPP's default routes:
 *
 *    0.0.0.0/0		-> DROP
 *    0.0.0.0/32	-> DROP
 *    224.0.0.0/4	-> DROP
 *    240.0.0.0/4	-> DROP
 *    255.255.255.255/32-> DROP
 *
 * Returns 1 if the route is one of the above default routes.
 */

static int vpp_is_ipv4_default_route(ip_fib_details_t *v4_route)
{
	if (v4_route->address[0] == 0) {
		if (v4_route->address[1] == 0
		    && v4_route->address[2] == 0
		    && v4_route->address[3] == 0
		    && (v4_route->address_length == 0
			|| v4_route->address_length == 32)) {
			return vpp_route_is_drop(v4_route->fib_path_vec);
		}

	} else if (v4_route->address[0] >= 224) {
		return 1;
	}

	return 0;
}


static void vpp_rt_add_ipv4(ip_fib_details_t *v4_routes,
			    struct zebra_ns *zns)
{
	u32 n_routes;
	u32 r;
	ip_fib_details_t *v4_route;

	if (!v4_routes) {
		return;
	}

	n_routes = vec_len(v4_routes);
	if (!n_routes) {
		return;
	}

	for (r = 0; r < n_routes; ++r) {
		v4_route = vec_elt_at_index(v4_routes, r);
		if (!vpp_is_ipv4_default_route(v4_route)) {
			vpp_rt_add_v4_route(v4_route, zns);
		}
	}
}


static void vpp_route_table_add(struct route_table_data *rt_table,
				struct zebra_ns *zns)
{
	u8 is_ipv6;

	if (!rt_table) {
		return;
	}

	is_ipv6 = rt_table->is_ipv6;
	if (is_ipv6) {
		vpp_rt_add_ipv6(rt_table->route_vec.ipv6, zns);
	} else {
		vpp_rt_add_ipv4(rt_table->route_vec.ipv4, zns);
	}
}


void vpp_route_read(struct zebra_ns *zns)
{
	struct route_table_data *rt_table;

        vmgmt_route_mark_dirty();
        vmgmt_route_refresh_all();

	rt_table = vmgmt_route_get_table((char *)ROUTE_DEFAULT_IPV4_NAME);
	vpp_route_table_add(rt_table, zns);

	rt_table = vmgmt_route_get_table((char *)ROUTE_DEFAULT_IPV6_NAME);
	vpp_route_table_add(rt_table, zns);
}


void route_read(struct zebra_ns *zns)
{
	vpp_route_read(zns);
}


void vpp_macfdb_read(struct zebra_ns *zns)
{
}


void macfdb_read(struct zebra_ns *zns)
{
	vpp_macfdb_read(zns);
}


void vpp_macfdb_read_for_bridge(struct zebra_ns *zns,
				struct interface *ifp,
				struct interface *br_if)
{
}


void macfdb_read_for_bridge(struct zebra_ns *zns,
			    struct interface *ifp,
			    struct interface *br_if)
{
	vpp_macfdb_read_for_bridge(zns, ifp, br_if);
}


void neigh_read(struct zebra_ns *zns)
{
	vpp_neigh_read(zns);
}


void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
	vpp_neigh_read_for_vlan(zns, vlan_if);
}

#endif
