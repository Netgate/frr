/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

#include <zebra.h>

#ifdef HAVE_LIBVPPMGMT

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

#include "zebra/rt_vpp.h"

#include <vppmgmt/vpp_mgmt_api.h>


void vpp_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
}


void vpp_neigh_read(struct zebra_ns *zns)
{
}


int kernel_neigh_update(int add, int ifindex, uint32_t addr,
			char *lla, int llalen)

{
	return -1;
}


int kernel_add_neigh(struct interface *ifp, struct ipaddr *ip,
			    struct ethaddr *mac)
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


void vpp_macfdb_read(struct zebra_ns *zns)
{
}


void vpp_macfdb_read_for_bridge(struct zebra_ns *zns,
				struct interface *ifp,
				struct interface *br_if)
{
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
	u_int8_t multipath;
	u_int8_t notlast;
	struct nexthop *nh;

	multipath = 0;
	is_ipv6 = PREFIX_FAMILY(p) == AF_INET6;
        
	/*
	 * These are the hard-coded default VPP route table names.
	 * FIXME: Need to call vmgmt_route_add_del_table() first.
	 * FIXME: needs to come from re->vrf_id.
	 */
	if (is_ipv6) {
		rt_table_name = "IPv6-VRF:0";
	} else {
		rt_table_name = "IPv4-VRF:0";
	}

	for (nh = re->nexthop; nh; nh = nh->next) {
		u_int8_t *nhaddr;
		struct route_add_del_args rada;
		int ret;

		if (nh->next) {
			multipath = 1;
			notlast = 1;
		} else {
			notlast = 0;
		}

		nhaddr = (u_int8_t *)&nh->gate;
		if ((nh->flags & NEXTHOP_FLAG_RECURSIVE) && nh->resolved) {
			nhaddr = (u_int8_t *)&nh->resolved->gate;
		}
		if (!nhaddr) {
			continue;
		}

		drop = !!(nh->type == NEXTHOP_TYPE_BLACKHOLE
			  && nh->bh_type == BLACKHOLE_NULL);

		unreachable = !!(nh->type == NEXTHOP_TYPE_BLACKHOLE
				 && nh->bh_type == BLACKHOLE_REJECT);

		memset(&rada, 0, sizeof(rada));

		strncpy(rada.route_table_name, rt_table_name,
			sizeof(rada.route_table_name) - 1);

		rada.is_add = is_add;
		rada.is_drop = drop;
		rada.is_unreachable = unreachable;
		rada.is_multipath = multipath;
		rada.is_not_last = notlast;
		rada.is_ipv6 = is_ipv6;
		rada.dest_mask_len = p->prefixlen;
		rada.nh_ifi = ~0;
		memcpy(rada.dest_prefix, &p->u.prefix, is_ipv6 ? 16 : 4);
		memcpy(rada.nh_addr, nhaddr, is_ipv6 ? 16 : 4);

		ret = vmgmt_route_add_del_args(&rada);
		
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}


int kernel_route_rib(struct prefix *p,
		     struct prefix *src_p,
		     struct route_entry *re_old,
		     struct route_entry *re_new)
{
	int ret;

	ret = 0;
	if (re_old) {
		ret = route_multipath(0, p, re_old);
	}
	if (re_new && !ret) {
		ret = route_multipath(1, p, re_new);
	}

	return ret;
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


int vpp_route_read(struct zebra_ns *zns)
{
	return -1;
}

#endif
