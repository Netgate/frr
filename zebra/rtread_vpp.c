/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

#include <zebra.h>

#ifdef HAVE_LIBVPPMGMT

#include "vty.h"
#include "zebra/zserv.h"
#include "zebra/rt_netlink.h"

#include "zebra/rt_vpp.h"


void route_read(struct zebra_ns *zns)
{
	vpp_route_read(zns);
}


void macfdb_read(struct zebra_ns *zns)
{
	vpp_macfdb_read(zns);
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
