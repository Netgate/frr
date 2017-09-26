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
#include "privs.h"

#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"

#include "zebra/rt_vpp.h"


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


int kernel_route_rib(struct prefix *p, struct prefix *src_p,
		     struct route_entry *old, struct route_entry *new)
{
	return 0;
}


int kernel_address_add_ipv4(struct interface *ifp, struct connected *ifc)
{
	return -1;
}


int kernel_address_delete_ipv4(struct interface *ifp, struct connected *ifc)
{
	return -1;
}


int vpp_route_read(struct zebra_ns *zns)
{
	return -1;
}

#endif
