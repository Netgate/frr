/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

#include <zebra.h>

#ifdef HAVE_LIBVPPMGMT

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/ioctl.h"

#include "rt_vpp.h"


int interface_lookup_vpp(struct zebra_ns *zns)
{
	return -1;
}


void interface_list(struct zebra_ns *zns)
{
	interface_lookup_vpp(zns);
}


int if_set_flags(struct interface *ifp, uint64_t flags)
{
	return -1;
}


int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	return -1;
}


void if_get_flags(struct interface *ifp)
{
}


int if_set_prefix(struct interface *fp, struct connected *ifc)
{
	return -1;
}


int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	return -1;
}


void if_get_metric(struct interface *ifp)
{
}


void if_get_mtu(struct interface *ifp)
{
}


int if_prefix_add_ipv6(struct interface *ifp, struct connected *ifc)
{
	return -1;
}


int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
	return -1;
}

#endif
