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

#include <vppmgmt/vpp_mgmt_api.h>

#include "zebra/rt_vpp.h"


unsigned int debug;		/* FIXME -- remove form libvppmgmt */


void kernel_init(struct zebra_ns *zns)
{
	int ret;

	ret = vmgmt_init((char *) "route_daemon", 1);
	if (ret < 0) {
		zlog_err("vmgmt_init failed with status %d", ret);
	} else {
		zlog_info("vmgmt_init success");
	}
	vmgmt_intf_event_register(vpp_link_change);
}


void kernel_terminate(struct zebra_ns *zns)
{
	vmgmt_disconnect();
	zlog_info("vmgmt_disconnect success");
}

#endif
