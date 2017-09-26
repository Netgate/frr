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


void kernel_init(struct zebra_ns *zns)
{
}


void kernel_terminate(struct zebra_ns *zns)
{
}

#endif
