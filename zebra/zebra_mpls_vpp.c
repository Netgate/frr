/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

#include <zebra.h>

#ifdef HAVE_LIBVPPMGMT

#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"


int kernel_add_lsp(zebra_lsp_t *lsp)
{
	return 0;
}


int kernel_upd_lsp(zebra_lsp_t *lsp)
{
	return 0;
}


int kernel_del_lsp(zebra_lsp_t *lsp)
{
	return 0;
}


int mpls_kernel_init(void)
{
	return -1;
};

#endif
