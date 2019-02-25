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

#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"


enum dp_req_result kernel_add_lsp(zebra_lsp_t *lsp)
{
	return DP_REQUEST_FAILURE;
}


enum dp_req_result kernel_upd_lsp(zebra_lsp_t *lsp)
{
	return DP_REQUEST_FAILURE;
}


enum dp_req_result kernel_del_lsp(zebra_lsp_t *lsp)
{
	return DP_REQUEST_FAILURE;
}


int mpls_kernel_init(void)
{
	return -1;
};

#endif
