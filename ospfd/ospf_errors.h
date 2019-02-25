/*
 * OSPF-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *		Chirag Shah
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __OSPF_ERRORS_H__
#define __OSPF_ERRORS_H__

#include "lib/ferr.h"

enum ospf_log_refs {
	OSPF_ERR_PKT_PROCESS = OSPF_FERR_START,
	OSPF_ERR_ROUTER_LSA_MISMATCH,
	OSPF_ERR_DOMAIN_CORRUPT,
	OSPF_ERR_INIT_FAIL,
	OSPF_ERR_SR_INVALID_DB,
	OSPF_ERR_SR_NODE_CREATE,
	OSPF_ERR_SR_INVALID_LSA_ID,
	OSPF_ERR_SR_INVALID_ALGORITHM,
};

extern void ospf_error_init(void);

#endif
