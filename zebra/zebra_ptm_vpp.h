/*
 * Copyright 2020, Rubicon Communications, LLC.
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

#define ZEBRA_BFD_DEST_UPD_PACK_SIZE 256

void zebra_ptm_vpp_init(void);
void zebra_ptm_vpp_finish(void);
void zebra_ptm_vpp_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			   struct stream *msg, uint32_t command);

void zebra_ptm_send_clients_proxy(struct stream *msg);
