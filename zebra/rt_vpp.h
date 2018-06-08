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

#define ROUTE_DEFAULT_IPV4_NAME		"ipv4-VRF:0"
#define ROUTE_DEFAULT_IPV6_NAME		"ipv6-VRF:0"


u32 vpp_map_ifindex_to_swif(u_int32_t ifindex);
u_int32_t vpp_map_swif_to_ifindex(u32 ifi);
int interface_lookup_vpp(struct zebra_ns *zns);
void vpp_route_read(struct zebra_ns *zns);
void vpp_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if);
void vpp_neigh_read(struct zebra_ns *zns);
void vpp_macfdb_read(struct zebra_ns *zns);
void vpp_macfdb_read_for_bridge(struct zebra_ns *zns,
				struct interface *ifp,
				struct interface *br_if);
void vpp_link_change(sw_interface_event_t *event);
