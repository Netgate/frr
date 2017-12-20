/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

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

