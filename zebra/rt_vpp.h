/* 
 * Copyright 2017, Rubicon Communications, LLC.
 */

int interface_lookup_vpp(struct zebra_ns *zns);
int vpp_route_read(struct zebra_ns *zns);
void vpp_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if);
void vpp_neigh_read(struct zebra_ns *zns);
void vpp_macfdb_read(struct zebra_ns *zns);
void vpp_macfdb_read_for_bridge(struct zebra_ns *zns,
				struct interface *ifp,
				struct interface *br_if);

