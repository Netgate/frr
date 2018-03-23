/*
 * Copyright 2017, Rubicon Communications, LLC.
 */

#include <zebra.h>

#ifdef HAVE_LIBVPPMGMT

#include "if.h"
#include "prefix.h"
#include "connected.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/ioctl.h"

#include <vppinfra/types.h>
#include <vppmgmt/vpp_mgmt_api.h>

#include "zebra/rt_vpp.h"


/*
 * VPP Land		FRR Land		What Is it?
 * --------		--------		----------
 * sw_if_index,ifi	ifindex			common variable name
 *	~0		IFINDEX_INTERNAL == 0	invalid entry
 *	0		1			first valid index
 *
 * sw_if_index as found in a VPP message is in network-byte-order.
 * ifi as found in vmgmt_*() calls is in host-byte-order.
 * So:
 *    ifi <==> ntohl(sw_if_index)
 *    ifindex <==> vpp_map_swif_to_ifindex(ifi)
 */

u32 vpp_map_ifindex_to_swif(u_int32_t ifindex)
{
	if (ifindex == IFINDEX_INTERNAL) {
		return ~0U;
	}
	return ifindex - 1;
}


u_int32_t vpp_map_swif_to_ifindex(u32 ifi)
{
	if (ifi == ~0U) {
		return IFINDEX_INTERNAL;
	}
	return ifi + 1;
}


/*
 * v4addr is in network byte order
 */
static u_int32_t broadcast_addr_v4(u_int32_t *v4addr, u_int8_t len)
{
	u_int32_t mask;

	if (len > 32) {
		len = 0;
	}

	mask = htonl((1 << (32 - len)) - 1);

	return *v4addr | mask;
}


static int vpp_intf_convert_one_if(u32 ifi)
{
	ip_address_details_t *addr;
	sw_interface_details_t *intf;
	struct interface *ifp;
	u_int64_t flags;
	vrf_id_t vrf_id;
	ip_details_t *ipd_v4;
	ip_details_t *ipd_v6;
	char addrbuf[40];

	if (!ifi) {
		return 0;
	}

	ipd_v4 = ipd_v6 = 0;
	vmgmt_intf_interface_data_get(ifi, &ipd_v4, &ipd_v6, &intf);

	/*
	 * Skip nameless interfaces.
	 */
	if (!intf->interface_name) {
		return 0;
	}

	printf("Interface: %s  VPP Index: %d\n", intf->interface_name, ifi);
	printf("    Admin status: %s\n", intf->admin_up ? "up" : "down");
	printf("    Link status: %s\n", intf->link_up ? "up" : "down");

	if (intf->l2_address_length == 6) {
		printf("    Layer 2 address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		       intf->l2_address[0],
		       intf->l2_address[1],
		       intf->l2_address[2],
		       intf->l2_address[3],
		       intf->l2_address[4],
		       intf->l2_address[5]);
	}

	flags = 0;
	flags |= (intf->admin_up) ? IFF_UP : 0;
	flags |= (intf->link_up) ? IFF_RUNNING : 0;
	flags |= (strncmp((const char *)intf->interface_name, "loop", 4)) ?
		0 : IFF_LOOPBACK;

	/*
	 * FIXME: Zebra VRF in VPP tinkerings.
	 * Perhaps if intf has a valid sub-if, it should be used?
	 */
	vrf_id = VRF_DEFAULT;

	ifp = if_get_by_name((char *)intf->interface_name, vrf_id, 0);
	if_set_index(ifp, vpp_map_swif_to_ifindex(ifi));
	ifp->mtu6 = ifp->mtu = intf->link_mtu;
	ifp->metric = 0;
	ifp->flags = flags & 0x0000fffff;
	ifp->ll_type = ZEBRA_LLT_ETHER;
	clib_memcpy(ifp->hw_addr, intf->l2_address, sizeof(intf->l2_address));
	ifp->hw_addr_len = intf->l2_address_length;

	if_add_update(ifp);

	/*
	 * IPv4 addresses.
	 */
	if (ipd_v4
	    && vec_len(ipd_v4->addr) > 0
	    && ipd_v4[ifi].present) {
		printf("    IPv4 addresses:\n");
		vec_foreach(addr, ipd_v4->addr) {
			u_int32_t bc;

			memset(addrbuf, 0, sizeof(addrbuf));
			inet_ntop(AF_INET, addr->ip, addrbuf, sizeof(addrbuf));
			printf("        %s/%u\n",
			       addrbuf, addr->prefix_length);

			bc = broadcast_addr_v4((u_int32_t *)addr->ip,
					       addr->prefix_length);
			connected_add_ipv4(ifp,
					   0,
					   (struct in_addr *)addr->ip,
					   addr->prefix_length,
					   (struct in_addr *)&bc,
					   NULL);
		}
	}

	/*
	 * IPv6 addresses.
	 */
	if (ipd_v6
	    && vec_len(ipd_v6->addr) > 0
	    && ipd_v6[ifi].present) {
		printf("    IPv6 addresses:\n");
		vec_foreach(addr, ipd_v6->addr) {
			memset(addrbuf, 0, sizeof(addrbuf));
			inet_ntop(AF_INET6,
				  addr->ip, addrbuf, sizeof(addrbuf));
			printf("        %s/%u\n",
			       addrbuf, addr->prefix_length);

			connected_add_ipv6(ifp,
					   0,
					   (struct in6_addr *)addr->ip,
					   addr->prefix_length,
					   NULL);
		}
	}

	return 0;
}


/*
 * Convert VPP interfaces to FRR interfaces.
 */
static int vpp_intf_convert_all(struct zebra_ns *zns)
{
	int ret;
	mhash_t *mhash_ifi_by_name;
	uword *ifk;
	uword *ifv;

	vmgmt_intf_refresh_all();
	mhash_ifi_by_name = vmgmt_intf_hash_by_name_get();

	/* *INDENT-OFF* */
	mhash_foreach(ifk, ifv, mhash_ifi_by_name,
	{
		u32 ifi_v = (int)*ifv;
		(void)ifk;
		ret = vpp_intf_convert_one_if(ifi_v);
		if (ret < 0) {
			return ret;
		}
	});
	/* *INDENT-ON* */

	return 0;
}


void interface_list(struct zebra_ns *zns)
{
	int ret;

	ret = vpp_intf_convert_all(zns);
	if (ret < 0) {
		zlog_err("Unable to fetch VPP interface data\n");
	}
}


int if_set_flags(struct interface *ifp, uint64_t flags)
{
	printf("%s: failed\n", __func__);
	return -1;
}


int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	printf("%s: failed\n", __func__);
	return -1;
}


void if_get_flags(struct interface *ifp)
{
}


int if_set_prefix(struct interface *fp, struct connected *ifc)
{
	printf("%s: failed\n", __func__);
	return -1;
}


int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	printf("%s: failed\n", __func__);
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
	printf("%s: failed\n", __func__);
	return -1;
}


int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
	printf("%s: failed\n", __func__);
	return -1;
}

void vpp_link_change(sw_interface_event_t *event)
{
	struct interface *ifp;
	char *if_name;
	u_int64_t flags = 0;

	if (!event) {
		zlog_err("%s: No interface event data", __func__);
	}

	zlog_warn("VPP interface event received");

	/* don't do anything for local0 */
	if (!event->sw_if_index) {
		return;
	}

	if_name = (char *) event->interface_name;
	if (!(ifp = if_get_by_name(if_name, VRF_DEFAULT, 0))) {
		zlog_err("%s: No interface found for %s", __func__, if_name);
		return;
	}

	zlog_info("%s: initial interface flags: %lu", __func__, ifp->flags);

	flags |= (event->admin_state) ? IFF_UP : 0;
	flags |= (event->link_state) ? IFF_RUNNING : 0;
	flags |= (strncmp(if_name, "loop", 4)) ? 0 : IFF_LOOPBACK;

	if_flags_update(ifp, flags & 0x0000fffff);

	zlog_info("%s: updated interface flags: %lu", __func__, ifp->flags);

}
#endif
