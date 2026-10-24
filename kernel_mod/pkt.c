/*
 * pkt.c - packet parsing and header rewriting.
 *
 * Transport headers are read with skb_header_pointer(), so non-linear skbs
 * (GSO, paged data) are handled. NAT rewrites update checksums incrementally
 * with the kernel's inet_proto_csum_replace*() helpers, which also cover
 * CHECKSUM_PARTIAL (offloaded) packets.
 */
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/checksum.h>
#include "fw.h"

static bool is_later_fragment(const struct iphdr *iph)
{
	return (ntohs(iph->frag_off) & IP_OFFSET) != 0;
}

int fw_pkt_tuple(const struct sk_buff *skb, struct fw_tuple *t, u8 *flags)
{
	const struct iphdr *iph = ip_hdr(skb);
	unsigned int off = iph->ihl * 4;

	t->saddr = ntohl(iph->saddr);
	t->daddr = ntohl(iph->daddr);
	t->proto = iph->protocol;
	t->sport = t->dport = 0;
	*flags = 0;

	if (is_later_fragment(iph))     /* no transport header in this fragment */
		return 0;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _th;
		const struct tcphdr *th = skb_header_pointer(skb, off, sizeof(_th), &_th);

		if (!th)
			return -EINVAL;
		t->sport = ntohs(th->source);
		t->dport = ntohs(th->dest);
		if (th->fin || th->rst)
			*flags |= FW_TCP_FIN_RST;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr _uh;
		const struct udphdr *uh = skb_header_pointer(skb, off, sizeof(_uh), &_uh);

		if (!uh)
			return -EINVAL;
		t->sport = ntohs(uh->source);
		t->dport = ntohs(uh->dest);
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr _ih;
		const struct icmphdr *ih = skb_header_pointer(skb, off, sizeof(_ih), &_ih);

		if (!ih)
			return -EINVAL;
		/* echo request/reply share an id: use it so each ping is its own flow */
		if (ih->type == ICMP_ECHO || ih->type == ICMP_ECHOREPLY)
			t->sport = t->dport = ntohs(ih->un.echo.id);
		break;
	}
	}
	return 0;
}

u32 fw_pkt_payload_len(const struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);

	return ntohs(iph->tot_len) - iph->ihl * 4;
}

bool fw_ip_match(u32 ip, u32 net, u32 mask)
{
	return (ip & mask) == (net & mask);
}

/*
 * Rewrite the source (src=true) or destination address and port of a packet.
 * Ports are only rewritten for TCP/UDP. Returns 0 on success.
 */
int fw_pkt_mangle(struct sk_buff *skb, bool src, u32 new_addr, u16 new_port)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned int ihl = iph->ihl * 4;
	unsigned int l4len = 0;
	__be32 old_ip, nip = htonl(new_addr);
	__be16 nport = htons(new_port);
	bool later_frag = is_later_fragment(iph);

	if (!later_frag) {
		if (iph->protocol == IPPROTO_TCP)
			l4len = sizeof(struct tcphdr);
		else if (iph->protocol == IPPROTO_UDP)
			l4len = sizeof(struct udphdr);
	}
	if (skb_ensure_writable(skb, ihl + l4len))
		return -ENOMEM;
	iph = ip_hdr(skb);              /* may have moved */
	old_ip = src ? iph->saddr : iph->daddr;

	if (l4len && iph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = (struct tcphdr *)((u8 *)iph + ihl);
		__be16 *port = src ? &th->source : &th->dest;

		inet_proto_csum_replace4(&th->check, skb, old_ip, nip, true);
		inet_proto_csum_replace2(&th->check, skb, *port, nport, false);
		*port = nport;
	} else if (l4len && iph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = (struct udphdr *)((u8 *)iph + ihl);
		__be16 *port = src ? &uh->source : &uh->dest;

		/* a zero UDP checksum means "no checksum": leave it that way */
		if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
			inet_proto_csum_replace4(&uh->check, skb, old_ip, nip, true);
			inet_proto_csum_replace2(&uh->check, skb, *port, nport, false);
			if (!uh->check)
				uh->check = CSUM_MANGLED_0;
		}
		*port = nport;
	}

	csum_replace4(&iph->check, old_ip, nip);
	if (src)
		iph->saddr = nip;
	else
		iph->daddr = nip;
	return 0;
}
