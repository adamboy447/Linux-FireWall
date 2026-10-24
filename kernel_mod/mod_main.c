/*
 * mod_main.c - module entry/exit and tunables.
 */
#include "fw.h"

unsigned int fw_tcp_timeout = 300;
unsigned int fw_tcp_close_timeout = 10;
unsigned int fw_udp_timeout = 60;
unsigned int fw_icmp_timeout = 30;
unsigned int fw_max_conns = 16384;

module_param_named(tcp_timeout, fw_tcp_timeout, uint, 0644);
MODULE_PARM_DESC(tcp_timeout, "idle timeout of a TCP flow in seconds (default 300)");
module_param_named(tcp_close_timeout, fw_tcp_close_timeout, uint, 0644);
MODULE_PARM_DESC(tcp_close_timeout, "timeout after FIN/RST in seconds (default 10)");
module_param_named(udp_timeout, fw_udp_timeout, uint, 0644);
MODULE_PARM_DESC(udp_timeout, "idle timeout of a UDP flow in seconds (default 60)");
module_param_named(icmp_timeout, fw_icmp_timeout, uint, 0644);
MODULE_PARM_DESC(icmp_timeout, "idle timeout of ICMP/other flows in seconds (default 30)");
module_param_named(max_conns, fw_max_conns, uint, 0644);
MODULE_PARM_DESC(max_conns, "size limit of the connection table (default 16384)");

static int __init fw_init(void)
{
	int ret;

	ret = fw_netlink_init();
	if (ret) {
		pr_err(FW_TAG "cannot create netlink socket %d (protocol in use?)\n", NETLINK_MYFW);
		return ret;
	}
	fw_conn_init();
	ret = fw_hooks_init();
	if (ret) {
		pr_err(FW_TAG "cannot register netfilter hooks: %d\n", ret);
		fw_conn_exit();
		fw_netlink_exit();
		return ret;
	}
	pr_info(FW_TAG "loaded (default ACCEPT, tcp %us / udp %us / icmp %us)\n",
		fw_tcp_timeout, fw_udp_timeout, fw_icmp_timeout);
	return 0;
}

static void __exit fw_exit(void)
{
	fw_hooks_exit();        /* no packet can enter our code after this */
	fw_netlink_exit();
	fw_conn_exit();
	fw_rules_flush();
	fw_nat_flush();
	pr_info(FW_TAG "unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("RicheyJang, jujuegg, adamboy447");
MODULE_DESCRIPTION("Netfilter stateful firewall with SNAT/DNAT, controlled over netlink");
