/*
 * mod_main.c - module entry/exit and tunables.
 */
#include "fw.h"

unsigned int fw_tcp_timeout = 300;
unsigned int fw_tcp_close_timeout = 10;
unsigned int fw_udp_timeout = 60;
unsigned int fw_icmp_timeout = 30;
unsigned int fw_max_conns = 16384;
unsigned int fw_stage_timeout = 30;
unsigned int fw_event_rate = 500;
unsigned int fw_initial_action = 1;
unsigned int fw_debug_fail_flow_alloc;
unsigned int fw_debug_fail_stage_alloc;

module_param_named(tcp_timeout, fw_tcp_timeout, uint, 0644);
MODULE_PARM_DESC(tcp_timeout, "idle timeout of a TCP flow in seconds (default 300)");
module_param_named(tcp_close_timeout, fw_tcp_close_timeout, uint, 0644);
MODULE_PARM_DESC(tcp_close_timeout, "timeout after FIN/RST in seconds (default 10)");
module_param_named(udp_timeout, fw_udp_timeout, uint, 0644);
MODULE_PARM_DESC(udp_timeout, "idle timeout of a UDP flow in seconds (default 60)");
module_param_named(icmp_timeout, fw_icmp_timeout, uint, 0644);
MODULE_PARM_DESC(icmp_timeout, "idle timeout of an ICMP echo flow in seconds (default 30)");
module_param_named(max_conns, fw_max_conns, uint, 0644);
MODULE_PARM_DESC(max_conns, "flow table limit; new flows beyond it are DROPPED (default 16384)");
module_param_named(stage_timeout, fw_stage_timeout, uint, 0644);
MODULE_PARM_DESC(stage_timeout, "seconds an idle staged candidate is kept (default 30)");
module_param_named(event_rate, fw_event_rate, uint, 0644);
MODULE_PARM_DESC(event_rate, "packet events per second, 0 = unlimited (default 500)");
module_param_named(initial_action, fw_initial_action, uint, 0444);
MODULE_PARM_DESC(initial_action, "default action before the first commit: 1 accept (default), 0 drop");
module_param_named(debug_fail_flow_alloc, fw_debug_fail_flow_alloc, uint, 0644);
MODULE_PARM_DESC(debug_fail_flow_alloc, "TEST ONLY: fail the next N flow allocations");
module_param_named(debug_fail_stage_alloc, fw_debug_fail_stage_alloc, uint, 0644);
MODULE_PARM_DESC(debug_fail_stage_alloc, "TEST ONLY: fail the next N candidate builds");

static void fw_abi_asserts(void)
{
	/* the Python control plane mirrors these sizes (myfw_ops/abi.py) */
	BUILD_BUG_ON(sizeof(struct fw_req_hdr) != 16);
	BUILD_BUG_ON(sizeof(struct fw_page_req) != 16);
	BUILD_BUG_ON(sizeof(struct fw_rsp_hdr) != 144);
	BUILD_BUG_ON(sizeof(struct fw_policy_hdr) != 176);
	BUILD_BUG_ON(sizeof(struct fw_zone_spec) != 152);
	BUILD_BUG_ON(sizeof(struct fw_rule_spec) != 96);
	BUILD_BUG_ON(sizeof(struct fw_nat_spec) != 112);
	BUILD_BUG_ON(sizeof(struct fw_stage_begin) != 40);
	BUILD_BUG_ON(sizeof(struct fw_commit_result) != 96);
	BUILD_BUG_ON(sizeof(struct fw_event) != 112);
	BUILD_BUG_ON(FW_R__COUNT > FW_R_SLOTS);
}

static int __init fw_init(void)
{
	struct fw_snap *s;
	int ret;

	fw_abi_asserts();
	ret = fw_stats_init();
	if (ret)
		return ret;
	s = fw_snap_initial();
	if (!s) {
		ret = -ENOMEM;
		goto err_stats;
	}
	RCU_INIT_POINTER(fw_active, s);
	fw_conn_init();
	ret = fw_netlink_init();
	if (ret) {
		pr_err(FW_TAG "cannot create netlink socket %d (protocol in use?)\n", NETLINK_MYFW);
		goto err_conn;
	}
	ret = fw_stage_init();
	if (ret)
		goto err_nl;
	ret = fw_hooks_init();
	if (ret) {
		pr_err(FW_TAG "cannot register netfilter hooks: %d\n", ret);
		goto err_stage;
	}
	pr_info(FW_TAG "loaded, UAPI %u, generation 1, default %s, max_conns %u\n",
		FW_UAPI_VERSION, fw_initial_action ? "ACCEPT" : "DROP", fw_max_conns);
	return 0;

err_stage:
	fw_stage_exit();
err_nl:
	fw_netlink_exit();
err_conn:
	fw_conn_exit();
	fw_snap_free(rcu_dereference_protected(fw_active, 1));
err_stats:
	fw_stats_exit();
	return ret;
}

static void __exit fw_exit(void)
{
	fw_hooks_exit();        /* no packet can enter our code after this returns */
	fw_netlink_exit();      /* no new requests */
	fw_stage_exit();
	fw_conn_exit();
	synchronize_rcu();
	fw_snap_free(rcu_dereference_protected(fw_active, 1));
	fw_stats_exit();
	pr_info(FW_TAG "unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("RicheyJang, jujuegg, adamboy447");
MODULE_DESCRIPTION("Netfilter stateful firewall with transactional policy snapshots, SNAT/DNAT");
