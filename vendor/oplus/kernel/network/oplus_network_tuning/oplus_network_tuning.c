#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/dst.h>
#include <linux/file.h>
#include <net/tcp_states.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <net/inet_connection_sock.h>
#include <linux/spinlock.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

enum tuning_msg_type_et
{
  	OPLUS_TUNING_MSG_UNSPEC,
  	OPLUS_TUNING_MSG_TCPSYN_ENABLE,
  	OPLUS_TUNING_MSG_TCP_CONTROL_ENABLE,
  	__OPLUS_TUNING_MSG_MAX,
};

#define OPLUS_NETWORK_TUNING_FAMILY_NAME "kernel_tuning"
#define OPLUS_NETWORK_TUNING_FAMILY_VERSION	1
#define OPLUS_NETWORK_TUNING_MSG_MAX (__OPLUS_TUNING_MSG_MAX - 1)
#define NLA_DATA(na) ((char *)((char*)(na) + NLA_HDRLEN))

#define OPLUS_FALSE 0
#define OPLUS_TRUE 1
#define ENABLE_DEBUG 0

static u32 s_oplus_network_tuning_user_pid = 0;
static int s_oplus_tuning_tcpsyn_enable_flag = 0;
static u32 s_oplus_tcp_congest_control_enable = 0;

enum network_tuning_cmd_type_et
{
	OPLUS_NETWORK_TUNING_CMD_UNSPEC,
	OPLUS_NETWORK_TUNING_CMD_CTRL,
	__OPLUS_NETWORK_TUNING_CMD_MAX,
};

static int oplus_network_tuning_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info);

void oplus_tuning_tcpsyn_enable(struct nlattr *nla) {
	u32 *data = (u32 *) NLA_DATA(nla);
	s_oplus_tuning_tcpsyn_enable_flag = data[0];
	printk("oplus_tuning_tcpsyn_enable_flag = %u", s_oplus_tuning_tcpsyn_enable_flag);
}

void oplus_tcp_congest_control_enable(struct nlattr *nla)
{
	s_oplus_tcp_congest_control_enable = OPLUS_TRUE;
	return;
}

static const struct genl_ops oplus_network_tuning_genl_ops[] =
{
	{
		.cmd = OPLUS_NETWORK_TUNING_CMD_CTRL,
		.flags = 0,
		.doit = oplus_network_tuning_netlink_rcv_msg,
		.dumpit = NULL,
	},
};

static struct genl_family oplus_network_tuning_genl_family =
{
	.id = 0,
	.hdrsize = 0,
	.name = OPLUS_NETWORK_TUNING_FAMILY_NAME,
	.version = OPLUS_NETWORK_TUNING_FAMILY_VERSION,
	.maxattr = OPLUS_NETWORK_TUNING_MSG_MAX,
	.ops = oplus_network_tuning_genl_ops,
	.n_ops = ARRAY_SIZE(oplus_network_tuning_genl_ops),
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	.resv_start_op = OPLUS_NETWORK_TUNING_CMD_CTRL + 1,
#endif
};

static inline int genl_msg_prepare_usr_msg(u8 cmd, size_t size, pid_t pid, struct sk_buff **skbp)
{
	struct sk_buff *skb;
	/* create a new netlink msg */
	skb = genlmsg_new(size, GFP_ATOMIC);
	if (skb == NULL) {
		return -ENOMEM;
	}

	/* Add a new netlink message to an skb */
	genlmsg_put(skb, pid, 0, &oplus_network_tuning_genl_family, 0, cmd);
	*skbp = skb;
	return 0;
}

static inline int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data, int len)
{
	/* add a netlink attribute to a socket buffer */
	return nla_put(skb, type, len, data);
}

static int oplus_network_tuning_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr *nla;

	nlhdr = nlmsg_hdr(skb);
	genlhdr = nlmsg_data(nlhdr);
	nla = genlmsg_data(genlhdr);

	s_oplus_network_tuning_user_pid = nlhdr->nlmsg_pid;
	if (ENABLE_DEBUG) {
		printk("set s_oplus_network_tuning_user_pid=%u.\n", s_oplus_network_tuning_user_pid);
	}

	/* to do: may need to some head check here*/
	if (ENABLE_DEBUG) {
		printk("oplus_network_tuning_netlink_rcv_msg type=%u.\n", nla->nla_type);
	}
	switch (nla->nla_type) {
	case OPLUS_TUNING_MSG_TCPSYN_ENABLE:
		oplus_tuning_tcpsyn_enable(nla);
		break;
	case OPLUS_TUNING_MSG_TCP_CONTROL_ENABLE:
		oplus_tcp_congest_control_enable(nla);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

/* send to user space */
int oplus_network_tuning_send_netlink_msg(int msg_type, char *payload, int payload_len)
{
	int ret = 0;
	void * head;
	struct sk_buff *skbuff;
	size_t size;

	if (!s_oplus_network_tuning_user_pid) {
		printk("oplus_network_tuning_send_netlink_msg, s_oplus_network_tuning_user_pid=0\n");
		return -1;
	}

	/* allocate new buffer cache */
	size = nla_total_size(payload_len);
	ret = genl_msg_prepare_usr_msg(OPLUS_NETWORK_TUNING_CMD_CTRL, size, s_oplus_network_tuning_user_pid, &skbuff);
	if (ret) {
		return ret;
	}

	ret = genl_msg_mk_usr_msg(skbuff, msg_type, payload, payload_len);
	if (ret) {
		kfree_skb(skbuff);
		return ret;
	}

	head = genlmsg_data(nlmsg_data(nlmsg_hdr(skbuff)));
	genlmsg_end(skbuff, head);

	/* send data */
	ret = genlmsg_unicast(&init_net, skbuff, s_oplus_network_tuning_user_pid);
	if(ret < 0) {
		printk("oplus_tcpsyn_send_netlink_msg error, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

static int oplus_network_tuning_netlink_init(void)
{
	int ret;
	ret = genl_register_family(&oplus_network_tuning_genl_family);
	if (ret) {
		printk("genl_register_family:%s failed,ret = %d\n", OPLUS_NETWORK_TUNING_FAMILY_NAME, ret);
		return ret;
	} else {
		printk("genl_register_family complete, id = %d!\n", oplus_network_tuning_genl_family.id);
	}

    return 0;
}

static void oplus_network_tuning_netlink_exit(void)
{
	genl_unregister_family(&oplus_network_tuning_genl_family);
}


static int __init oplus_kernel_tuning_init(void)
{
	int ret;

	ret = oplus_network_tuning_netlink_init();
	if (ret < 0) {
		printk("init module failed to init netlink, ret =% d\n",  ret);

		return ret;
	}

	return ret;
}

static void __exit oplus_kernel_tuning_fini(void)
{
	oplus_network_tuning_netlink_exit();
}

module_init(oplus_kernel_tuning_init);
module_exit(oplus_kernel_tuning_fini);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("oplus_network_tuning");
