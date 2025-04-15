#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

// IP của client cần chặn (192.168.17.132)
#define BLOCKED_IP "192.168.17.132"
#define BLOCKED_PORT 80 // Apache2 thường chạy trên cổng 80

static struct nf_hook_ops netfilter_hook;

// Hàm callback xử lý gói tin
static unsigned int block_client_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned int src_ip;

    // Kiểm tra gói tin
    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb); // Lấy header IP
    if (!ip_header) return NF_ACCEPT;

    // Kiểm tra giao thức (chỉ xử lý TCP)
    if (ip_header->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcp_header = tcp_hdr(skb); // Lấy header TCP
    if (!tcp_header) return NF_ACCEPT;

    // Chuyển đổi IP nguồn từ dạng chuỗi sang số
    src_ip = in_aton(BLOCKED_IP);

    // Kiểm tra nếu IP nguồn và cổng đích khớp
    if (ip_header->saddr == src_ip && ntohs(tcp_header->dest) == BLOCKED_PORT) {
        printk(KERN_INFO "Blocked IP: %pI4 trying to access Apache on port %d\n",
               &ip_header->saddr, BLOCKED_PORT);
        return NF_DROP; // Chặn gói tin
    }

    return NF_ACCEPT; // Cho phép gói tin khác
}

// Hàm khởi tạo module
static int __init netfilter_block_client_init(void) {
    printk(KERN_INFO "Netfilter Block Client Module Loaded.\n");

    // Cấu hình hook
    netfilter_hook.hook = block_client_func;
    netfilter_hook.hooknum = NF_INET_PRE_ROUTING;
    netfilter_hook.pf = PF_INET;
    netfilter_hook.priority = NF_IP_PRI_FIRST;

    // Đăng ký hook
    nf_register_net_hook(&init_net, &netfilter_hook);

    return 0;
}

// Hàm gỡ bỏ module
static void __exit netfilter_block_client_exit(void) {
    printk(KERN_INFO "Netfilter Block Client Module Unloaded.\n");

    // Hủy đăng ký hook
    nf_unregister_net_hook(&init_net, &netfilter_hook);
}

module_init(netfilter_block_client_init);
module_exit(netfilter_block_client_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cong Son");
MODULE_DESCRIPTION("Block Client Module Example");
