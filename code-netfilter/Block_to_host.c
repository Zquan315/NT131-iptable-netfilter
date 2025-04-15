#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

// Khai báo các cấu trúc `nf_hook_ops` để đăng ký hook
static struct nf_hook_ops hook1, hook2, hook3;

// Hàm chặn các gói ICMP ping tới địa chỉ IP 10.0.3.8
unsigned int blockICMP(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;       // Header IP
    struct icmphdr *icmph;   // Header ICMP

    char ip[16] = "10.0.3.8"; // Địa chỉ IP cần chặn
    u32 ip_addr;             // Địa chỉ IP dạng nhị phân

    // Kiểm tra gói tin có hợp lệ không
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb); // Truy xuất header IP từ gói tin
    // Chuyển đổi địa chỉ IP từ chuỗi dạng "10.0.3.8" sang nhị phân
    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

    // Kiểm tra giao thức ICMP
    if (iph->protocol == IPPROTO_ICMP)
    {
        icmph = icmp_hdr(skb); // Truy xuất header ICMP từ gói tin
        // Nếu gói tin là ping (ICMP_ECHO) và gửi đến địa chỉ 10.0.3.8, thì chặn
        if (iph->daddr == ip_addr && icmph->type == ICMP_ECHO)
        {
            printk(KERN_WARNING "*** Dropping %pI4 (ICMP) \n", &(iph->daddr));
            return NF_DROP; // Chặn gói tin
        }
    }
    return NF_ACCEPT; // Cho phép gói tin nếu không khớp điều kiện
}

// Hàm chặn các gói TCP Telnet tới cổng 23 của địa chỉ 10.0.3.8
unsigned int blockTelnet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;       // Header IP
    struct tcphdr *tcph;     // Header TCP

    u16 port = 23;           // Cổng Telnet
    char ip[16] = "10.0.3.8"; // Địa chỉ IP cần chặn
    u32 ip_addr;             // Địa chỉ IP dạng nhị phân

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb); // Truy xuất header IP từ gói tin
    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

    // Kiểm tra giao thức TCP
    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb); // Truy xuất header TCP từ gói tin
        // Nếu gói tin đến địa chỉ 10.0.3.8 và cổng đích là 23, thì chặn
        if (iph->daddr == ip_addr && ntohs(tcph->dest) == port)
        {
            printk(KERN_WARNING "*** Dropping %pI4 (TCP), port %d\n", &(iph->daddr), port);
            return NF_DROP; // Chặn gói tin
        }
    }
    return NF_ACCEPT; // Cho phép gói tin nếu không khớp điều kiện
}

// Hàm in thông tin gói tin đi qua các hook
unsigned int printInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    char *hook;
    char *protocol;

    // Xác định hook hiện tại (điểm trên đường đi của gói tin)
    switch (state->hook)
    {
    case NF_INET_LOCAL_IN:
        hook = "LOCAL_IN";
        break;
    case NF_INET_LOCAL_OUT:
        hook = "LOCAL_OUT";
        break;
    case NF_INET_PRE_ROUTING:
        hook = "PRE_ROUTING";
        break;
    case NF_INET_POST_ROUTING:
        hook = "POST_ROUTING";
        break;
    case NF_INET_FORWARD:
        hook = "FORWARD";
        break;
    default:
        hook = "IMPOSSIBLE";
        break;
    }
    printk(KERN_INFO "*** %s\n", hook); // In thông tin hook

    iph = ip_hdr(skb); // Truy xuất header IP từ gói tin
    // Xác định giao thức
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        protocol = "TCP";
        break;
    case IPPROTO_ICMP:
        protocol = "ICMP";
        break;
    default:
        protocol = "OTHER";
        break;
    }
    // In địa chỉ nguồn, đích và giao thức của gói tin
    printk(KERN_INFO "  %pI4    --> %pI4 (%s)\n", &(iph->saddr), &(iph->daddr), protocol);

    return NF_ACCEPT; // Cho phép gói tin đi qua
}

// Hàm khởi tạo module và đăng ký các bộ lọc
int registerFilter(void)
{
    printk(KERN_INFO "Registering filters.\n");

    // Đăng ký hook in thông tin gói tin
    hook1.hook = printInfo;
    hook1.hooknum = NF_INET_LOCAL_OUT; // Hook tại LOCAL_OUT
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST; // Ưu tiên cao nhất
    nf_register_net_hook(&init_net, &hook1);

    // Đăng ký hook chặn gói ICMP
    hook2.hook = blockICMP;
    hook2.hooknum = NF_INET_LOCAL_OUT; // Hook tại LOCAL_OUT
    hook2.pf = PF_INET;
    hook2.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook2);

    // Đăng ký hook chặn gói Telnet
    hook3.hook = blockTelnet;
    hook3.hooknum = NF_INET_LOCAL_OUT; // Hook tại LOCAL_OUT
    hook3.pf = PF_INET;
    hook3.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook3);

    return 0;
}

// Hàm gỡ bỏ module và hủy đăng ký các bộ lọc
void removeFilter(void)
{
    printk(KERN_INFO "The filters are being removed. \n");
    nf_unregister_net_hook(&init_net, &hook1); // Hủy hook in thông tin
    nf_unregister_net_hook(&init_net, &hook2); // Hủy hook chặn ICMP
    nf_unregister_net_hook(&init_net, &hook3); // Hủy hook chặn Telnet
}

// Định nghĩa các macro để chỉ định hàm khởi tạo và hủy bỏ module
module_init(registerFilter);
module_exit(removeFilter);

// Thông tin về giấy phép
MODULE_LICENSE("GPL");