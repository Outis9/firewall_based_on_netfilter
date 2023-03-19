#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/uaccess.h>
#include "firewall.h"

static struct nf_hook_ops nf_hook_localin;
static struct nf_hook_ops nf_hook_localout;
static struct nf_hook_ops nf_hook_prerouting;
static struct nf_hook_ops nf_hook_forwarding;
static struct nf_hook_ops nf_hook_postrouting;
static struct nf_sockopt_ops nf_hook_sockopt;

ban_status rules, recv;


//callback functions
unsigned int hook_localin(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    printk(KERN_INFO "hook_localin");
    if(!skb)
        return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    int i;


    //block source port
    if(rules.source_port_status != 0){
		switch(iph->protocol){
			case IPPROTO_TCP:
				tcph = tcp_hdr(skb);
				for(i = 0;i <= MAX - 1;i++){
					if(tcph->source == ntohs(rules.ban_source_port_list[i])){
						return NF_DROP;
						break;
					}
				}
			case IPPROTO_UDP:
				udph = udp_hdr(skb);
				for(i = 0;i <= MAX - 1;i++){
					if(udph->source == ntohs(rules.ban_source_port_list[i])){
						return NF_DROP;
						break;
					}
				}
		}
	}

    //block dest port
    if(rules.dest_port_status != 0){
		switch(iph->protocol){
			case IPPROTO_TCP:
				tcph = tcp_hdr(skb);
				for(i = 0;i <= MAX - 1;i++){
					if(tcph->dest == ntohs(rules.ban_dest_port_list[i])){
						return NF_DROP;
						break;
					}
				}
			case IPPROTO_UDP:
				udph = udp_hdr(skb);
				for(i = 0;i <= MAX - 1;i++){
					if(udph->dest == ntohs(rules.ban_dest_port_list[i])){
						return NF_DROP;
						break;
					}
				}
		}
	}

    //block icmp
    if(iph->protocol == IPPROTO_ICMP && rules.icmp_status == 1)
		return NF_DROP;

    //block tcp
	if(iph -> protocol == IPPROTO_TCP && rules.tcp_status == 1)
		return NF_DROP;
	
	//block udp
	if(iph -> protocol == IPPROTO_UDP && rules.udp_status == 1)
		return NF_DROP;

	//more to add!

    return NF_ACCEPT;
}

unsigned int hook_localout(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    printk(KERN_INFO "hook_localout");
    if(!skb)
        return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);
    int i;

    //block dest ip
    if(rules.dest_ip_status != 0){
        for(i = 0;i <= MAX - 1;i++){
            if(rules.ban_dest_ip_list[i] == iph->daddr)
                return NF_DROP;
        }
    }

    //more to add!
    
    return NF_ACCEPT;
}

unsigned int hook_prerouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    printk(KERN_INFO "hook_prerouting!");
    if(!skb)
        return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);
    
    //block source ip
    int i;
    if(rules.source_ip_status != 0){
        for(i = 0;i <= MAX - 1;i++){
            if(rules.ban_source_ip_list[i] == iph->saddr)
                return NF_DROP;
        }
    }

    // more to add!

    return NF_ACCEPT;
}

unsigned int hook_postrouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    printk(KERN_INFO "hook_postrouting!");
    if(!skb)
        return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);

    //block UDP out
    struct udphdr *udph = udp_hdr(skb);
    unsigned short port = ntohs(udph->dest);
    int i;
    if(iph->protocol == IPPROTO_UDP){
        for(i = 0;i <= MAX -1 ;i++){
            if(rules.ban_dest_ip_list[i] == iph->daddr && rules.ban_dest_port_list[i] == udph->dest){
                printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
                return NF_DROP;
            }
        }
    }

    // more to add!

    return NF_ACCEPT;
}

unsigned int hook_forwarding(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    printk(KERN_INFO "hook_forwarding");
    return NF_ACCEPT;
}

// kernal communicate with user
int hook_sockopt_set(struct sock *sk, int optval, void __user *user, unsigned int len){
    int res, i;
    printk(KERN_INFO "hook_sockopt_set!");
    res = copy_from_user(&recv, user, sizeof(recv));

    switch(optval){
        case BANICMP:
            rules.icmp_status = recv.icmp_status;
            break;
        case BANIP:
            rules.source_ip_status = recv.source_ip_status;
            rules.dest_ip_status = recv.dest_ip_status;
            rules.ban_ip = recv.ban_ip;
            for(i = 0;i <= MAX - 1;i++){
                rules.ban_source_ip_list[i] = recv.ban_source_ip_list[i];
                rules.ban_dest_ip_list[i] = recv.ban_dest_ip_list[i];
            }
            break;
        case BANPORT:
            rules.source_port_status = recv.source_port_status;
            rules.dest_port_status = recv.dest_port_status;
            rules.ban_port = recv.ban_port;
            for(i = 0;i <= MAX - 1;i++){
                rules.ban_source_port_list[i] = recv.ban_source_port_list[i];
                rules.ban_dest_port_list[i] = recv.ban_dest_port_list[i];
            }
            break;
        case BANTCP:
            rules.tcp_status = recv.tcp_status;
            break;
        case BANUDP:
            rules.udp_status = recv.udp_status;
            break;
        case FLUSH:
            rules.tcp_status = 0;
            rules.udp_status = 0;
            rules.icmp_status = 0;
            rules.dest_ip_status = MAX + 1;
            rules.source_ip_status = MAX + 1;
            rules.dest_port_status = MAX + 1;
            rules.source_port_status = MAX + 1;
            rules.ban_ip = 0;
            rules.ban_port = 0;
            for(i = 0; i <= MAX - 1; i++){
                rules.ban_source_ip_list[i] = 0;
                rules.ban_source_port_list[i] = 0;
                rules.ban_dest_ip_list[i] = 0;
                rules.ban_dest_port_list[i] = 0;
            }
            break;
        default:
            break;
    }
    if(res != 0){
        res = -EINVAL;
        printk(KERN_ERR "copy_from_user error!");
    }
    return res;
}

int hook_sockopt_get(struct sock *sk, int optval, void __user *user, int *len){
    int res;
    printk(KERN_INFO "hook_sockopt_get!");
    res = copy_to_user(user, &rules, sizeof(rules));
    if(res != 0){
        res = -EINVAL;
        printk(KERN_ERR "copy_to_user error!");
    }
    return res;
}

//init module
// use int registerFilter(void){} if func below is not usable
int init_module(){
    int i = 0;
    rules.tcp_status = 0;
    rules.udp_status = 0;
    rules.icmp_status = 0;
    rules.dest_ip_status = MAX + 1;
    rules.source_ip_status = MAX + 1;
    rules.dest_port_status = MAX + 1;
    rules.source_port_status = MAX + 1;
    rules.ban_ip = 0;
    rules.ban_port = 0;
    for(i = 0; i <= MAX - 1; i++){
        rules.ban_source_ip_list[i] = 0;
        rules.ban_source_port_list[i] = 0;
        rules.ban_dest_ip_list[i] = 0;
        rules.ban_dest_port_list[i] = 0;
    }

    //register filters
    nf_hook_localin.hook = hook_localin;
    nf_hook_localin.hooknum = NF_INET_LOCAL_IN;
    nf_hook_localin.pf = PF_INET;
    nf_hook_localin.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_hook_localin);

    nf_hook_localout.hook = hook_localout;
    nf_hook_localout.hooknum = NF_INET_LOCAL_OUT;
    nf_hook_localout.pf = PF_INET;
    nf_hook_localout.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_hook_localout);

    nf_hook_prerouting.hook = hook_prerouting;
    nf_hook_prerouting.hooknum = NF_INET_PRE_ROUTING;
    nf_hook_prerouting.pf = PF_INET;
    nf_hook_prerouting.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_hook_prerouting);

    nf_hook_forwarding.hook = hook_forwarding;
    nf_hook_forwarding.hooknum = NF_INET_FORWARD;
    nf_hook_forwarding.pf = PF_INET;
    nf_hook_forwarding.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_hook_forwarding);

    nf_hook_postrouting.hook = hook_postrouting;
    nf_hook_postrouting.hooknum = NF_INET_POST_ROUTING;
    nf_hook_postrouting.pf = PF_INET;
    nf_hook_postrouting.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_hook_postrouting);

    //register nf_socket
    nf_hook_sockopt.pf = PF_INET;
    nf_hook_sockopt.set_optmin = SOC_MIN;
    nf_hook_sockopt.set_optmax = SOC_MAX;
    nf_hook_sockopt.set = hook_sockopt_set;
    nf_hook_sockopt.get_optmin = SOC_MIN;
    nf_hook_sockopt.get_optmax = SOC_MAX;
    nf_hook_sockopt.get = hook_sockopt_get;
    nf_register_sockopt(&nf_hook_sockopt);

    printk(KERN_INFO "The filters are registed.\n");
    return 0;
}

// use void removeFilter(void){} if func below is not usable
void cleanup_module(){
    nf_unregister_net_hook(&init_net, &nf_hook_localin);
    nf_unregister_net_hook(&init_net, &nf_hook_localout);
    nf_unregister_net_hook(&init_net, &nf_hook_prerouting);
    nf_unregister_net_hook(&init_net, &nf_hook_forwarding);
    nf_unregister_net_hook(&init_net, &nf_hook_postrouting);

    nf_unregister_sockopt(&nf_hook_sockopt);

    printk(KERN_INFO "The filters are removed.\n");

}

// !need test!
// uncommit next two lines if meet problem!
// module_init(registerFilter);
// module_exit(removeFilter);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OUTIS");
MODULE_DESCRIPTION("A SIMPLE FIREWALL");



