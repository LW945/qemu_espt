#include "util/espt.h"


void netlink_init(int *skfd, struct sockaddr_nl *saddr, struct sockaddr_nl *daddr){
    *skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(*skfd == -1)
    {
        perror("create socket error\n");
        return;
    }
    memset(saddr, 0, sizeof(struct sockaddr_nl));
    saddr->nl_family = AF_NETLINK;
    saddr->nl_pid = 100; 
    saddr->nl_groups = 0;

	memset(daddr, 0, sizeof(struct sockaddr_nl));
    daddr->nl_family = AF_NETLINK;
    daddr->nl_pid = 0; // to kernel 
    daddr->nl_groups = 0;
    
	if(bind(*skfd, (struct sockaddr *)saddr, (socklen_t)sizeof(struct sockaddr_nl)) != 0)
    {
        perror("bind() error\n");
        close(*skfd);
        return;
    }
	return;
}

void netlink_send(int skfd, struct sockaddr_nl saddr, struct sockaddr_nl daddr, struct MyNetlinkPack msg){
	int ret, type, msg_len = 0;	
	struct nlmsghdr *nlh_send = NULL;
	nlh_send = (struct nlmsghdr *)malloc(NLMSG_SPACE(msg.gva_list_len + 5));
    memset(nlh_send, 0, sizeof(struct nlmsghdr));
    nlh_send->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh_send->nlmsg_flags = 0;
    nlh_send->nlmsg_type = 0;
    nlh_send->nlmsg_seq = 0;
    nlh_send->nlmsg_pid = saddr.nl_pid; //self port
	
	if(msg.type == 1){
		memcpy(NLMSG_DATA(nlh_send), &msg.type, sizeof(int)); msg_len += sizeof(int);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, &msg.gva, sizeof(unsigned long)); msg_len += sizeof(unsigned long);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, &msg.hva, sizeof(unsigned long)); msg_len += sizeof(unsigned long);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, &msg.pid, sizeof(int));
		ret = sendto(skfd, nlh_send, nlh_send->nlmsg_len, 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(struct sockaddr_nl));		
	}
	else{
		memcpy(NLMSG_DATA(nlh_send), &msg.type, sizeof(int)); msg_len += sizeof(int);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, &msg.pid, sizeof(int)); msg_len += sizeof(int);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, &msg.gva_list_len, sizeof(int)); msg_len += sizeof(int);
		memcpy(NLMSG_DATA(nlh_send)+msg_len, msg.gva_list, sizeof(unsigned long))*msg.gva_list_len; msg_len = msg_len + sizeof(unsigned long)*msg.gva_list_len;
		ret = sendto(skfd, nlh_send, nlh_send->nlmsg_len, 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(struct sockaddr_nl));	
	}    
	if(!ret)
    {
        perror("sendto error\n");
        close(skfd);
        exit(-1);
    }
    //printf("send kernel gva:%0lx\n", *(unsigned long *)NLMSG_DATA(nlh_send));
	//printf("send kernel hva:%0lx\n", *(unsigned long *)(NLMSG_DATA(nlh_send)+sizeof(unsigned long)));
	//printf("send kernel pid:%0lx\n", *(int *)(NLMSG_DATA(nlh_send)+sizeof(unsigned long) * 2));
	free(nlh_send);
	return ;
}

void netlink_recv(int skfd, struct sockaddr_nl daddr, struct nlmsghdr *nlh_rev){
	int ret, result;    
    ret = recvfrom(skfd, nlh_rev, NLMSG_SPACE(MAX_PLOAD), 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(struct sockaddr_nl));
    if(!ret)
    {
        perror("recv form kernel error\n");
        close(skfd);
        exit(-1);
    }
	result = *(int *)NLMSG_DATA(nlh_rev);
	close(skfd);
	if(result){
		return;
	}
	else{
		exit(-1);
	}
}
