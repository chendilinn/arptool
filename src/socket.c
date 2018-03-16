/*===============================================================
*   Copyright (C) 2017 All rights reserved.
*   
*   文件名称：socket.c
*   创 建 者：陈迪林
*   创建日期：2017年07月20日
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
#include <fcntl.h>
#include "socket.h"
#include  "log.h"

/************************
函数功能:check sum
参数：buf:需要校验的数组，len:数组长度
返回值：校验和
************************/
unsigned short check_sum(unsigned short *buf, int len)
{
     LOG("check_sum()\n");
    unsigned int sum = 0;
    while(len > 1)
    {
        sum += *buf++;
        len -= 2;
    }

    if(len) /* 说明字节总数为奇数，补全 */
    {
        sum += *(unsigned char *)buf;
    }

    while(sum >> 16)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (unsigned short)(~sum);
}


/************************
函数功能:获取本机mac地址
参数：存放mac地址的指针
返回值：0 成功
	   -1 失败
************************/
int getlocalmac(unsigned char *mac)
{
	LOG("getlocalmac()\n");
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	strcpy(req.ifr_name,IF_NAME);        /* IF_NAME = "eth0" interface name */
	if(-1 != ioctl(s,SIOCGIFHWADDR,&req))
	{
		close(s);
		memcpy(mac,req.ifr_hwaddr.sa_data,6);
		return 0;
	}
	else
	{
		perror("ioctl error");
		close(s);
		return -1;
	}
}



/******************************
函数功能:获取本机IP
参数：无
返回值：成功 网络字节序的IP地址
		失败 -1
******************************/
int getlocalip()
{
	LOG("getlocalip()\n");
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	int ip;
	strcpy(req.ifr_name,IF_NAME);
	if(-1 != ioctl(s, SIOCGIFADDR, &req))
	{
		close(s);
		ip = (int)(((struct sockaddr_in *)(&req.ifr_addr))->sin_addr).s_addr;
		return ip;
	}
	else
	{
		perror("ioctl error");
		close(s);
		return -1;
	}
}

/******************************
函数功能:获取网关ip地址
参数：无
返回值：成功 网络字节序的网关IP地址
		失败 -1
******************************/
int getgateway()
{
	LOG("getgateway()\n");
	FILE* gw_fd;
	char temp[100],szNetGate[20];
	if((gw_fd = popen("route -n | grep 'UG'", "r")))
	{
		fread(temp,1,128, gw_fd);
		sscanf(temp, "%*s%s", szNetGate);
		return inet_addr(szNetGate);
	}
	else
		return -1;

}

/************************************
函数功能:填充ARP数据帧
参数： arp_frame:待填充的arp数据帧指针
	   type:2位arp响应包 1为arp广播包
返回值：成功 0
		失败 -1
************************************/
int fill_arp_frame(ARPFRAME *arp_frame, unsigned char type, unsigned char *dst,\
				   unsigned char *src, int sender_ip, int target_ip)
{
	LOG("fill_arp_frame()\n");
	int i = 0;
	for(i=0;i<6;i++)
	{
		arp_frame->dst[i] = dst[i];
		arp_frame->src[i] = src[i];
		arp_frame->sender_mac[i] = src[i];
		arp_frame->target_mac[i] = dst[i];
	}
	arp_frame->type = htons(0x0806);/*0806表示协议为arp协议，将0x0806转换成网络字节序放入type字段*/ 
	arp_frame->htype = htons(0x01);/*硬件类型 1：以太网*/
	arp_frame->ptype = htons(0x0800);/*arp使用的上层协议 ip*/
	arp_frame->hlen = 6;/*mac length*/
	arp_frame->plen = 4;/*ip length*/
	arp_frame->oper = htons(type);/* arp帧类型 2为响应包 1为广播包 */	
	arp_frame->sender_ip = sender_ip;
	arp_frame->target_ip = target_ip;
    return 0;
}

/**************************************
函数功能:发现局域网主机
参数： ip：发现结果存入ip指向的数组中
      mac: 主机的MAC地址
	 size: 发现的主机数
返回值：成功 0
		失败 -1
**************************************/
int find_host(unsigned char mac[255][6], int *ip, int *size)
{
	LOG("find_host()\n");
	ARPFRAME arp_frame = {0};
	
	unsigned char localmac[6],dst_mac[6];
	int localip, targetip;

	getlocalmac(localmac);

	localip = getlocalip();

	targetip = localip;

	int i;
	for(i=0;i<6;i++) dst_mac[i] = 0xff;

	fill_arp_frame(&arp_frame, 1, dst_mac, localmac, localip, targetip);

	/* 为发送数据帧做准备 创建发送数据的socket */
	int send_sock;
	if((send_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("send creat error");
		return -1;
	}

	struct sockaddr_ll toaddr;
	struct ifreq ifr;
	bzero(&toaddr,sizeof(toaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, IF_NAME); /*用于获取IF_NAME网卡索引*/

	if(-1 == ioctl(send_sock,SIOCGIFINDEX,&ifr))/**/
	{
		perror("get dev index error");
		return -1;
	}
	toaddr.sll_ifindex = ifr.ifr_ifindex; /* 网卡索引 发送和接收数据时需要用到网卡的索引 */
	toaddr.sll_family = PF_PACKET; /* 获取数据链路层数据 */
	
	/* 为接收数据做准备 创建接收数据的socket */
	int recv_sock;	
	if((recv_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
	{
		perror("recv socket create error");
		return -1;
	}
	if(-1 == fcntl(recv_sock, F_SETFL, O_NONBLOCK))/* 设置socket为超时模式 */
	{
		perror("fcntl error");
		return -1;
	}

	/* 超时模式所需要的数据 */
	struct timeval tv;
	fd_set readfds;
	tv.tv_sec = 1;
	tv.tv_usec = 1;
	FD_ZERO(&readfds);
	FD_SET(recv_sock,&readfds);

	unsigned char *p = (unsigned char *)&arp_frame.target_ip;
	/* 发送构造好的以太网数据帧 广播每台主机 */
	LOG("sendattck\n");
	for(i=1;i<255;i++)
	{
		p[3]=i;
		sendto(send_sock,&arp_frame,sizeof(arp_frame),0,(struct sockaddr*)&toaddr,sizeof(toaddr));
	}
	
	int cnt=0;
	int re=0;
	ARPFRAME recv_arpdat;
	while((re=select(recv_sock+1, &readfds, NULL, NULL, &tv)) > 0) /* 是否有数据来到 是否超时 */
	{
		recvfrom(recv_sock, &recv_arpdat, sizeof(recv_arpdat), 0, NULL, NULL);
		if(arp_frame.type == htons(0x0806) && recv_arpdat.oper==htons(0x02))/*0806表示协议为arp协议，将0x0806转换成网络字节序放入type字段*/ 
		{
			ip[cnt] = recv_arpdat.sender_ip;
			memcpy(&mac[cnt][0], &recv_arpdat.sender_mac[0], 6);
			cnt++;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 1;
	}
	LOG("re=%d\n",re);

	int j;
	unsigned char *pp;  /* 冒泡排序 */
	for(i=0;i<cnt;i++)
	{
		for(j=0;j<cnt-i-1;j++)
		{
			p = (unsigned char *)&ip[j];    /* 按照主机号进行排序 */
			pp = (unsigned char *)&ip[j+1];
			if(p[3] > pp[3])
			{
				int temp;
				unsigned char nmac[6];
				memcpy(&nmac[0], &mac[j][0], 6);
				memcpy(&mac[j][0], &mac[j+1][0], 6);
				memcpy(&mac[j+1][0], &nmac[0], 6);
				temp = ip[j];
				ip[j] = ip[j+1];
				ip[j+1] = temp;
			}
		}
	}

	*size = cnt;

	close(recv_sock);
	close(send_sock);
	return 0;
}

/**************************************
函数功能:通过IP获取局域网主机MAC地址
参数： ip：要获取mac主机的ip地址 
	  mac：获取到的mac地址保存在mac中
返回值：成功 0
		失败 -1
**************************************/
int getmacbyip(char *ip, unsigned char *mac)
{
	LOG("getmacbyip()\n");
	ARPFRAME arp_frame = {0};
	
	unsigned char localmac[6],dst_mac[6];
	int localip, targetip;

	getlocalmac(localmac);

	localip = getlocalip();

	targetip = inet_addr(ip);

	int i;
	for(i=0;i<6;i++) dst_mac[i] = 0xff;

	fill_arp_frame(&arp_frame, 1, dst_mac, localmac, localip, targetip);
	

	/* 为发送数据帧做准备 创建发送数据的socket */
	int send_sock;
	if((send_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("send creat error");
		return -1;
	}

	struct sockaddr_ll toaddr;
	struct ifreq ifr;
	bzero(&toaddr,sizeof(toaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, IF_NAME); /*用于获取IF_NAME网卡索引*/

	if(-1 == ioctl(send_sock,SIOCGIFINDEX,&ifr))/**/
	{
		perror("get dev index error");
		return -1;
	}
	toaddr.sll_ifindex = ifr.ifr_ifindex; /* 网卡索引 发送和接收数据时需要用到网卡的索引 */
	toaddr.sll_family = PF_PACKET; /* 获取数据链路层数据 */
	
	/* 为接收数据做准备 创建接收数据的socket */
	int recv_sock;	
	if((recv_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("recv creat error");
		return -1;
	}
	if(-1 == fcntl(recv_sock, F_SETFL, O_NONBLOCK))/* 设置socket为超时模式 */
	{
		perror("fcntl error");
		return -1;
	}

	/* 超时模式所需要的数据 */
	struct timeval tv;
	fd_set readfds;
	tv.tv_sec = 1;
	tv.tv_usec = 1;
	FD_ZERO(&readfds);
	FD_SET(recv_sock,&readfds);

	/* 发送构造好的以太网数据帧 广播每台主机 */
	if(sizeof(ARPFRAME) != sendto(send_sock,&arp_frame,42,0,(struct sockaddr*)&toaddr,sizeof(toaddr)))
	{
		perror("send error");
		return -1;
	}
	
	int cnt=0;
	while(select(recv_sock+1, &readfds, NULL, NULL, &tv) > 0) /* 是否有数据来到 是否超时 */
	{
		ARPFRAME recv_arpdat;
		recvfrom(recv_sock, &recv_arpdat, sizeof(recv_arpdat), 0, NULL, NULL);
		if((htons(recv_arpdat.oper) == 0x02) && (recv_arpdat.sender_ip == inet_addr(ip)))/* 如果收到的数据包是arp应答包并且是我们想要的ip地址发过来的，就接收mac地址并退出 */
		{
			int i;
			for(i=0;i<6;i++)
			{
				mac[i] = recv_arpdat.sender_mac[i];			
			}
			break;
		}
		usleep(100000);
		if(sizeof(ARPFRAME) != sendto(send_sock,&arp_frame,42,0,(struct sockaddr*)&toaddr,sizeof(toaddr)))/* 如果没有收到arp响应包，则继续发送arp请求包，直到收到或者发送次数满100次 */
		{
			perror("send error");
			return -1;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 1;
		cnt++;
		if(cnt==100)
		{
			printf("目标主机未响应\n");
			return -1;
		}
	}
	close(recv_sock);
	close(send_sock);
	return 0;
}


/******************************************
函数功能:发送网络数据包，tcp/ip的四层数据
参数：  send_data:待发送数据包
	    data_size:发送数据的大小
返回值：成功 0
		失败 -1
******************************************/
int send_data(void *send_data, int data_size)
{
	LOG("send_data()\n");
	/* 为发送数据帧做准备 创建发送数据的socket */
	int send_sock;
	if((send_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("send creat error");
		return -1;
	}

	struct sockaddr_ll toaddr;
	struct ifreq ifr;
	bzero(&toaddr,sizeof(toaddr));
	bzero(&ifr,sizeof(ifr));
	strcpy(ifr.ifr_name, IF_NAME); /*用于获取IF_NAME网卡索引*/

	if(-1 == ioctl(send_sock,SIOCGIFINDEX,&ifr))/**/
	{
		perror("get dev index error");
		return -1;
	}
	toaddr.sll_ifindex = ifr.ifr_ifindex; /* 网卡索引 发送和接收数据时需要用到网卡的索引 */
	toaddr.sll_family = PF_PACKET; /* 获取数据链路层数据 */

	/* 发送构造好的以太网数据帧 广播每台主机 */
	if(data_size != sendto(send_sock, send_data, data_size, 0, (struct sockaddr*)&toaddr,sizeof(toaddr)))
	{
		perror("send error");
		return -1;
	}
	
	close(send_sock);
	
	return 0;
}
/******************************************
函数功能:接收网络数据包，tcp/ip的四层数据
参数：  recv_data:接收缓冲区
	    data_size:接收数据的大小 byte
返回值：成功 接收数据的字节数
		失败 -1
******************************************/
int recv_data(void *recv_buff, int data_size)
{
	LOG("recv_data()\n");
	int recv_sock;	
	if((recv_sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("recv socket create error");
		return -1;
	}
	return recvfrom(recv_sock, recv_buff, data_size, 0, NULL, NULL);
}

int portscan()
{
    LOG("portscan()\n");
    unsigned short portlist[7] = {21,22,23,53,69,80,443};
    int sock = socket(AF_INET, SOCK_STREAM, 0); 
    if(-1 == sock)
    {
        perror("socket");
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    int i = 0,j = 1;
    int ip[255];
    int hostnum;
    unsigned char mac[255][6];

    find_host(mac, ip, &hostnum);
    for(;j<hostnum;j++)
    {
        if(mac[j][0] == 0x00)
        {
            addr.sin_addr.s_addr = ip[j];
            struct in_addr inaddr;
            inaddr.s_addr = ip[j];
            char *p = inet_ntoa(inaddr);
            printf("-----------------\n");
            printf("IP -> %s\n", p);
            for(i=0;i<7;i++)
            {
                addr.sin_port = htons(portlist[i]);
                if(-1 != connect(sock, (struct sockaddr*)&addr,sizeof addr))
                {
                    printf("%d-----open\n",portlist[i]);
                }
            }
        }
    }
    return 0;
}



























