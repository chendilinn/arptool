/*===============================================================
*   Copyright (C) 2017 All rights reserved.
*   
*   文件名称：main.c
*   创 建 者：陈迪林
*   创建日期：2017年07月20日
*   描    述：
*
*   更新日志：
*
================================================================*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>

#include "socket.h"
#include "function.h"

int main(int argc,char *argv[]) 
{
	printf("***************网络攻击工具*******************\n");
	printf("*****************版本：0.2********************\n");
	printf("[1]发现局域网主机.\n");
	printf("[2]局域网断网.\n");
	printf("[3]DNS劫持.\n");
	printf("[4]局域网软件（VNC等)断网工具.\n");
	printf("[5]端口扫描.\n");
	printf(".................................  ");
	printf("选择功能:");fflush(stdout);
    int option;

    unsigned char iphdrhdr[100]={
    0x3c,0x46,0xd8,0xcb,0x15,0xbe,0x00,0x0c,0x29,0xc7,0xb1,0x08,0x08,0x00,0x45,0x00,
    0x00,0x3e,0x44,0xf1,0x40,0x00,0x40,0x11,0xf1,0xb0,0xc0,0xa8,0x03,0x95,0x3d,0x8b,
    0x02,0x45,0x9f,0xac,0x00,0x35,0x00,0x2a,0x2e,0xf4,0x34,0x9b,0x01,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x64,0x61,0x69,0x73,0x79,0x06,0x75,0x62,0x75,
    0x6e,0x74,0x75,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01};
    
    //dns_datagram *dns = (dns_datagram *)iphdrhdr;
    
    // printf("\n*************eth header**************\n");
    // printf("dstmac: %02x:%02x:%02x:%02x:%02x:%02x\n",dns->ethhdr.dst[0],\
    // dns->ethhdr.dst[1],dns->ethhdr.dst[2],dns->ethhdr.dst[3],dns->ethhdr.dst[4]\
    // ,dns->ethhdr.dst[5]);
    
    // printf("srcmac: %02x:%02x:%02x:%02x:%02x:%02x\n",dns->ethhdr.src[0],\
    // dns->ethhdr.src[1],dns->ethhdr.src[2],dns->ethhdr.src[3],dns->ethhdr.src[4]\
    // ,dns->ethhdr.src[5]);
    
    // printf("type:%04x\n",ntohs(dns->ethhdr.type));
    
    // printf("*************ip header**************\n");
	// printf("version:%x\n",dns->iphdr.version);
	// printf("hdr_length:%x\n",dns->iphdr.hdr_length);
	// printf("tos:%x\n",dns->iphdr.tos);
	// printf("total_length:%d\n",ntohs(dns->iphdr.total_length));
	// printf("identification:%x\n",ntohs(dns->iphdr.identification));
	// printf("offset:%x\n",ntohs(dns->iphdr.flag_offset));
	// printf("ttl:%x\n",dns->iphdr.ttl);
	// printf("protocol:%x\n",dns->iphdr.protocol);
	// printf("check_sum:%04x\n",ntohs(dns->iphdr.check_sum));

	// struct in_addr inaddr;
    // inaddr.s_addr = dns->iphdr.srcip;
    // char *srcip = inet_ntoa(inaddr);
    // printf("srciphdr:%s\n",srcip);

    // inaddr.s_addr = dns->iphdr.dstip;
    // char *dstip = inet_ntoa(inaddr);
    // printf("srciphdr:%s\n",dstip);

    
    // printf("*************udp header*************\n");
    // printf("srcport:%d\n",ntohs(dns->udphdr.srcport));
    // printf("dstport:%d\n",ntohs(dns->udphdr.dstport));
    // printf("len:%x\n",ntohs(dns->udphdr.total_length));
    // printf("check_sum:%04x\n",ntohs(dns->udphdr.check_sum));

    scanf("%d",&option);
    switch (option)
    {
        case 1:one();
				break;
		case 2:two();
				break;
		case 3:three();
				break;
		case 4:four();
				break;
		case 5:portscan();
				break;
		default: printf("输入错误.\n");
	}	
	return 0;
}

