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

    unsigned char iphdr[100]={
    0xc8,0xe7,0xd8,0x2e,0x19,0x42,0x18,0xcf,0x5e,0xf7,0x89,0xd5,0x08,0x00,0x45,0x00,
	0x00,0x46,0xba,0x23,0x40,0x00,0x40,0x11,0x68,0xab,0xc0,0xa8,0x01,0x6b,0xd3,0xa2,
	0x82,0x22,0xd2,0x1f,0x00,0x35,0x00,0x32,0x0d,0x43,0xe3,0xdd,0x01,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x64,0x65,0x74,0x65,0x63,0x74,0x70,0x6f,0x72,
	0x74,0x61,0x6c,0x07,0x66,0x69,0x72,0x65,0x66,0x6f,0x78,0x03,0x63,0x6f,0x6d,0x00,
	0x00,0x01,0x00,0x01};

	dns_datagram *dns = (dns_datagram *)iphdr;
	printf("\nversion:%x\n",dns->ip.version);
	printf("hdr_length:%x\n",dns->ip.hdr_length);
	printf("tos:%x\n",dns->ip.tos);
	printf("total_length:%d\n",ntohs(dns->ip.total_length));
	printf("identification:%x\n",ntohs(dns->ip.identification));
	printf("offset:%x\n",ntohs(dns->ip.flag_offset));
	printf("ttl:%x\n",dns->ip.ttl);
	printf("protocol:%x\n",dns->ip.protocol);
	printf("check_sum:%x\n",ntohs(dns->ip.check_sum));
	

	struct in_addr inaddr;
    inaddr.s_addr = dns->ip.srcip;
    char *srcip = inet_ntoa(inaddr);
    printf("srcip:%s\n",srcip);

    inaddr.s_addr = dns->ip.dstip;
    char *dstip = inet_ntoa(inaddr);
    printf("srcip:%s\n",dstip);

    printf("srcport:%d\n",ntohs(dns->udp.srcport));
    printf("dstport:%d\n",ntohs(dns->udp.dstport));
    printf("len:%x\n",ntohs(dns->udp.total_length));
    printf("check_sum:%x\n",ntohs(dns->udp.check_sum));

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
