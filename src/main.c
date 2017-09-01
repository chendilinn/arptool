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
	printf("***************LAN network tools*******************\n");
	printf("*****************Version: 0.3**********************\n");
	printf("[1]Find LAN host.\n");
	printf("[2]局域网断网.\n");
	printf("[3]DNS劫持.\n");
	printf("[4]局域网软件（VNC等)断网工具.\n");
	printf("[5]端口扫描.\n");
	printf(".................................  ");
	printf("选择功能:");fflush(stdout);

    char s[100]={0};
    dns_datagram *dn = (dns_datagram *)s;
    // printf("ipaddr=%p\n",&dn->iphdr.length_ver);
    // printf("ipaddr=%p\n",&dn->iphdr.dstip);

    // printf("size=%ld\n",sizeof(ip_header));
    int option;
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

