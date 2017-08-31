#ifndef _SOCKET_H_
#define _SOCKET_H_

#define IF_NAME "wlp3s0"

/* port define */
#define ftp     21
#define ssh     22
#define telnet  23
#define domain  53
#define tftp    69
#define http    80
#define https   443

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

typedef struct _eth_header
{
    u8  dst[6];//目标MAC地址
    u8  src[6];//源MAC地址
    u16 type;//帧类型 
}__attribute__((packed)) eth_header;//强制不对齐 紧凑方式

typedef struct _ip_header
{
    /* LITTLE_MODE */
    int hdr_length:4;
    int version:4;
    u8  tos;
    u16 total_length;
    u16 identification;
    u16 flag_offset;
    u8  ttl;
    u8  protocol;
    u16 check_sum;
    int srcip;
    int dstip;
}__attribute__((packed)) ip_header;

typedef struct _udp_header
{
    u16 srcport;
    u16 dstport;
    u16 total_length;
    u16 check_sum;
}__attribute__((packed)) udp_header;

typedef struct _ip_datagram
{
    eth_header ethhdr;
    ip_header  iphdr;
}__attribute__((packed)) ip_datagram;

typedef struct _udp_datagram
{
    eth_header ethhdr;
    ip_header  iphdr;
    udp_header udphdr;
}__attribute__((packed)) udp_datagram;

typedef struct _dns_datagram
{
    eth_header ethhdr;
    ip_header  iphdr;
    udp_header udphdr;
    u16 transactionid;
    u16 flags;
}__attribute__((packed)) dns_datagram;

typedef struct _arp  //size:42byte 以太网ARP协议数据帧
{
    u8  dst[6];//目标MAC地址
    u8  src[6];//源MAC地址
    u16 type;//帧类型 ARP 
    
    u16 htype;//硬件类型
    u16 ptype;//协议类型
    u8  hlen;
    u8  plen;//协议地址长度
    u16 oper;//操作码
    u8  sender_mac[6];//sender hardware address
             int   sender_ip;//sender ip address
    u8  target_mac[6];
             int   target_ip;
}__attribute__((packed)) ARPFRAME;//强制不对齐 紧凑方式

int getlocalmac(u8 *mac);
int getlocalip();
int getgateway();
int getmacbyip(char *ip, u8 *mac);

int fill_arp_frame(ARPFRAME *arp_frame, u8 type, u8 *dst,\
				   u8 *src, int sender_ip, int target_ip);

int find_host(u8 mac[][6], int *ip, int *size);
int send_data(void *send_data, int data_size);
int recv_data(void *recv_buff, int data_size);
u16 check_sum(u16 *buf, int len);

int portscan();

#endif /* ! _SOCKET_H_*/
