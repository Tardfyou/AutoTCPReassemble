#ifndef PACKET_HEADER_H
#define PACKET_HEADER_H

#include <asm/types.h>

//以太帧首部
typedef struct ethhdr {
	__u8 h_dest[6];		//目的MAC地址
	__u8 h_source[6];	//源MAC地址
	__u16 h_type;		//帧类型
} EthHdr_t;

//IP数据报首部
typedef struct iphdr {
#ifdef __BIG_ENDIAN__
	__u8 version:4, ihl:4;	//版本,报头长度
#else
//#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	__u8 ihl:4, version:4;	//版本,报头长度
#endif
	__u8 tos;		//服务类型
	__u16 tot_len;		//总长度
	__u16 id;		//标识
	__u16 frag_off;		//标志+片偏移
	__u8 ttl;		//生存周期
	__u8 protocol;		//协议类型
	__u16 check;		//头部校验和
	__u32 saddr;		//源IP地址
	__u32 daddr;		//目的IP地址
	__u8 option[0];		//选项
} IPHdr_t;

//TCP报文段首部
typedef struct tcphdr {
	__u16 source;		//源端口
	__u16 dest;		//目的端口
	__u32 seq;		//序号
	__u32 ack_seq;		//确认号
#ifdef __BIG_ENDIAN__
	__u8 doff:4, res1:4;	//数据偏移,保留
	__u8 cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;	//标志位
#else
//#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	__u8 res1:4, doff:4;	//数据偏移,保留
	__u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;	//标志位
#endif
	__u16 window;		//窗口
	__u16 check;		//检验和
	__u16 urg_ptr;		//紧急指针
	__u8 option[0];		//选项
} TCPHdr_t;

#endif	//PACKET_HEADER_H
