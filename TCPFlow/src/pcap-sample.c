#include <string.h>    // 用于字符串操作
#include <stdlib.h>    // 用于内存分配和其他常用功能
#include <pcap.h>      // 用于捕获和处理网络数据包
#include <netinet/in.h> // 提供 IP 地址操作函数（如 inet_aton）
#include <arpa/inet.h>  // 提供 IP 地址转换相关函数（如 inet_aton）
#include <fcntl.h>      // 用于文件控制操作
#include <unistd.h>     // 提供 UNIX 系统调用，如文件操作等
#include <errno.h>      // 提供错误代码定义

#include "packet_header.h" // 自定义数据包头部定义（可能包含协议结构体等）
#include "TCPFlow.h"

// 开启调试信息
#define WITH_DBG
#include "se_dbg.h"  // 自定义调试宏，用于调试信息的输出

// 启用 FTP 控制协议的调试信息
//#define _DBG_PKT   // 处理数据包的调试信息
//#define _DBG_ETH   // 处理以太网帧头的调试信息
//#define _DBG_IP    // 处理 IP 头的调试信息
//#define _DBG_TCP   // 处理 TCP 头的调试信息
#define _DBG_FTP_CTRL // 启用 FTP 控制协议的调试信息

// FTP 常用命令的定义
#define FTP_CMD_PORT  "PORT "   // PORT 命令，用于指定数据连接的 IP 和端口
#define FTP_CMD_PASV  "PASV"    // PASV 命令，用于请求服务器进入被动模式
#define FTP_CMD_LIST  "LIST"    // LIST 命令，用于请求列出目录内容
#define FTP_CMD_RETR  "RETR "   // RETR 命令，用于请求下载文件
#define FTP_CMD_STOR  "STOR "   // STOR 命令，用于请求上传文件

// FTP 数据命令的标识符
#define FTP_DATA_CMD_LIST  1   // 对应 LIST 命令
#define FTP_DATA_CMD_RETR  2   // 对应 RETR 命令
#define FTP_DATA_CMD_STOR  3   // 对应 STOR 命令

static __u32 ftp_data_cmd = 0;  // 当前 FTP 数据命令的标识符
char ftp_filename[256] = {0};   // 当前 FTP 文件名（用于 RESTR 或 STOR 命令）

// FTP 数据连接模式
#define FTP_DATA_MODE_PORT  1   // 使用 PORT 模式（客户端主动指定数据连接地址和端口）
#define FTP_DATA_MODE_PASV  2   // 使用 PASV 模式（服务器主动指定数据连接地址和端口）

static __u32 ftp_data_mode = 0;  // 当前 FTP 数据模式（PORT 或 PASV）

// FTP 数据连接的监听 IP 和端口
static __u32 ftp_data_listen_ip = 0;  // FTP 数据连接的监听 IP 地址
static __u16 ftp_data_listen_port = 0;  // FTP 数据连接的监听端口
//新增数据结构
static __u32 client_ip = 0; //记录下客户端ip
static __u32 server_ip = 0; //record server ip
static char loginname[128] = {0}; //record username for ftp
static char passwd[128] = {0}; //record password for ligin

// 函数：将 "a1,a2,a3,a4,a5,a6" 格式的地址字符串转换为 IP 地址和端口
int get_ftp_data_addr(const char *addrstr)
{
    __u32 a1, a2, a3, a4, a5, a6;  // 存储解析后的六个数值
    char ipstr[20];                 // 存储转换后的 IP 地址字符串
    struct in_addr in;              // 用于存储转换后的 IP 地址

    if (addrstr == NULL)  // 如果输入的地址字符串为空，返回错误
        goto errout;

    // 使用 sscanf 函数解析 "PORT" 命令中的地址字符串，格式为 "a1,a2,a3,a4,a5,a6"
    sscanf(addrstr, "%u,%u,%u,%u,%u,%u", &a1, &a2, &a3, &a4, &a5, &a6);
    
    // 拼接出标准的 IPv4 地址字符串，格式为 "a1.a2.a3.a4"
    sprintf(ipstr, "%u.%u.%u.%u", a1, a2, a3, a4);
    
    // 使用 inet_aton 函数将字符串格式的 IP 地址转换为网络字节序格式
    if (inet_aton(ipstr, &in) < 0)  // 如果转换失败，返回错误
        goto errout;

    // 计算数据连接的监听 IP 地址和端口：
    // 1. IP 地址（in.s_addr）从 inet_aton 得到
    // 2. 端口由 a5 和 a6 组成，a5*256 + a6
    ftp_data_listen_ip = in.s_addr;
    ftp_data_listen_port = a5 * 256 + a6;
    
    return 0;  // 返回成功

errout:
    // 如果出错，将监听地址和端口置为无效值
    ftp_data_listen_ip = 0;
    ftp_data_listen_port = 0;
    return -1;  // 返回失败
}

// 处理 FTP 控制协议数据
void ftp_ctrl_proc(int dir, const u_char *ftp_msg, __u32 msg_len, __u32 srcip, __u32 dstip)
{
    const char *addrstr = NULL;  // 存储提取的地址字符串

    if (msg_len == 0)  // 如果消息长度为 0，则不处理
        return;

    // 新增功能：获得客户端和服务器端的ip地址
    if(dir == 0) {//还没有获取到地址
        if(client_ip == 0 ) {
            client_ip = srcip;
            server_ip = dstip;
        }
        //获取账号密码
        if(strncmp(ftp_msg, "USER ",5) == 0) {
            bzero(loginname, sizeof(loginname));
            strncpy(loginname, ftp_msg + 5, msg_len - 7); //USER + ' ' + "\r\n"
        } 
        else if (strncmp(ftp_msg, "PASS ", 5) == 0) {
            bzero(passwd, sizeof(passwd));
            strncpy(passwd, ftp_msg + 5, msg_len - 7);//PASS + ' ' + "\r\n"
        }
    }

#ifdef _DBG_FTP_CTRL  // 如果定义了调试宏 _DBG_FTP_CTRL，则打印 FTP 控制信息
    DBG("FTP-CTRL: ");
    if (dir == 0) {
        // 如果方向是客户端->服务器，打印客户端到服务器的消息
        DBG("C->S: %.*s", msg_len, (char *) ftp_msg);
    } else {
        // 如果方向是服务器->客户端，打印服务器到客户端的消息
        DBG("S->C: %.*s", msg_len, (char *) ftp_msg);
    }
#endif

    // 处理 FTP 的 PORT 命令（用于 FTP 数据连接的地址和端口）
    if (strncmp(ftp_msg, FTP_CMD_PORT, strlen(FTP_CMD_PORT)) == 0) {
        //"PORT a1,a2,a3,a4,a5,a6
        addrstr = ftp_msg + strlen(FTP_CMD_PORT);  // 跳过命令部分，提取地址字符串
        // 调用 get_ftp_data_addr 获取数据连接的 IP 地址和端口
        if (get_ftp_data_addr(addrstr) == 0) {
            ftp_data_mode = FTP_DATA_MODE_PORT;  // 设置数据连接模式为 PORT
            DBG("***** FTP DATA Mode: %d, Server: %u.%u.%u.%u:%u\n", ftp_data_mode, NIPQUAD(ftp_data_listen_ip), ftp_data_listen_port);
        }
    } 
    // 处理 FTP 的 PASV 响应（服务器告知客户端数据连接的地址）
    else if (strncmp(ftp_msg, "227", strlen("227")) == 0) {
        //"227 Entering Passive Mode (a1,a2,a3,a4,a5,a6)"
        addrstr = strchr(ftp_msg, '(');  // 找到括号位置，提取数据连接的地址
        if (addrstr != NULL) {
            addrstr++;  // 跳过 '('
            if (get_ftp_data_addr(addrstr) == 0) {
                ftp_data_mode = FTP_DATA_MODE_PASV;  // 设置数据连接模式为 PASV
                DBG("***** FTP DATA Mode: %d, Server: %u.%u.%u.%u:%u\n", ftp_data_mode, NIPQUAD(ftp_data_listen_ip), ftp_data_listen_port);
            }
        }
    }

    // 处理 FTP 数据命令（如 LIST, RETR, STOR 等）
    if (ftp_data_mode) {
        if (strncmp(ftp_msg, FTP_CMD_LIST, strlen(FTP_CMD_LIST)) == 0) {
            ftp_data_cmd = FTP_DATA_CMD_LIST;  // 设置为 LIST 命令
            bzero(ftp_filename, sizeof(ftp_filename));  // 清空文件名
        } else if (strncmp(ftp_msg, FTP_CMD_RETR, strlen(FTP_CMD_RETR)) == 0) {
            ftp_data_cmd = FTP_DATA_CMD_RETR;  // 设置为 RETR 命令（下载文件）
            bzero(ftp_filename, sizeof(ftp_filename));  // 清空文件名
            // 提取文件名
            strncpy(ftp_filename, ftp_msg + strlen(FTP_CMD_RETR), msg_len - strlen(FTP_CMD_RETR) - 2);  // 排除尾部的 "\r\n"
            DBG("***** Get file %s\n", ftp_filename);  // 打印获取的文件名
        } else if (strncmp(ftp_msg, FTP_CMD_STOR, strlen(FTP_CMD_STOR)) == 0) {
            ftp_data_cmd = FTP_DATA_CMD_STOR;  // 设置为 STOR 命令（上传文件）
            bzero(ftp_filename, sizeof(ftp_filename));  // 清空文件名
            // 提取文件名
            strncpy(ftp_filename, ftp_msg + strlen(FTP_CMD_STOR), msg_len - strlen(FTP_CMD_STOR) - 2);  // 排除尾部的 "\r\n"
            DBG("***** Put file %s\n", ftp_filename);  // 打印上传的文件名
        }
    }
    return;
}

// 处理 TCP 数据包，新增功能
void tcp_proc(const u_char *tcp_pkt, __u32 pkt_len, __u32 srcip, __u32 dstip)
{
    TCPHdr_t *tcph = (TCPHdr_t *) tcp_pkt;  // 解析 TCP 头部

#ifdef _DBG_TCP  // 如果定义了调试宏 _DBG_TCP，则打印 TCP 头部信息
    DBG("**** TCP Header ****\n");
    DBG("Source Port: %d\n", ntohs(tcph->source));  // 打印源端口
    DBG("Dest   Port: %d\n", ntohs(tcph->dest));  // 打印目标端口
    DBG("Data Offset: %d (%d bytes)\n", tcph->doff, tcph->doff * 4);  // 打印数据偏移量（头部长度）
    DBG("SequenceNum: %u\n", ntohl(tcph->seq));  // 打印序列号
    DBG("Ack Number : %u\n", ntohl(tcph->ack_seq));  // 打印确认号
    DBG("TCP Payload: %u bytes\n", pkt_len - tcph->doff * 4);  // 打印有效负载长度
    DBG("Flags      :");
    if (tcph->syn) DBG(" SYN");  // 如果 SYN 标志位为 1，打印 SYN
    if (tcph->fin) DBG(" FIN");  // 如果 FIN 标志位为 1，打印 FIN
    if (tcph->rst) DBG(" RST");  // 如果 RST 标志位为 1，打印 RST
    if (tcph->ack) DBG(" ACK");  // 如果 ACK 标志位为 1，打印 ACK
    DBG("\n\n");
#endif

    // 如果目标端口是 21（FTP 控制协议的默认端口），则处理 FTP 控制协议数据
    if (ntohs(tcph->dest) == 21) {
        ftp_ctrl_proc(0, tcp_pkt + tcph->doff * 4, pkt_len - tcph->doff * 4, srcip, dstip);  // 0 表示客户端到服务器
        return;
    } 
    // 如果源端口是 21（FTP 控制协议的默认端口），则处理 FTP 控制协议数据
    else if (ntohs(tcph->source) == 21) {
        ftp_ctrl_proc(1, tcp_pkt + tcph->doff * 4, pkt_len - tcph->doff * 4, srcip, dstip);  // 1 表示服务器到客户端
        return;
    }

    /* FTP 数据连接的处理代码 */
    // 新增数据流重组功能
    const u_char * payload = tcp_pkt + tcph->doff * 4;
    __u32 payload_len = pkt_len - tcph->doff * 4;
    ftp_data_reconstruct(payload, payload_len, ntohl(tcph->seq), tcph->syn, tcph->fin);
    /* 在此处添加处理 FTP 数据包的代码 */

    return;  // 如果不是 FTP 数据包，直接返回
};

// 处理 IP 数据包
void ip_proc(const u_char *ip_pkt, __u32 pkt_len)
{
    IPHdr_t *iph = (IPHdr_t *) ip_pkt;

	#ifdef _DBG_IP  // 如果定义了调试宏 _DBG_IP，则打印 IP 头部相关信息
    DBG("*** IP Header ***\n");  // 打印 IP 头部开始标记
    DBG("Version  : %d\n", iph->version);  // 打印 IP 协议版本
    DBG("Headerlen: %d (%d bytes)\n", iph->ihl, iph->ihl * 4);  // 打印 IP 头长度（单位是 4 字节）
    DBG("Total len: %d\n", ntohs(iph->tot_len));  // 打印 IP 数据包的总长度
    DBG("Source IP: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));  // 打印源 IP 地址
    DBG("Dest   IP: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));  // 打印目的 IP 地址
    DBG("Protocol : %d", iph->protocol);  // 打印 IP 协议类型（例如 ICMP, TCP, UDP 等）
    
    // 根据协议类型进一步输出信息
    switch (iph->protocol) {
        case IPPROTO_ICMP:
            DBG("(ICMP)\n\n");  // 如果是 ICMP 协议
            break;
        case IPPROTO_TCP:
            DBG("(TCP)\n\n");  // 如果是 TCP 协议
            break;
        case IPPROTO_UDP:
            DBG("(UDP)\n\n");  // 如果是 UDP 协议
            break;
        default:
            DBG("(Other)\n\n");  // 如果是其他协议
            break;
    }
#endif

    // 如果协议是 TCP, 则进一步处理 TCP 数据包
    if (iph->protocol == IPPROTO_TCP) {
        // 计算 TCP 数据部分，跳过 IP 头部
        tcp_proc(ip_pkt + iph->ihl * 4, ntohs(iph->tot_len) - iph->ihl * 4, iph->saddr, iph->daddr);
        return;  // 处理完 TCP 数据包后直接返回
    }

    return;  // 如果不是 TCP 协议，直接返回
}

// 处理捕获的每个数据包
void pkt_proc(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int i = 0;
    int *cnt = (int *) arg;  // 获取数据包计数器的地址
    EthHdr_t *eth = (EthHdr_t *) packet;  // 解析以太网帧头部

    (*cnt)++;  // 增加数据包计数器

#ifdef _DBG_PKT  // 如果定义了调试宏 _DBG_PKT,则打印数据包的基本信息
    DBG("------------------------------------------------------------\n");
    DBG("Packet #%d (%dB): \n", (*cnt), pkthdr->len);  // 打印数据包编号和大小
    DBG_DUMP_BYTES(packet, pkthdr->len);  // 打印数据包内容的字节序列
#endif

#ifdef _DBG_ETH  // 如果定义了调试宏 _DBG_ETH,则打印以太网头部信息
    DBG("** Ether Header **\n");
    DBG("Dest   MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", MACSIX(eth->h_dest));  // 打印目标 MAC 地址
    DBG("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", MACSIX(eth->h_source));  // 打印源 MAC 地址
    DBG("Frame Type: 0x%04X(%s)\n\n", ntohs(eth->h_type), ((ntohs(eth->h_type) == 0x0800) ? "IP" : "Other"));  // 打印帧类型，0x0800 表示 IP 数据包
#endif

    // 如果是 IP 数据包（即以太网帧类型为 0x0800),则进一步处理 IP 数据包
    if (ntohs(eth->h_type) == 0x0800) {
        // 跳过以太网头部，调用 ip_proc 函数处理 IP 数据包
        ip_proc(packet + sizeof(EthHdr_t), pkthdr->len - sizeof(EthHdr_t));
        return;  // 处理完 IP 数据包后直接返回
    }

    return;  // 如果不是 IP 数据包，直接返回
}

// 打印程序的使用方法
void usage(const char *appname)
{
    printf("Usage:\n");
    printf("\t%s <pcap filename>\n", appname);  // 打印程序的使用格式，要求提供一个 pcap 文件作为参数
    return;
}

// 主函数入口
int main(int argc, char **argv)
{
    char *pfile;  // 存储pcap文件路径
    pcap_t *pd = NULL;  // pcap会话句柄,保存打开的pcap文件会话
    char ebuf[PCAP_ERRBUF_SIZE];  // 用于存储错误信息的缓冲区
    int count = 0;  // 用于计数处理的数据包数量

    // 检查命令行参数个数是否为2(程序名和pcap文件路径)
    if (argc != 2) {
        usage(argv[0]);  // 如果参数不正确,调用usage函数显示使用帮助
        return -1;  // 返回错误
    }

    pfile = argv[1];  // 获取用户输入的pcap文件路径
    printf("============================================================\n");
    printf("Start the analysis of the FTP connection:\n");
    printf("pcap file: %s\n", pfile);  // 打印指定的pcap文件路径

    // 打开指定的pcap文件,进行离线解析
    pd = pcap_open_offline(pfile, ebuf);
    if (pd == NULL) {
        // 如果打开失败,打印错误信息并返回
        printf("Open pcap file failed (%s)\n", ebuf);
        return -1;
    }

    // 使用pcap_loop函数循环处理所有的数据包
    // -1表示处理所有数据包,pkt_proc是处理每个数据包的回调函数
    // (u_char *) &count是用户指定的参数,传递给回调函数,用于统计数据包数量
    pcap_loop(pd, -1, pkt_proc, (u_char *) & count);

    // 输出处理完成后的总结信息
    printf("============================================================\n");
    //补充更多信息，下面是控制连接
    printf("Information about the session:\n");
    printf("Client ip: %u.%u.%u.%u\n",NIPQUAD(client_ip));
    printf("Server ip: %u.%u.%u.%u\n",NIPQUAD(server_ip));
    printf("Loginname: %s, PASSWD: %s\n", loginname, passwd);
    printf("File name: %s\n",ftp_filename);
    const char *mode_str;
    switch (ftp_data_mode) {
        case FTP_DATA_MODE_PASV:
            mode_str = "PASV";
            break;
        case FTP_DATA_MODE_PORT:
            mode_str = "PORT";
            break;
        default:
            mode_str = "None";
            break;
    }
    printf("Data Mode: %s\n", mode_str);
    //数据连接信息
    printf("Data Connection IP  : %u.%u.%u.%u\nData Connection Port: %u\n", NIPQUAD(ftp_data_listen_ip),ftp_data_listen_port);

    //总分析包数据
    printf("Total %d packets are analyzed.\n\n", count);
    // 关闭pcap会话
    pcap_close(pd);

    return 0;  // 程序正常结束
}

