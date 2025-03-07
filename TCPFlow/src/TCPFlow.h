#ifndef TCP_FLOW_H
#define TCP_FLOW_H

#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>  // 使用标准整数类型

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  重组 FTP 数据连接的 TCP 载荷
 * 
 * @param payload       TCP 载荷数据
 * @param payload_len   数据长度
 * @param seq          TCP 序列号
 * @param syn          标识 SYN 标志（非 0 表示置位）
 * @param fin          标识 FIN 标志（非 0 表示置位）
 */
void ftp_data_reconstruct(const uint8_t *payload, uint32_t payload_len, uint32_t seq, int syn, int fin);

#ifdef __cplusplus
}
#endif

#endif  // TCP_FLOW_H
