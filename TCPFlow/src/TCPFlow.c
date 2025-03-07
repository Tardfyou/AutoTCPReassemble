#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "TCPFlow.h"

// 使用外部定义的 FTP 文件名
extern char ftp_filename[256];

// 定义 TCP 数据片段结构体，表示一个 TCP 数据包的基本信息
typedef struct TcpSegment {
    uint32_t sequence_number;  // TCP 序列号，标识数据包在流中的位置
    uint32_t data_length;      // 数据长度，表示数据包中载荷的大小
    uint8_t *payload;          // 指向数据载荷的指针
    struct TcpSegment *next;   // 指向下一个 TCP 数据包的指针，用于链表管理
} TcpSegment;

// TCP 数据流管理变量
static TcpSegment *tcp_stream_head = NULL;  // TCP 数据流的头指针，指向第一个数据片段
static int is_tcp_stream_initialized = 0;   // 标记 TCP 数据流是否已初始化
static uint32_t initial_sequence_number = 0; // 记录 TCP 连接的初始序列号

/**
 * @brief  分配内存并复制数据，创建新的 TCP 数据片段
 * @param  payload 数据载荷指针，指向存储的内容
 * @param  data_length 数据长度，表示数据的大小
 * @return  返回分配好的 TcpSegment 结构体指针，若失败则返回 NULL
 */
static TcpSegment *create_tcp_segment(const uint8_t *payload, uint32_t data_length) {
    TcpSegment *segment = (TcpSegment *)malloc(sizeof(TcpSegment));
    if (!segment) {
        fprintf(stderr, "[ERROR] Memory allocation failed for TcpSegment\n");
        return NULL;
    }

    segment->payload = (uint8_t *)malloc(data_length);
    if (!segment->payload) {
        fprintf(stderr, "[ERROR] Memory allocation failed for payload\n");
        free(segment);
        return NULL;
    }

    memcpy(segment->payload, payload, data_length);
    segment->data_length = data_length;
    segment->next = NULL;

    return segment;
}

/**
 * @brief  按序插入 TCP 数据片段，确保数据流按序排列
 * @param  sequence_number 序列号，标识数据片段的位置
 * @param  payload 数据载荷指针，指向存储的内容
 * @param  data_length 数据长度，表示数据的大小
 * 
 * @note   该函数会检查数据片段是否重复，如果重复则跳过插入。
 *         在链表中按序插入数据片段，保持 TCP 流的正确顺序。
 */
static void insert_tcp_segment(uint32_t sequence_number, const uint8_t *payload, uint32_t data_length) {
    if (data_length == 0) return; // 如果数据长度为 0，则无需插入

    // 创建新的数据片段
    TcpSegment *new_segment = create_tcp_segment(payload, data_length);
    if (!new_segment) return;  // 如果创建失败，则返回

    new_segment->sequence_number = sequence_number;

    // 在链表中按序插入数据片段，保持 TCP 数据的顺序
    TcpSegment **current = &tcp_stream_head;
    while (*current && (*current)->sequence_number < sequence_number) {
        current = &(*current)->next;
    }

    // 检查是否存在重复的序列号，避免数据冗余
    if (*current && (*current)->sequence_number == sequence_number) {
        fprintf(stderr, "[WARNING] Duplicate packet detected, seq: %u\n", sequence_number);
        free(new_segment->payload);
        free(new_segment);
        return;
    }

    // 插入新数据片段
    new_segment->next = *current;
    *current = new_segment;
    printf("[INFO] Packet inserted: seq=%u, length=%u\n", sequence_number, data_length);
}

/**
 * @brief  将 TCP 流数据重组并写入文件
 * 
 * @note   该函数根据 TCP 序列号顺序重组数据流，并将数据写入指定文件。
 *         如果发现丢失的数据段，会在日志中提示警告。
 */
static void flush_tcp_stream() {
    if (ftp_filename[0] == '\0') {
        fprintf(stderr, "[ERROR] Target filename not set\n");
        return;
    }

    // 打开指定文件以进行写操作
    FILE *file_pointer = fopen(ftp_filename, "wb");
    if (!file_pointer) {
        perror("[ERROR] Failed to open file");
        return;
    }

    uint32_t expected_sequence = initial_sequence_number;
    TcpSegment *current = tcp_stream_head;
    while (current) {
        // 如果当前数据片段的序列号不等于期望的序列号，说明有丢包
        if (current->sequence_number != expected_sequence) {
            fprintf(stderr, "[WARNING] Missing data detected, expected seq: %u, found seq: %u\n", expected_sequence, current->sequence_number);
        }

        // 将数据片段的载荷写入文件
        fwrite(current->payload, 1, current->data_length, file_pointer);

        // 更新期望的下一个序列号
        expected_sequence = current->sequence_number + current->data_length;
        current = current->next;
    }
    
    fclose(file_pointer);
    printf("[INFO] File [%s] reassembly completed successfully\n", ftp_filename);
}

/**
 * @brief  释放 TCP 数据流内存，清理所有已存储的 TCP 片段
 * 
 * @note   该函数会释放所有动态分配的内存，清除 TCP 数据流的头指针，
 *         以及重置相关的初始化标记和序列号。
 */
static void free_tcp_stream() {
    TcpSegment *current = tcp_stream_head;
    while (current) {
        TcpSegment *temp = current;
        current = current->next;
        free(temp->payload);  // 释放数据载荷内存
        free(temp);           // 释放数据片段结构体内存
    }
    tcp_stream_head = NULL;  // 清空 TCP 流头指针
    is_tcp_stream_initialized = 0; // 重置 TCP 流初始化标记
    initial_sequence_number = 0;   // 重置初始序列号
    printf("[INFO] TCP stream data has been cleared\n");
}

/**
 * @brief  处理 FTP 数据流，进行 TCP 数据重组
 * @param  payload      载荷数据
 * @param  payload_len  载荷数据长度
 * @param  sequence_number TCP 序列号
 * @param  is_syn       是否为 SYN 标志，表示 TCP 连接的开始
 * @param  is_fin       是否为 FIN 标志，表示 TCP 连接的结束
 * 
 * @note   如果检测到 TCP 连接初始化（SYN 标志），则会清理之前的流数据并初始化新流。
 *         处理完所有数据片段后，若检测到 TCP 连接结束（FIN 标志），则会将数据重组并写入文件。
 */
void ftp_data_reconstruct(const uint8_t *payload, uint32_t payload_len, uint32_t sequence_number, int is_syn, int is_fin) {
    // 初始化 TCP 数据流，如果是连接建立的第一个包（SYN）
    if (is_syn && !is_tcp_stream_initialized) {
        printf("[INFO] TCP connection initialized, starting seq: %u\n", sequence_number);
        free_tcp_stream(); // 清理已有数据，初始化流
        is_tcp_stream_initialized = 1;
        initial_sequence_number = sequence_number;
    }

    if (!is_tcp_stream_initialized) return; // 如果 TCP 流未初始化，则直接返回

    // 按序插入数据片段
    insert_tcp_segment(sequence_number, payload, payload_len); 
    
    // 如果检测到 FIN 标志，说明 TCP 连接关闭，开始文件重组
    if (is_fin) {
        printf("[INFO] TCP connection closed, starting file reconstruction\n");
        flush_tcp_stream(); // 处理完整的 TCP 数据流，写入文件
        free_tcp_stream(); // 释放 TCP 流内存
    }
}
