#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 12345
#define BUFFER_SIZE 256


void malware_function() { // 使用 system 函数调用 nc 指令 创建监听端口 接受数据
    const char *cmd = "nc -l -p 54321";
    printf("Executing command: %s\n", cmd);
    int ret = system(cmd);
    if (ret == -1) {
        perror("system failed");
    } else {
        printf("Command executed successfully.\n");
    }
}


void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);  // 缓冲区溢出漏洞
}

   


int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char array[100]; // 存储指令的数组

    // 创建套接字
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 绑定套接字
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 监听
    if (listen(server_fd, 1) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    // 接受客户端连接
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Client connected.\n");

    while (1) {
        // 接收指令
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Client disconnected.\n");
            break;
        }

        buffer[bytes_received] = '\0'; // 确保字符串以空字符结束
        printf("Received: %s\n", buffer);

        // 检查指令大小
        if (bytes_received < 100) {
            memset(array, 0, 100);
            strncpy(array, buffer, bytes_received);

            // 判断第2-3个元素是否为AB
            if (array[1] == 'A' && array[2] == 'B') {
                malware_function(); 
                send(client_fd, "mal test\n", 9, 0);
                continue;
            }

            // 判断第9个元素是否为X
            if (array[8] == 'X') {
                vulnerable_function(array);
                send(client_fd, "vul test\n", 9, 0);
                continue;
            }
        }

        // 默认回复
        send(client_fd, "Try Again\n", 10, 0);
    }

    // 关闭套接字
    close(client_fd);
    close(server_fd);

    return 0;
}