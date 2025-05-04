#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/select.h>

#include <fcntl.h>

#define BUFFER_SIZE     4096
#define HTTP_VERSION    "HTTP/1.1"
#define CONNETION_TYPE  "Connection: close\r\n"

//通过dns协议 由域名获取到IP地址 将ip地址转换为字符串返回
char* host_to_ip(const char* hostname){

    //使用系统提供的接口
    struct hostent* host_entry = gethostbyname(hostname);
    
    if(host_entry){
        /**
         * host_entry 用于表示主机条目的数据结构
         *  h_addr_list 表示主机的网络地址列表
         *  struct in_addr 表示ipv4地址的基本数据结构
         * inet_ntoa 将点分十进制转换为字符串类型
         */ 
        return inet_ntoa(*(struct in_addr*)*host_entry->h_addr_list);
    }
        
    return NULL;
     
}

//通过socket连接服务器
int http_create_socket(char* ip){
    /*
    int socket(int domain, int type, int protocol);
        AF_INET - 地址族(Address Family)
        SOCK_STREAM - 套接字类型 ==> tcp
    成功时返回套接字描述符(非负整数)
    */
    int sockfd = socket(AF_INET,SOCK_STREAM,0);

    /*
    struct sockaddr_in 是用于 IPv4 网络编程的核心数据结构，用于表示套接字地址信息。
       struct sockaddr_in {
            sa_family_t    sin_family;   // 地址族 (AF_INET) 与socket调用指定地址类型相同
            in_port_t      sin_port;     // 16位端口号 (网络字节序)
            struct in_addr sin_addr;     // 32位IPv4地址 (网络字节序)
            unsigned char  sin_zero[8];  // 填充字段，通常置零
        }; 
    */
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(ip);//将点分十进制字符串地址转换为网络字节序32位整数值

    //连接服务器
    /*
    connect(
        sockfd,                     // 参数1：socket文件描述符
        (struct sockaddr*)&sin,     // 参数2：指向目标地址结构的指针（强制类型转换）
        sizeof(struct sockaddr_in)  // 参数3：地址结构的大小
    );
    
    */
    if(0 != connect(sockfd,(struct sockaddr*)&sin,sizeof(struct sockaddr_in))){
        return -1;
    }

    //将连接设为非阻塞
    fcntl(sockfd,F_SETFL,O_NONBLOCK);

    return sockfd;
}

//基于socket发送数据
char* http_send_request(const char* hostname,const char* resource){

    char* ip = host_to_ip(hostname);
    int sockfd = http_create_socket(ip);

    //建立缓冲区 存放http请求格式的数据
    char buffer[BUFFER_SIZE] = {0};
    //往缓冲区中写入数据
    //此处缩进问题 如果包在同一个双引号 一定要确保所有字段前面没有空格
    sprintf(buffer,
        "GET %s %s\r\n\
Host: %s\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\
%s\r\n\
\r\n"
        ,resource,HTTP_VERSION,hostname,CONNETION_TYPE);
    
    printf("Sending request:\n%s\n", buffer);

    send(sockfd,buffer,strlen(buffer),0); //发送数据
        
    //因为发送数据是非阻塞的 需要使用select 监听是否有回应
    //select 检测网络io中有没有可以读的数据

    /*
    fd_set 是用于 I/O 多路复用（如 select() 系统调用）的数据结构，
    用于监控多个文件描述符（包括Socket）的 可读、可写或异常 状态。
    
    它是一个 文件描述符集合，本质是位掩码（bitmask），每个bit代表一个文件描述符（fd）。
    配合 select() 使用，可以同时监控多个fd的状态（如是否有数据可读、是否可写、是否发生异常）
    */
    fd_set fdread;

    /*
    FD_ZERO(&fdset)	清空集合（所有bit置0）
    FD_SET(fd, &fdset)	将指定fd加入集合（对应bit置1）
    FD_CLR(fd, &fdset)	从集合中移除指定fd（对应bit置0）
    FD_ISSET(fd, &fdset)	检查fd是否在集合中（bit是否为1）
    */
    FD_ZERO(&fdread);
    FD_SET(sockfd,&fdread);

    struct timeval tv;
    tv.tv_sec = 5;//秒
    tv.tv_usec = 0;//微秒

    char* result = malloc(sizeof(int));
    memset(result,0,sizeof(int));

    while(1){
        /*
        int select(
            int nfds,              // 监控的最大fd + 1（如监控fd=0和fd=3，则nfds=4）
            fd_set *readfds,       // 监控可读的fd集合
            fd_set *writefds,      // 监控可写的fd集合
            fd_set *exceptfds,     // 监控异常的fd集合
            struct timeval *timeout // 超时时间（NULL=阻塞，0=非阻塞）
        );
        */
        int selection = select(sockfd+1,&fdread,NULL,NULL,&tv);
        if( !selection || !FD_ISSET(sockfd,&fdread)){
            break;
        }else{
            
            memset(buffer,0,BUFFER_SIZE);
            /*
            > 0	成功接收的字节数（数据已存入 buffer）
            0	连接已关闭（TCP 中表示对方调用了 close() 或 shutdown()）
            -1	出错（需检查 errno，如 EAGAIN 非阻塞无数据，ECONNRESET 连接重置）
            */
            int len = recv(sockfd,buffer,BUFFER_SIZE,0);
            if(len == 0){
                break;
            }
            
            /*
            动态扩展内存并拼接字符串，常见于网络编程中逐步接收数据并组合成完整消息的场景
                realloc 动态扩容
                    重新分配 result 的内存空间，大小为：原长度 + 新数据长度 + 1（为 \0 预留）。
                    strlen(result)：当前字符串长度（不含 \0）。
                    len：本次接收的新数据长度（recv() 返回值）。
                    +1：为字符串终止符 \0 预留空间。
                strncat 拼接数据
                    将 buffer 中的前 len 字节追加到 result 末尾，并自动添加 \0。
            */
            result = realloc(result,(strlen(result)+len+1)*sizeof(char));
            strncat(result,buffer,len);
        }
    }

    return result;
}

int main(int argc,char* argv[]){

    if(argc < 3) return -1; 

    char* response = http_send_request(argv[1],argv[2]);
    printf("response: %s\n",response);

    free(response);
}

