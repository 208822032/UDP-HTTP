#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>


#define DNS_SERVER_PORT   53
#define DNS_SERVER_IP     "114.114.114.114"

#define DNS_HOST          0x01
#define DNS_CNAME         0x05

//初始化请求头
struct dns_header{

    //分别对应DNS协议请求头的各字段
    //16位数据 使用short类型
    unsigned short id;//会话标识
    unsigned short flags;//标志

    unsigned short questions;///问题数
    unsigned short answer;///回答

    unsigned short authority;//
    unsigned short additional;
};

//定义询问内容
struct dns_question{
    int length;
    unsigned short qtype;
    unsigned short qclass;
    unsigned char* name;
};

struct dns_item{
    char* domain;
    char* ip;
};

//填充head内容
int dns_create_header(struct dns_header* header){

    if(header == NULL) return -1;
    memset(header,0,sizeof(struct dns_header));

    //生成随机值作为id
    srandom(time(NULL));
    header->id = random();

    header->flags = htons(0x0100);//将数字转为网络序
    header->questions = htons(1);//一次性回答一个问题
    
    return 0;
}

int dns_create_question(struct dns_question* question,const char* hostname){
    //初始化数据
    if(question == NULL || hostname == NULL)  return -1;
    memset(question,0,sizeof(struct dns_question));

    question->name = (char*)malloc(strlen(hostname) + 2);//预留两个位置用于表示结尾
    if(question->name == NULL)
        return -2;
    question->length = strlen(hostname) + 2;

    //初始化查询类别
    question->qtype = htons(1);
    question->qclass = htons(1);

    //将hostname填充到name中
    /*
    hostname的存储方式 
        www.0voice.com -> 3www60voice3com
    */
   const char* delim = ".";//用于截断的标准
   char* qname = question->name;

   char* hostname_dup = strdup(hostname);//底层调用malloc 复制hostname
   char* token = strtok(hostname_dup,delim);//对hostname_dup进行截断 此时token=www

   while(token != NULL){

    size_t len = strlen(token);//将数字先放入
    *qname = len;
    qname++;

    strncpy(qname,token,len+1);//此处+1多考虑一位'\0'
    qname += len;

    token = strtok(NULL,delim);//因为一开始有值 所以不需要在在第一个参数给值

   }

   free(hostname_dup);
   return 0;
}

int dns_build_request(struct dns_header* header,struct dns_question* question,char* request,int rlen){

    if(header == NULL || question == NULL || request == NULL) return -1;
    memset(request,0,rlen);

    //将头部数据放入request中
    memcpy(request,header,sizeof(struct dns_header));
    int offset = sizeof(struct dns_header);
    //将question放入request中
    memcpy(request+offset,question->name,question->length);
    offset += question->length;
    memcpy(request+offset,&question->qtype,sizeof(question->qtype));
    offset += sizeof(question->qtype);
    memcpy(request+offset,&question->qclass,sizeof(question->qclass));
    offset += sizeof(question->qclass);


    return offset;
}

//检查一个整数 in 是否是 DNS 消息中的指针（DNS compression pointer）
//DNS 压缩指针的标志是 最高两位是 11（即 0xC0
static int is_pointer(int in){
    return ((in & 0xC0) == 0xC0);
}

//DNS域名解析函数 
/*
普通标签 格式为长度+字符串，如3www6google3com0
压缩指针 格式为0xC0+偏移量，用于减少重复域名的存储

读取当前字节
    如果是0表示域名结束
如果是压缩指针(最高两位为11)：
    获取偏移量
    跳转到指定位置继续解析
如果是普通标签：
    读取标签长度
    复制标签内容到输出缓冲区
    添加点分隔符(如果不是最后一个标签)
    继续处理下一个标签
*/
static void dns_parse_name(unsigned char* chunk,unsigned char* ptr,char* out,int* len){

    /**
     * chunk：指向整个 DNS 报文数据的起始位置（用于处理指针跳转）。
        ptr：当前正在解析的位置（可能指向普通标签或指针）。
        out：存储解析结果的缓冲区（最终输出的域名字符串）。
        len：记录当前已解析的域名长度（用于正确写入 out）。
        flag：存储当前字节（可能是标签长度或指针标志）。
        n：用于存储指针偏移量（如果遇到 DNS 压缩指针）。
        pos：指向 out 缓冲区的当前位置，用于写入解析结果。
     */
    int flag = 0,n = 0,alen = 0;
    char* pos = out + (*len);

    while(1){

        flag = (int)ptr[0];//读取当前字节
        if(flag == 0) break;//当读到末尾 即0就结束

        //检查是否是dns压缩指针
        if(is_pointer(flag)){
            n = (int)ptr[1];//获取指针偏移量
            ptr = chunk + n;//跳转到指针指向的位置
            dns_parse_name(chunk,ptr,out,len);//递归解析
            break;
        }else{//处理非指针
            ptr++;
            memcpy(pos,ptr,flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if((int)ptr[0] != 0){
                memcpy(pos,".",1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

/**
 * 
 * 代码处理的DNS响应报文大致结构如下：

头部：
    事务ID(2字节)
    标志(2字节)
    问题数(2字节)
    回答数(2字节)
    授权记录数(2字节)
    额外记录数(2字节)

查询部分：
    查询域名(可变长度)
    查询类型(2字节)
    查询类(2字节)
    回答部分(代码主要解析的部分)：
    域名(可能为指针)
    类型(2字节)
    类(2字节)
    TTL(4字节)
    数据长度(2字节)
    数据(可变长度)
 */
//buffer 指向接收到的DNS响应报文的指针
//domains 输出参数，用于返回解析得到的域名和IP地址列表
static int dns_parse_response(char* buffer,struct dns_item** domains){

    //跳过不需要的部分
    int i = 0;
    unsigned char* ptr = buffer;//移动指针用于遍历DNS报文

    ptr += 4;//跳过事务ID
    //读取查询部分的数量(2字节) 使用ntohs从网络字节转换为主机字节
    int querys = ntohs(*(unsigned short*)ptr);
    
    //读取回答部分的数量 字节序转换
    ptr += 2;
    int answers = ntohs(*(unsigned short*)ptr);

    //跳过授权记录数 外记录数 查询部分类型和类
    ptr += 6;

    /*
    遍历每个查询记录
    内层循环解析查询域名(以0结尾)
    每次跳过查询类型(2字节)和查询类(2字节)，共4字节
    */
    for(i = 0;i < querys;i++){
        while(1){
            int flag = (int)ptr[0];
            ptr += (flag + 1);

            if(flag == 0) break;
        }
        ptr += 4;
    }

    /*
    为回答记录分配内存空间

    cname: 存储CNAME记录
    aname: 存储解析的域名
    ip: 存储点分十进制IP
    netip: 存储二进制IP

    len: 域名长度
    type: 记录类型
    ttl: 生存时间
    datalen: 数据长度
    */
    char cname[128],aname[128],ip[20],netip[4];
    int len,type,ttl,datalen;


    //分配结果内存
    int cnt = 0;
    struct dns_item* list = (struct dns_item*)calloc(answers,sizeof(struct dns_item));
    if(list == NULL){
        return -1;
    }
    //解析每个回答
    for(i = 0;i < answers;i++){
        //清空aname缓冲区
        bzero(aname,sizeof(aname));
        len = 0;
        //解析域名
        dns_parse_name(buffer,ptr,aname,&len);
        ptr += 2;
        //读取记录类型
        type = htons(*(unsigned short*)ptr);
        ptr += 4;

        //读取TTL(4字节)并转换字节序
        //读取数据长度(2字节)并转换字节序
        //移动指针6字节
        ttl = htons(*(unsigned short*)ptr);
        ptr += 4;

        datalen = ntohs(*(unsigned short*)ptr);
        ptr += 2;

        //处理CNAME记录
        if(type == DNS_CNAME){
            /*
            如果是CNAME记录
            清空cname缓冲区
            解析别名
            移动指针到数据末尾
            */
            bzero(cname,sizeof(cname));
            len = 0;
            dns_parse_name(buffer,ptr,cname,&len);
            ptr += datalen;
        }else if(type == DNS_HOST){
            
            bzero(ip,sizeof(ip));//清空缓存

            if(datalen == 4){//检查数据是否为4(IPV4)
                memcpy(netip,ptr,datalen);
                inet_ntop(AF_INET,netip,ip,sizeof(struct sockaddr));//转换为点分十进制

                printf("%s has address %s\n",aname,ip);
                printf("\tTime to live: %d minutes, %d seconds\n",ttl/60,ttl%60);

                list[cnt].domain = (char*)calloc(strlen(aname) + 1,1);
                memcpy(list[cnt].domain,aname,strlen(aname));

                list[cnt].ip = (char*)calloc(strlen(ip)+1,1);
                memcpy(list[cnt].ip,ip,strlen(ip));

                cnt++;
            }
            ptr += datalen;
        }
    }
    *domains = list;
    ptr += 2;

    return cnt;
}

//作为客户端向服务器段发送数据
int dns_client_commit(const char* domain){

    int sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd < 0) return -1;

    //拼接地址
    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    
    //对于UDP 不需要挥手连接 但可以使用连接先开辟一次道路
    int ret = connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));
    printf("connect : %d\n",ret);

    struct dns_header header = {0};
    dns_create_header(&header);

    struct dns_question question = {0};
    dns_create_question(&question,domain);

    char request[1024] = {0};
    int length = dns_build_request(&header,&question,request,1024);

    int slen = sendto(sockfd,request,length,0,(struct sockaddr*)&servaddr,sizeof(struct sockaddr));

    //接受服务器的回应
    char response[1024] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);

    int n = recvfrom(sockfd,response,sizeof(response),
        0,(struct sockaddr*)&addr,(socklen_t*)&addr_len);

    struct dns_item* dns_domian = NULL;
    dns_parse_response(response,&dns_domian);

    free(dns_domian);
    return n;
}

int main(int argc,char* argv[]){

    if(argc < 2) return -1;


    dns_client_commit(argv[1]);

}
