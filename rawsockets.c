// 程序运行流程如下：
// 1.
// 初始化：设置随机种子，创建原始套接字，解析并设置目标IP地址和端口，解析并设置源IP地址和随机客户端端口，告知内核数据包中包含了IP头部。
// 2. 发送SYN：创建SYN包并发送至服务器，请求建立TCP连接。
// 3.
// 接收SYN-ACK：从服务器接收SYN-ACK包。服务器收到SYN包后会返回SYN-ACK包，表示同意建立TCP连接。
// 4.
// 读取序列和确认号：从SYN-ACK包中读取服务器发送的序列号和确认号，这两个带会在后续的TCP数据传输中使用。
// 5. 发送ACK：发送ACK包至服务器，确认成功接收SYN-ACK包。
// 6. 发送数据：创建数据包，并发送HTTP
// GET请求到服务器。请求内容为：在localhost下，路劲为/，使用HTTP/1.1协议。
// 7.
// 接收并确认服务器响应：反复从服务器接收数据包，并创建ACK包确认成功接收。重复上述过程，直至无数据收取。
// 8. 断开连接：关闭套接字，断开与服务器的连接。

// 如何编译？
// gcc -Wall -Wextra -Wpedantic -std=gnu11 rawsockets.c -o run

// 如何运行？
// sudo ./run 源地址 远程地址 远程端口

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// pseudo header needed for tcp header checksum calculation
struct pseudo_header {
  u_int32_t source_address; // 这是源地址
  u_int32_t dest_address;   // 这是目的地址
  u_int8_t placeholder;     // 为0
  u_int8_t protocol;        // 协议号
  u_int16_t tcp_length;     // tcp长度
};

#define DATAGRAM_LEN 4096 // datagram length
#define OPT_SIZE 20       // tcp options size

// 该函数checksum的主要任务是计算一定长度数据的校验和。这个算法是TCP/IP协议中用来检查报文头部在传输过程中是否发生改变的一种方法。这个校验和的计算过程大体上按照以下步骤：
// 首先，初始化两个无符号整型变量sum和i，其中sum用来保存校验和计算结果，i作为流程控制的迭代器。
// 使用一个for循环对数据进行组合和累加操作，每次迭代时取buf数组中2个字节的数据（即16位），对这些数据求和并保存到sum中。为了阅读这两个字节的数据，它使用类型转换将部分字符数组转化为一个无符号16位短整型指针，然后解引用此指针获取16位数据。不断累加这些数据直到处理完输入字符串的全部字符。
// 在计算过程中，如果输入的数据个数是奇数个，那么最后会剩下一个字节未处理。这个时候就需要进行特殊处理。代码if
// (size &
// 1)判断输入数据的个数是否为奇数，如果是则再处理剩下的一个字节，将其转换成无符号16位短整型并添加到sum中。
// 通过循环将sum的高16位与低16位相加，将结果保存到sum中，直到sum的数值能在16位空间表示为止。无线相加的过程被称为“对折（Folding）”。
// 最后，使用位反操作符~对sum进行取反操作，将得到的值作为checksum返回，这步操作性质就Like
// TCP/IP checksum规范，需要取结果的“反码”。
unsigned short checksum(const char *buf, unsigned size) {
  unsigned sum = 0, i;

  /* Accumulate checksum */
  for (i = 0; i < size - 1; i += 2) {
    unsigned short word16 = *(unsigned short *)&buf[i];
    sum += word16;
  }

  /* Handle odd-sized case */
  if (size & 1) {
    unsigned short word16 = (unsigned char)buf[i];
    sum += word16;
  }

  /* Fold to get the ones-complement result */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  /* Invert to get the negative in ones-complement arithmetic */
  return ~sum;
}

// 此函数create_syn_packet的工作是在给定的源地址和目标地址之间创建一个TCP的SYN（同步）包。
// 下面是它的主要步骤：
// 通过calloc分配足够的内存空间来存储IP包。然后将ip包和struct
// iphdr(IP头结构）以及struct tcphdr (TCP头结构）的首地址关联。
// 在IP头进行配置。其中包括头长度（iph->ihl），版本（iph->version），长度总和（iph->tot_len），生存时间（iph->ttl），协议类型（iph->protocol），以及源地址和目标地址等。它还设置了一个随机的包ID并预留了校验和，后面会填充。
// 然后函数配置TCP头部。设置其源端口和目标端口，也随机设置一个序列号，然后定义了TCP头部大小，窗口大小等TCP需要的数值。并预留了校验和字段位置用于后期填入。
// 进行TCP伪头部的创建，这个伪头部用于后续的TCP和IP数值校验进行使用(remote
// checksum
// 的辅助检校部分)。它包含源地址，目标地址，协议类型等信息，并存入一个新的数据包。
// 设置TCP的option部分。设置了MSS（最大段大小）为48，选项代码为0x02,长度值0x04。并且开启了SACK(选择性确认)，这个选项的代码为0x04,长度值0x02。
// 计算TCP校验和和IP头的校验部分，用到的方法是你之前提到的checksum方法。将计算出来的值分别填入TCP头和IP头的检校部分。
// 将更新后的IP数据包和它的长度作为输出参数赋值给*out_packet和*out_packet_len，然后释放之前创建的伪头部的内存空间。
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       char **out_packet, int *out_packet_len) {
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // TCP options
  // unsigned char options[20] = {// End of Option List (EOL)
  //                              0x00,
  //                              // No-Operation (NOP)
  //                              0x01,
  //                              // Maximum Segment Size (MSS), 其默认值1452
  //                              bytes 0x02, 0x04, 0x05, 0xb4,
  //                              // TCP Window Scale (WS), shift count is 5
  //                              0x03, 0x03, 0x05,
  //                              // TCP Selective Acknowledgement Permitted
  //                              (SACKPermitted) 0x04, 0x02,
  //                              // SACK, left edge: 282214678, right edge:
  //                              282214758 0x05, 0x0A, 0x10, 0xd6, 0x86, 0xa6,
  //                              0x10, 0xd6, 0x87, 0x06,
  //                              // Timestamp, value: 2839276240, echo reply: 0
  //                              0x08, 0x0A, 0xa9, 0x14, 0x00, 0x50, 0x00,
  //                              0x00, 0x00, 0x00};
  // memcpy((void *)tcph + sizeof(struct tcphdr), options, sizeof(options));

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48); // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;
  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));
  pseudogram[36] = 0x04;
  pseudogram[37] = 0x02;

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

// 函数的工作流程具体如下：
// 通过calloc分配足够的内存来存储IP包。然后将IP包和struct
// iphdr（IP头结构）以及struct tcphdr (TCP头结构）的首地址相连。
// 配置IP头。配置的内容，如头部长度（iph->ihl），版本（iph->version），长度总和(iph->tot_len)，生存时间（iph->ttl），以及协议类型（iph->protocol），源地址，和目标地址等与之前函数相同。这部分同样还预留了校验和字段填入真正的校验和，此步数后续处理。
// 配置TCP头。除了源端口，目标端口，头大小，窗口大小等字段按需填充外，函数参数中的seq和ack_seq用于填充序列号字段和确认号字段。tcph->ack被设置为1，表明这是一个ACK数据包用于确认接收到信息。
// 创建TCP伪头部（pseudo
// header）。此步骤的主要作用是协助之后校验头部和数据段的校验和。其中的源地址和目的地址都来源于传入的源和目标套接字。
// 计算TCP头和IP头的校验和（checksum方法）并回传给相应位置。
// 最后将包和长度返回（通过设置*out_packet 和
// *out_packet_len）。注意这里，伪头部在使用完毕后释放了其内存。
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, char **out_packet,
                       int *out_packet_len) {
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

// 这个函数create_data_packet的目的是创建一个带有数据负载的TCP数据包。它会在之前已有的握手环节之后用于数据的传输。
// 具体工作流程如下：
// 通过calloc分配足够大小的内存以容纳整个数据包。然后把内存的指针和IP头部结构struct
// iphdr以及TCP头部结构struct tcphdr的起始地址关联起来。
// 接下来，函数设置数据的负载。函数会计算负载的位置，它在IP头部和TCP头部之后。然后就把传入的data拷贝到这个位置。
// 配置IP包头部。相比于之前的create_ack_packet函数，这里唯一的变化是长度字段iph->tot_len里加上了数据的长度。
// 配置TCP头部。大部分字段和create_ack_packet函数类似。不过这次中，tcph->psh被设置为1，表示这个TCP包推送了数据。并且tcph->ack也被设置为1，表示这是一个确认包。其余字段如序列号和确认序列号都来源于函数的参数。
// 创建TCP的伪头部（pseudo
// header），稍微不同的地方在于这次还加上了数据长度data_len。
// 计算TCP头和IP头的校验和，并把结果写回传入包的相应字段中。
// 最后，把包和它的长度返回通过参数*out_packet 和
// *out_packet_len返回。然后释放伪头部的内存。
void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                        int32_t seq, int32_t ack_seq, char *data, int data_len,
                        char **out_packet, int *out_packet_len) {
  // datagram to represent the packet
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

  // required structs for IP and TCP header
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // set payload
  char *payload =
      datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  memcpy(payload, data, data_len);

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len =
      sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE +
              data_len;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE + data_len);

  tcph->check = checksum((const char *)pseudogram, psize);
  iph->check = checksum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

// 此函数read_seq_and_ack的工作是读取TCP数据包中的序列号和确认号。序列号和确认号都是TCP首部中的重要字段。序列号用于标记数据的顺序，确认号则用于ACK包确认已经成功接收序列号为ack-1及其之前的数据。
// 下面是整个函数的工作步骤：
// 首先函数备份了序列号字段里的值到变量seq_num中。序列号在TCP包的位置通常位于偏移量为24的地方。然后它通过一个指针备份了确认号，它通常位于序列号之后的偏移量为28的位置。
// 因为网络中传输的数据通常都是使用的大端（网络）序，而主机内存通常使用的是小端序，所以这里使用ntohl把数据转换为主机序。
// 把转换为主机序的seq_num和ack_num的值回传给输入参数seq和ack。
// 最后，打印了转换到主机序的序列号和确认号。
void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack) {
  // read sequence number
  uint32_t seq_num;
  memcpy(&seq_num, packet + 24, 4);
  // read acknowledgement number
  uint32_t ack_num;
  memcpy(&ack_num, packet + 28, 4);
  // convert network to host byte order
  *seq = ntohl(seq_num);
  *ack = ntohl(ack_num);
  printf("sequence number: %lu\n", (unsigned long)*seq);
  printf("acknowledgement number: %lu\n", (unsigned long)*seq);
}

// 这个函数receive_from的目标是从特定的目的端口接收数据，并存储到提供的缓冲区当中。
// 以下是这个函数的具体操作：
// 该函数一开始设定了用于保存目的数据端口的变量dst_port，以及用于保存接收到的字节数量的变量received。
// 然后，该函数进入一个循环中，使用recvfrom函数从套接字接收数据并将其存储到提供的缓冲区中。同时该函数返回接收的字节数量并存储在变量received中。
// 如果recvfrom返回值小于0，说明出现了错误（如连接被断开等），在这种情况下，循环将立即结束，函数返回received值。
// 如果接收成功，将从接收到的数据的本地头部字段（位于缓冲区22位的位置）中取出目的端口号，并存储到变量dst_port中。
// 完成提取的目的端口号后，会检查该端口号是否等于期待接收的源数据的端口号（dst->sin_port），如果不符合预期，该函数就会断开循环，并继续接收数据，直到目的端口符合预期就终止循环。
// 打印接收到的字节数量以及预期接收数据的目的端口号。
int receive_from(int sock, char *buffer, size_t buffer_length,
                 struct sockaddr_in *dst) {
  unsigned short dst_port;
  int received;
  do {
    received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
    if (received < 0)
      break;
    memcpy(&dst_port, buffer + 22, sizeof(dst_port));
  } while (dst_port != dst->sin_port);
  printf("received bytes: %d\n", received);
  printf("destination port: %d\n", ntohs(dst->sin_port));
  return received;
}

// main的目标是创建一个TCP/IP流并根据输入采取行动。流程如下：
// 首先，它检查参数数量argc是否为4，因为这个应用需要3个参数：源IP地址，目的IP地址和目的端口。对第一个参数（程序自身的名字）不进行处理。
// 然后，它创建一个原始的套接字sock，该套接字使用的是TCP协议。如果创建失败就直接退出程序。
// 配置目标地址daddr，包括IP地址和端口号，使用的命名空间为AF_INET。
// 配置源地址saddr，包括随机选择一个客户端端口和提供的源IP。
// 并且打印输出选择的源端口。
// 使用setsockopt来通知内核，已经包含头文件到套接字中。
// 使用之前定义的创建SYN函数create_syn_packet来创建一个SYN数据包并把数据包发送给目标地址。
// 接收来自的目标的SYN-ACK包，解析序列号和确认码，用这两个数字来创建ACK数据包并邮寄回给目标。
// 创建一个含有HTTP GET请求的数据包create_data_packet并发送到目标地址。
// 然后，主进程等待并处理目标发来的数据包，每当收到一次应答，就会通过create_ack_packet创建一ACK包并回复给目标。
// 等到所有操作都完成时，关闭套接字并返回0来结束程序。
int main(int argc, char **argv) {
  if (argc != 4) {
    printf("invalid parameters.\n");
    printf("USAGE %s <source-ip> <target-ip> <port>\n", argv[0]);
    return 1;
  }

  srand(time(NULL));

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock == -1) {
    printf("socket creation failed\n");
    return 1;
  }

  // destination IP address configuration
  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons(atoi(argv[3]));
  if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1) {
    printf("destination IP configuration failed\n");
    return 1;
  }

  // source IP address configuration
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(rand() % 65535); // random client port
  if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1) {
    printf("source IP configuration failed\n");
    return 1;
  }
  printf("selected source port number: %d\n", ntohs(saddr.sin_port));

  // tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) {
    printf("setsockopt(IP_HDRINCL, 1) failed\n");
    return 1;
  }

  // send SYN
  char *packet;
  int packet_len;
  create_syn_packet(&saddr, &daddr, &packet, &packet_len);

  int sent;
  if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr,
                     sizeof(struct sockaddr))) == -1) {
    printf("sendto() failed\n");
  } else {
    printf("successfully sent %d bytes SYN!\n", sent);
  }

  // receive SYN-ACK
  char recvbuf[DATAGRAM_LEN];
  int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
  if (received <= 0) {
    printf("receive_from() failed\n");
  } else {
    printf("successfully received %d bytes SYN-ACK!\n", received);
  }

  // read sequence number to acknowledge in next packet
  uint32_t seq_num, ack_num;
  read_seq_and_ack(recvbuf, &seq_num, &ack_num);
  int new_seq_num = seq_num + 1;

  // send ACK
  // previous seq number is used as ack number and vica vera
  create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
  if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr,
                     sizeof(struct sockaddr))) == -1) {
    printf("sendto() failed\n");
  } else {
    printf("successfully sent %d bytes ACK!\n", sent);
  }

  // send data
  while (1) {
    char request[] = "Hello server!!!";
    // char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    create_data_packet(&saddr, &daddr, ack_num, new_seq_num, request,
                       sizeof(request) - 1 / sizeof(char), &packet,
                       &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr,
                       sizeof(struct sockaddr))) == -1) {
      printf("send failed\n");
    } else {
      printf("successfully sent %d bytes PSH!\n", sent);
    }
  }

  // receive response
  while ((received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr)) >
         0) {
    printf("successfully received %d bytes!\n", received);
    read_seq_and_ack(recvbuf, &seq_num, &ack_num);
    new_seq_num = seq_num + 1;
    create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet,
                      &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr *)&daddr,
                       sizeof(struct sockaddr))) == -1) {
      printf("send failed\n");
    } else {
      printf("successfully sent %d bytes ACK!\n", sent);
    }
  }
  close(sock);
  return 0;
}
