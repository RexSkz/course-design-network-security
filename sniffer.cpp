#include <iostream>
#include <cstdio>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <winsock.h>
#include <pthread.h>
#define DEF_BUF_SIZE  1024
#define SIO_RCVALL    (0x80000000 | (0x18000000) | (1))
#define OUTPUT_FORMAT "| %-6d | %-5d | %-6s | %-15s | %-15s | %-8d | %-8d |\n"
#define NUM_THREADS   8

using namespace std;

// 编译命令: g++ sniffer.cpp -o sniffer -lwsock32 -liphlpapi -lpthread

typedef struct _PACK_INFO {
	unsigned short	nLength;			// 数据包长度
	unsigned short	nProtocol;			// 协议类型
	unsigned int	nSourIp;			// 源IP
	unsigned int	nDestIp;			// 目的IP
	unsigned short	nSourPort;			// 源端口号
	unsigned short	nDestPort;			// 目的端口号
} PACK_INFO, *PPACK_INFO;

typedef struct _IP_HEADER {
	unsigned char	bVerAndHLen;		// 版本信息（前4位）和头长度（后4位）
	unsigned char	bTypeOfService;	    // 服务类型
	unsigned short	nTotalLength;		// 数据包长度
	unsigned short	nID;				// 数据包标识
	unsigned short	nReserved;			// 保留字段
	unsigned char	bTTL;				// 生成时间
	unsigned char	bProtocol;			// 协议类型
	unsigned short	nCheckSum;			// 校验和
	unsigned int	nSourIp;			// 源IP
	unsigned int	nDestIp;			// 目的IP
} IP_HEADER, *PIP_HEADER;

typedef struct _TCP_HEADER {
	unsigned short	nSourPort;			// 源端口号
	unsigned short	nDestPort;			// 目的端口号
	unsigned int	nSequNum;			// 序列号
	unsigned int	nAcknowledgeNum;	// 确认号
	unsigned short	nHLenAndFlag;		// 前4位：TCP头长度；中6位：保留；后6位：标志位
	unsigned short	nWindowSize;		// 窗口大小
	unsigned short	nCheckSum;			// 检验和
	unsigned short	nrgentPointer;		// 紧急数据偏移量
} TCP_HEADER, *PTCP_HEADER;

typedef struct _UDP_HEADER {
	unsigned short	nSourPort;			// 源端口号
	unsigned short	nDestPort;			// 目的端口号
	unsigned short	nLength;			// 数据包长度
	unsigned short	nCheckSum;			// 校验和
} UDP_HEADER, *PUDP_HEADER;

void displayPackage(PACK_INFO PackInfo) {
	static int nCount = 0;
	nCount += 1;
	char *lpszProtocol = new char[8];
	char *lpszSourIp = new char[16];
	char *lpszDestIp = new char[16];
	// 判断包的类型
	if (PackInfo.nProtocol == IPPROTO_TCP)
		strcpy(lpszProtocol, "TCP");
	else if (PackInfo.nProtocol == IPPROTO_UDP)
		strcpy(lpszProtocol, "UDP");
	struct in_addr SourAddr, DestAddr;
	SourAddr.S_un.S_addr = PackInfo.nSourIp;
	strcpy(lpszSourIp, inet_ntoa(SourAddr));
	DestAddr.S_un.S_addr = PackInfo.nDestIp;
	strcpy(lpszDestIp, inet_ntoa(DestAddr));
	printf(OUTPUT_FORMAT, nCount, PackInfo.nLength, lpszProtocol, lpszSourIp, lpszDestIp,
		htons(PackInfo.nSourPort), htons(PackInfo.nDestPort));
	delete lpszProtocol;
	delete lpszSourIp;
	delete lpszDestIp;
}

void *Sniffer(void *ip) {
	PACK_INFO PackInfo = {0};
	int nRecvSize = 0;
	char *szPackBuf = new char[DEF_BUF_SIZE];
	sockaddr_in localhost;
	localhost.sin_family = AF_INET;
	localhost.sin_addr.s_addr = inet_addr((char *)ip);
	localhost.sin_port = htons(0);
	// 创建监听套接字
	SOCKET fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (fd == INVALID_SOCKET) {
		cout << "Socket error, please run as administrator." << endl;
		return NULL;
	}
	// 绑定地址信息到套接字
	bind(fd, (sockaddr*)&localhost, sizeof(sockaddr));
	// 设置为混杂模式，收所有IP包
	unsigned long dwValue = 1;
	ioctlsocket(fd, SIO_RCVALL, &dwValue);
	while (1) {
		nRecvSize = recv(fd, szPackBuf, DEF_BUF_SIZE, 0);
		if (nRecvSize > 0) {
			// 解析IP包头
			PIP_HEADER pIpHeader       = (PIP_HEADER)szPackBuf;
			PackInfo.nLength           = nRecvSize;
			PackInfo.nProtocol         = (unsigned short)pIpHeader->bProtocol;
			PackInfo.nSourIp           = pIpHeader->nSourIp;
			PackInfo.nDestIp           = pIpHeader->nDestIp;
			unsigned int nIpHeadLength = (pIpHeader->bVerAndHLen & 0x0F) * sizeof(unsigned int);
			PTCP_HEADER pTcpHeader;
			PUDP_HEADER pUdpHeader;
			// 只检测TCP和UDP包
			switch(pIpHeader->bProtocol) {
			case IPPROTO_TCP:
				// 取得TCP数据包端口号
				pTcpHeader = (PTCP_HEADER)&szPackBuf[nIpHeadLength];
				PackInfo.nSourPort = pTcpHeader->nSourPort;
				PackInfo.nDestPort = pTcpHeader->nDestPort;
				displayPackage(PackInfo);
				break;
			case IPPROTO_UDP:
				// 取得UDP数据包端口号
				pUdpHeader = (PUDP_HEADER)&szPackBuf[nIpHeadLength];
				PackInfo.nSourPort = pUdpHeader->nSourPort;
				PackInfo.nDestPort = pUdpHeader->nDestPort;
				displayPackage(PackInfo);
				break;
			}
		}
	}
	return NULL;
}

int main() {
	cout << "| nCount | nSize | szProt | SourIP          | DestIP          | SourPort | DestPort |" << endl;
	pthread_t tids[NUM_THREADS];
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		cout << "WSAStartup error" << endl;
		return 1;
	}
	// 获取网卡信息
	PIP_ADAPTER_INFO adapter = new IP_ADAPTER_INFO();
	unsigned long size = sizeof(IP_ADAPTER_INFO);
	int result = GetAdaptersInfo(adapter, &size);
	if (result == ERROR_BUFFER_OVERFLOW) {
		delete adapter;
		adapter = (PIP_ADAPTER_INFO)new unsigned char[size];
		result = GetAdaptersInfo(adapter, &size);
	}
	// 获取本地地址信息
	if (result == ERROR_SUCCESS) {
		int index;
		for (; adapter; adapter = adapter->Next) {
			index = 0;
			for (IP_ADDR_STRING *ip = &(adapter->IpAddressList); ip; ip = ip->Next, ++index) {
				if (strcmp(ip->IpAddress.String, "0.0.0.0") == 0) {
					continue;
				}
				pthread_create(&tids[index], NULL, Sniffer, (void*)ip->IpAddress.String);
			}
		}
		char localhost[16];
		strcpy(localhost, "127.0.0.1");
		pthread_create(&tids[index], NULL, Sniffer, (void*)localhost);
	}
	for (int i = 0; i < NUM_THREADS; ++i)
		pthread_join(tids[i], NULL);
	return 0;
}
