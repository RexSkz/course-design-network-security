#include <iostream>
#include <cstring>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <winsock.h>
#define NUM_THREADS 50
using namespace std;

// 编译命令: g++ portscan.cpp -o portscan -liphlpapi -lwsock32

SOCKET fd;

// 对 inet_ntoa 的一个封装
inline char *print_inet_ntoa(int ip) {
	in_addr inaddr;
	inaddr.s_addr = htonl(ip);
	return inet_ntoa(inaddr);
}

// 扫描指定 IP 和端口
inline bool scanPort(int ip, int port) {
	struct sockaddr_in my_addr;
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(1, 1);
	if (WSAStartup(wVersionRequested , &wsaData)) {
		cout << "Winsock Initialization failed." << endl;
		return false;
	}
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		cout << "Socket Error." << endl;
		return false;
	}
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = htonl(ip);
	my_addr.sin_port = htons(port);
	int error = -1, len = sizeof(int);
	bool ret = false;
	// 设置为非阻塞模式
	unsigned long iMode = 1;
	ioctlsocket(fd, FIONBIO, &iMode);
	// 尝试连接
	if (connect(fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1) {
		timeval tm;
		tm.tv_sec = 0;
		tm.tv_usec = 200;
		fd_set set;
		FD_ZERO(&set);
		FD_SET(fd, &set);
		if (select(fd + 1, NULL, &set, NULL, &tm) > 0) {
			getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
			if (error == 0) ret = true;
			else ret = false;
		}
		else ret = false;
	}
	else ret = true;
	iMode = 0;
	ioctlsocket(fd, FIONBIO, &iMode);
	closesocket(fd);
	return ret;
}

// 根据 IP 和子网掩码推算子网
inline void scanLocalNetwork(char *ip, char *mask) {
	int ip_int = ntohl(inet_addr(ip));
	int mask_int = ntohl(inet_addr(mask));
	int ip_start = ip_int & mask_int;
	int ip_end = ip_int | (~mask_int);
	cout << "Start scan IP from " << print_inet_ntoa(ip_start);
	cout << " to " << print_inet_ntoa(ip_end) << endl;
	// 枚举局域网 IP 地址
	for (int i = ip_start; i <= ip_end; ++i) {
		for (int j = 1; j < 1<<16; ++j) {
			if (scanPort(i, j)) {
				cout << "Found open port " << print_inet_ntoa(i) << ":" << j << endl;
			}
		}
	}
	cout << endl;
}

int main(int argc, char* argv[]) {
	// 获取网卡信息
	PIP_ADAPTER_INFO adapter = new IP_ADAPTER_INFO();
	unsigned long size = sizeof(IP_ADAPTER_INFO);
	int result = GetAdaptersInfo(adapter, &size);
	if (result == ERROR_BUFFER_OVERFLOW) {
		delete adapter;
		adapter = (PIP_ADAPTER_INFO)new BYTE[size];
		result = GetAdaptersInfo(adapter, &size);
	}
	// 启动 socket 连接
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WinSock initialize failed." << endl;
		return false;
	}
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == INVALID_SOCKET) {
		cout << "Socket start failed." << endl;
		return false;
	}
	// 枚举网卡的 IP 和子网掩码
	if (result == ERROR_SUCCESS) {
		for (; adapter; adapter = adapter->Next) {
			for (IP_ADDR_STRING *ip = &(adapter->IpAddressList); ip; ip = ip->Next) {
				if (strcmp(ip->IpAddress.String, "0.0.0.0") == 0) {
					continue;
				}
				scanLocalNetwork(ip->IpAddress.String, ip->IpMask.String);
			}
		}
	}
	WSACleanup();
	return 0;
}
