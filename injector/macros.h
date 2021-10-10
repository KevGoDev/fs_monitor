#pragma once
// Helper macro to print debug information
#define MAX_BUF 512
#define DBG_LOG(fmt, ...) {\
	char buf[MAX_BUF]={0}; \
	sprintf_s(buf, MAX_BUF, "[fs_monitorer][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__); \
	printf(buf);\
}