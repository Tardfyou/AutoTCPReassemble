#ifndef _SE_LOG_H_
#define _SE_LOG_H_

#ifndef __KERNEL__
#include <stdio.h>
#endif

#include <asm/types.h>

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((__u8 *)&addr)[0], \
	((__u8 *)&addr)[1], \
	((__u8 *)&addr)[2], \
	((__u8 *)&addr)[3]
#endif // NIPQUAD

#ifndef HIPQUAD
#ifdef __BIG_ENDIAN__
#define HIPQUAD(addr) \
	((__u8 *)&addr)[0], \
	((__u8 *)&addr)[1], \
	((__u8 *)&addr)[2], \
	((__u8 *)&addr)[3]
#else
#define HIPQUAD(addr) \
	((__u8 *)&addr)[3], \
	((__u8 *)&addr)[2], \
	((__u8 *)&addr)[1], \
	((__u8 *)&addr)[0]
#endif // __BIG_ENDIAN__
#endif // HIPQUAD

#ifndef MACSIX
#define MACSIX(mac) \
	((__u8 *)mac)[0], \
	((__u8 *)mac)[1], \
	((__u8 *)mac)[2], \
	((__u8 *)mac)[3], \
	((__u8 *)mac)[4], \
	((__u8 *)mac)[5]
#endif // MAXSIX

static inline void ip2str(__u32 ip, char *str)
{
	sprintf(str, "%d.%d.%d.%d", NIPQUAD(ip));
	return;
}

static inline void mac2str(__u8 * mac, char *str)
{
	sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", MACSIX(mac));
	return;
}

static inline __u32 str2ip(const char *str, __u32 * ip)
{
	__u16 a[4];
	__u32 addr;
	__u8 *p;
	int i;

	a[0] = a[1] = a[2] = a[3] = 0;
	sscanf(str, "%hu.%hu.%hu.%hu", &a[0], &a[1], &a[2], &a[3]);
	for (i = 0; i < 4; i++) {
		p = (__u8 *) & addr + i;
		*p = a[i] & 0xFF;
	}

	if (ip)
		*ip = addr;

	return addr;
}

static inline void str2mac(const char *str, __u8 * mac)
{
	int i;
	__u16 m[6];

	m[0] = m[1] = m[2] = m[3] = m[4] = m[5] = 0;
	sscanf(str, "%hx:%hx:%hx:%hx:%hx:%hx", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
	for (i = 0; i < 6; i++)
		mac[i] = m[i];

	return;
}

#endif /* _SE_LOG_H_ */
