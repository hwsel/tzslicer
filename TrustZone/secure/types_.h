#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8; 
typedef unsigned char __u8; 

typedef signed short __s16;
typedef unsigned short __u16;

typedef signed int __s32;
typedef unsigned int __u32;

typedef signed long long __s64;
typedef unsigned long long __u64;

typedef unsigned int 	__kernel_size_t;
typedef signed int 	__kernel_ssize_t;

typedef __kernel_size_t		size_t;

typedef __kernel_ssize_t	ssize_t;

typedef unsigned char		u_char;
typedef unsigned short		u_short;
typedef unsigned int		u_int;
typedef unsigned long		u_long;

typedef		__s8		int8_t;
typedef		__s16		int16_t;
typedef		__s32		int32_t;


typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;

typedef		__u64		uint64_t;
typedef		__s64		int64_t;



#endif /* _LINUX_TYPES_H */
