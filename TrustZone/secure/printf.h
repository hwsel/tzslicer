#ifndef _PRINTF_H
#define _PRINTF_H

void serial_printf(const char *fmt, ...);
int timer_printf(const char *fmt, ...);
int printf(const char *fmt, ...);
int gtimer_printf(const char *fmt, ...);
unsigned int __div64_32(unsigned long long *n, unsigned int base);

#define getc() uart_getc()
#define KERN_UART     1
#define KERN_ERROR    2
#define KERN_INFO     3
#define KERN_DEBUG    4
#define TRACE(level,fmt,args...)  ( ((level) <= CURRENT_DEBUG_LEVEL ) ? printf(fmt,##args) : printbuf(fmt,##args))

#define CFG_PBSIZE 256
#define NULL    0
#define INT_MAX         ((int)(~0U>>1))

#define _U      0x01    /* upper */
#define _L      0x02    /* lower */
#define _D      0x04    /* digit */
#define _C      0x08    /* cntrl */
#define _P      0x10    /* punct */
#define _S      0x20    /* white space (space/lf/tab) */
#define _X      0x40    /* hex digit */
#define _SP     0x80    /* hard space (0x20) */

#define is_digit(c)	((c) >= '0' && (c) <= '9')
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c)      ((__ismask(c)&(_U|_L|_D)) != 0)

#endif
