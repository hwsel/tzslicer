#include <stdarg.h>
#include "uart.h"
#include "printf.h"
#include "timer.h"

#define is_digit(c)	((c) >= '0' && (c) <= '9')

# define do_div(n,base) ({				\
        unsigned int __base = (base);			\
	unsigned int __rem;				\
	(void)(((typeof((n)) *)0) == ((unsigned long long *)0)); \
	if (((n) >> 32) == 0) {				\
		__rem = (unsigned int)(n) % __base;	\
		(n) = (unsigned int)(n) / __base;	\
	} else						\
		 __rem = __div64_32(&(n), __base);	\
	__rem;						\
})

const unsigned char _ctype[] = { 
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,         /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                    /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                        /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                        /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                        /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,      /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                        /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,      /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                        /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,   /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,       /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,       /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,       /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,       /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};      /* 240-255 */


static int skip_atoi(const char **s)
{
	int i = 0;

	while (is_digit(**s))
		i = i * 10 + *((*s)++) - '0';

	return i;
}

unsigned int strnlen(const char * s, unsigned int count)
{
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
} 

static char *put_dec_trunc(char *buf, unsigned q)
{
	unsigned d3, d2, d1, d0;
	d1 = (q>>4) & 0xf;
	d2 = (q>>8) & 0xf;
	d3 = (q>>12);

	d0 = 6*(d3 + d2 + d1) + (q & 0xf);
	q = (d0 * 0xcd) >> 11;
	d0 = d0 - 10*q;
	*buf++ = d0 + '0'; /* least significant digit */
	d1 = q + 9*d3 + 5*d2 + d1;
	if (d1 != 0) {
		q = (d1 * 0xcd) >> 11;
		d1 = d1 - 10*q;
		*buf++ = d1 + '0'; /* next digit */

		d2 = q + 2*d2;
		if ((d2 != 0) || (d3 != 0)) {
			q = (d2 * 0xd) >> 7;
			d2 = d2 - 10*q;
			*buf++ = d2 + '0'; /* next digit */

			d3 = q + 4*d3;
			if (d3 != 0) {
				q = (d3 * 0xcd) >> 11;
				d3 = d3 - 10*q;
				*buf++ = d3 + '0';  /* next digit */
				if (q != 0)
					*buf++ = q + '0'; /* most sign. digit */
			}
		}
	}
	return buf;
}

static char *put_dec_full(char *buf, unsigned q)
{
	unsigned d3, d2, d1, d0;
	d1 = (q>>4) & 0xf;
	d2 = (q>>8) & 0xf;
	d3 = (q>>12);

	d0 = 6*(d3 + d2 + d1) + (q & 0xf);
	q = (d0 * 0xcd) >> 11;
	d0 = d0 - 10*q;
	*buf++ = d0 + '0';
	d1 = q + 9*d3 + 5*d2 + d1;
		q = (d1 * 0xcd) >> 11;
		d1 = d1 - 10*q;
		*buf++ = d1 + '0';

		d2 = q + 2*d2;
			q = (d2 * 0xd) >> 7;
			d2 = d2 - 10*q;
			*buf++ = d2 + '0';

			d3 = q + 4*d3;
				q = (d3 * 0xcd) >> 11; /* - shorter code */
				/* q = (d3 * 0x67) >> 10; - would also work */
				d3 = d3 - 10*q;
				*buf++ = d3 + '0';
					*buf++ = q + '0';
	return buf;
}

static char *put_dec(char *buf, unsigned long num)
{
	while (1) {
		unsigned rem;
		if (num < 100000)
			return put_dec_trunc(buf, num);
		rem = do_div(num, 100000);
		buf = put_dec_full(buf, rem);
	}
}

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SMALL	32		/* Must be 32 == 0x20 */
#define SPECIAL	64		/* 0x */

#define ADDCH(str, ch)	(*(str)++ = (ch))

static char *number(char *buf, char *end, unsigned long long num,
		int base, int size, int precision, int type)
{
	static const char digits[16] = "0123456789ABCDEF";

	char tmp[66];
	char sign;
	char locase;
	int need_pfx = ((type & SPECIAL) && base != 10);
	int i;

	locase = (type & SMALL);
	if (type & LEFT)
		type &= ~ZEROPAD;
	sign = 0;
	if (type & SIGN) {
		if ((signed long long) num < 0) {
			sign = '-';
			num = -(signed long long) num;
			size--;
		} else if (type & PLUS) {
			sign = '+';
			size--;
		} else if (type & SPACE) {
			sign = ' ';
			size--;
		}
	}
	if (need_pfx) {
		size--;
		if (base == 16)
			size--;
	}

	i = 0;
	if (num == 0)
		tmp[i++] = '0';
	else if (base != 10) { /* 8 or 16 */
		int mask = base - 1;
		int shift = 3;

		if (base == 16)
			shift = 4;

		do {
			tmp[i++] = (digits[((unsigned char)num) & mask]
					| locase);
			num >>= shift;
		} while (num);
	} else { /* base 10 */
		i = put_dec(tmp, num) - tmp;
	}

	if (i > precision)
		precision = i;
	size -= precision;
	if (!(type & (ZEROPAD + LEFT))) {
		while (--size >= 0)
			ADDCH(buf, ' ');
	}
	if (sign)
		ADDCH(buf, sign);
	if (need_pfx) {
		ADDCH(buf, '0');
		if (base == 16)
			ADDCH(buf, 'X' | locase);
	}
	if (!(type & LEFT)) {
		char c = (type & ZEROPAD) ? '0' : ' ';

		while (--size >= 0)
			ADDCH(buf, c);
	}
	while (i <= --precision)
		ADDCH(buf, '0');
	while (--i >= 0)
		ADDCH(buf, tmp[i]);
	while (--size >= 0)
		ADDCH(buf, ' ');
	return buf;
}

static char *string(char *buf, char *end, char *s, int field_width,
		int precision, int flags)
{
	int len, i;

	if (s == NULL)
		s = "<NULL>";

	len = strnlen(s, precision);

	if (!(flags & LEFT))
		while (len < field_width--)
			ADDCH(buf, ' ');
	for (i = 0; i < len; ++i)
		ADDCH(buf, *s++);
	while (len < field_width--)
		ADDCH(buf, ' ');
	return buf;
}

static char *pointer(const char *fmt, char *buf, char *end, void *ptr,
		int field_width, int precision, int flags)
{
	unsigned long long num = (unsigned int)ptr;


	switch (*fmt) {
	case 'a':
		flags |= SPECIAL | ZEROPAD;

		switch (fmt[1]) {
		case 'p':
		default:
			field_width = sizeof(unsigned long long) * 2 + 2;
			num = *(unsigned long long *)ptr;
			break;
		}
		break;
	case 'm':
		flags |= SPECIAL;
		break;
	}

	flags |= SMALL;
	if (field_width == -1) {
		field_width = 2*sizeof(void *);
		flags |= ZEROPAD;
	}
	return number(buf, end, num, 16, field_width, precision, flags);
}

static int vsnprintf_internal(char *buf, unsigned int size, const char *fmt,
		va_list args)
{
	unsigned long long num;
	int base;
	char *str;

	int flags;		/* flags to number() */

	int field_width;	/* width of output field */
	int precision;		/* min. # of digits for integers; max
				   number of chars for from string */
	int qualifier;		/* 'h', 'l', or 'L' for integer fields */
				/* 'z' support added 23/7/1999 S.H.    */
				/* 'z' changed to 'Z' --davidm 1/25/99 */
				/* 't' added for ptrdiff_t */
	char *end = buf + size;

	str = buf;

	for (; *fmt ; ++fmt) {
		if (*fmt != '%') {
			ADDCH(str, *fmt);
			continue;
		}

		flags = 0;
repeat:
			++fmt;		/* this also skips first '%' */
			switch (*fmt) {
			case '-':
				flags |= LEFT;
				goto repeat;
			case '+':
				flags |= PLUS;
				goto repeat;
			case ' ':
				flags |= SPACE;
				goto repeat;
			case '#':
				flags |= SPECIAL;
				goto repeat;
			case '0':
				flags |= ZEROPAD;
				goto repeat;
			}

		/* get field width */
		field_width = -1;
		if (is_digit(*fmt))
			field_width = skip_atoi(&fmt);
		else if (*fmt == '*') {
			++fmt;
			/* it's the next argument */
			field_width = va_arg(args, int);
			if (field_width < 0) {
				field_width = -field_width;
				flags |= LEFT;
			}
		}

		/* get the precision */
		precision = -1;
		if (*fmt == '.') {
			++fmt;
			if (is_digit(*fmt))
				precision = skip_atoi(&fmt);
			else if (*fmt == '*') {
				++fmt;
				/* it's the next argument */
				precision = va_arg(args, int);
			}
			if (precision < 0)
				precision = 0;
		}

		/* get the conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' ||
			 *fmt == 'Z' || *fmt == 'z' || *fmt == 't') {
			qualifier = *fmt;
			++fmt;
			if (qualifier == 'l' && *fmt == 'l') {
				qualifier = 'L';
				++fmt;
			}
		}

		/* default base */
		base = 10;

		switch (*fmt) {
		case 'c':
			if (!(flags & LEFT)) {
				while (--field_width > 0)
					ADDCH(str, ' ');
			}
			ADDCH(str, (unsigned char) va_arg(args, int));
			while (--field_width > 0)
				ADDCH(str, ' ');
			continue;

		case 's':
			str = string(str, end, va_arg(args, char *),
				field_width, precision, flags);
			continue;

		case 'p':
			str = pointer(fmt + 1, str, end,
					va_arg(args, void *),
					field_width, precision, flags);
			/* Skip all alphanumeric pointer suffixes */
			while (isalnum(fmt[1]))
				fmt++;
			continue;

		case 'n':
			if (qualifier == 'l') {
				long *ip = va_arg(args, long *);
				*ip = (str - buf);
			} else {
				int *ip = va_arg(args, int *);
				*ip = (str - buf);
			}
			continue;

		case '%':
			ADDCH(str, '%');
			continue;

		/* integer number formats - set up the flags and "break" */
		case 'o':
			base = 8;
			break;

		case 'x':
			flags |= SMALL;
		case 'X':
			base = 16;
			break;

		case 'd':
		case 'i':
			flags |= SIGN;
		case 'u':
			break;

		default:
			ADDCH(str, '%');
			if (*fmt)
				ADDCH(str, *fmt);
			else
				--fmt;
			continue;
		}
		if (qualifier == 'L')  /* "quad" for 64 bit variables */
			num = va_arg(args, unsigned long long);
		else if (qualifier == 'l') {
			num = va_arg(args, unsigned long);
			if (flags & SIGN)
				num = (signed long) num;
		} else if (qualifier == 'Z' || qualifier == 'z') {
			num = va_arg(args, unsigned int);
		} else if (qualifier == 't') {
			num = va_arg(args, unsigned int);
		} else if (qualifier == 'h') {
			num = (unsigned short) va_arg(args, int);
			if (flags & SIGN)
				num = (signed short) num;
		} else {
			num = va_arg(args, unsigned int);
			if (flags & SIGN)
				num = (signed int) num;
		}
		str = number(str, end, num, base, field_width, precision,
			     flags);
	}

	*str = '\0';
	
	return str - buf;
}

int vsprintf(char *buf, const char *fmt, va_list args)
{
	return vsnprintf_internal(buf, INT_MAX, fmt, args);
}

int sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsprintf(buf, fmt, args);
	va_end(args);
	return i;
}

int printf(const char *fmt, ...)
{
	va_list args;
	unsigned int i;
	char printbuffer[CFG_PBSIZE];

	va_start(args, fmt);

	i = vscnprintf(printbuffer, sizeof(printbuffer), fmt, args);
	va_end(args);

	uart_puts(printbuffer);
	return i;
}

int timer_printf(const char *fmt, ...)
{
	va_list args;
	unsigned int i = 0, msecond = 0;
	char printbuffer[CFG_PBSIZE - 12];
	char printbuffer_with_timestamp[CFG_PBSIZE];

	va_start(args, fmt);

	msecond=get_timer(0);
	vsprintf(printbuffer, fmt, args);
	i = sprintf(printbuffer_with_timestamp,"[%7u.%03u]%s",msecond/1000,msecond%1000,printbuffer);
	va_end(args); 

	/* Print the string */
	uart_puts(printbuffer_with_timestamp);

	return i;
}

int gtimer_printf(const char *fmt, ...)
{
	va_list args;
	unsigned int i = 0, msecond = 0;
	char printbuffer[CFG_PBSIZE - 12];
	char printbuffer_with_timestamp[CFG_PBSIZE];

	va_start(args, fmt);

	msecond=gget_timer(0);
	vsprintf(printbuffer, fmt, args);
	i = sprintf(printbuffer_with_timestamp,"[%7u.%03u]%s",msecond/1000,msecond%1000,printbuffer);
	va_end(args); 

	/* Print the string */
	uart_puts(printbuffer_with_timestamp);

	return i;
}

unsigned int __div64_32(unsigned long long *n, unsigned int base)
{
	unsigned long long rem = *n;
	unsigned long long b = base;
	unsigned long long res, d = 1;
	unsigned int high = rem >> 32;

	/* Reduce the thing a bit first */
	res = 0;
	if (high >= base) {
		high /= base;
		res = (unsigned long) high << 32;
		rem -= (unsigned long) (high*base) << 32;
	}

	while ((signed long long)b > 0 && b < rem) {
		b = b+b;
		d = d+d;
	}

	do {
		if (rem >= b) {
			rem -= b;
			res += d;
		}
		b >>= 1;
		d >>= 1;
	} while (d);

	*n = res;
	return rem;
}


int vsnprintf(char *buf, unsigned int size, const char *fmt,
		va_list args)
{
	return vsnprintf_internal(buf, size, fmt, args);
}

int vscnprintf(char *buf, unsigned int size, const char *fmt, va_list args)
{
	int i;

	i = vsnprintf(buf, size, fmt, args);

	if ((i < size))
		return i;
	if (size != 0)
		return size - 1;
	return 0;
}

int raise(int signum)
{
	printf("raise: Signal # %d caught\n",signum);
	return 0;
}

