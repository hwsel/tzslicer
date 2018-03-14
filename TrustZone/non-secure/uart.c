#include "uart.h"
#include "common.h"

void uart_putc(char c)
{
	while ((readl(UART_BASE + 0x2c) & 0x10) != 0) {}
	if (c == '\n') {
		writel('\r',UART_BASE + 0x30);
		while ((readl(UART_BASE + 0x2c) & 0x10) != 0) {}
	}   
	writel(c, UART_BASE + 0x30);
}

void uart_puts(const char *s) 
{
	while (*s) {
		uart_putc(*s++);
	}   
}

void uart_init(void)
{
	writel(0x10 | 0x4 | 0x2 | 0x1, UART_BASE + 0x0);
	writel(0x20, UART_BASE + 0x4);

	writel(0x56, UART_BASE + 0x18); //config baud
	writel(0x4, UART_BASE + 0x34);
}
