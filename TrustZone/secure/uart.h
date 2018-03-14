#ifndef _UART_H
#define _UART_H

#define UART_BASE 0xe0001000
#define putchar(c) uart_putc(c)   


void uart_putc(char c);
void uart_puts(const char *s);
void uart_init(void);


#endif
