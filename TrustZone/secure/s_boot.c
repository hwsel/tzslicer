#include "uart.h"
#include "printf.h"
#include "timer.h"
#include "common.h"

extern void monitorInit();

int secure_main(void)
{
	int i;
	uart_init();
	timer_init();
	
	// set for non-secure can access some coprocessor reg
	CP15_SET_NSACR(0x00073fff);
	CP15_SET_CPACR(0x0fffffff);

	// set for SCR
	CP15_SET_SCR(0b110000);

	writel(0xdf0d, 0xf8000008);	//unlock
//	writel(0x0, 0xe0200018);	//config uart to secure
	writel(0xffff, 0xf8000404);	//config ocmram2 to non-secure
//	writel(0x0, 	   0xf8000400); //config ocmram1 to secure
//	writel(0x767b,	0xf8000910);	//lock
	
	asm volatile ("isb");
	asm volatile ("dsb");
	
	// Install monitor
//  char* dest = (char*)0x20100;
//	char* src  = (char*)0x1000;
// 	for(i=0; i<500; i++)
//	 	*dest++ = *src++;

	writel((0x1 << 7), 0xe0200018);	//config uart to secure
	monitorInit();

#if 1
	for (i = 0; i < 10; i++) {
		uart_puts("Secure World\n");
		asm volatile ("smc #0\n\t");		// Switch to normal world
	}
#endif
	return 0;
}
