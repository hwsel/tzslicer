.phony: all

all: normal.bin

ARMGNU ?= arm-xilinx-linux-gnueabi


CC  = $(ARMGNU)-gcc
LD  = $(ARMGNU)-ld
COPY= $(ARMGNU)-objcopy
DUMP= $(ARMGNU)-objdump
PLATFORM_LIBGCC = /opt/CodeSourcery/Sourcery_CodeBench_Lite_for_Xilinx_GNU_Linux/lib/gcc/arm-xilinx-linux-gnueabi/4.6.1

normal.bin: normal.elf
	$(COPY) -O binary normal.elf normal.bin
	$(DUMP) -D normal.elf > dump_normal.log

normal.elf: normal_startup.S normal_main.c
	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -nostdlib normal_startup.S
	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -nostdlib normal_main.c printf.c uart.c timer.c
#	$(LD) -T normal.lds -o normal.elf normal_startup.o normal_main.o printf.o uart.o
	$(LD)  -nostartfiles -static -nostdlib -T normal.lds normal_startup.o normal_main.o printf.o timer.o uart.o -o normal.elf  -lgcc -L${PLATFORM_LIBGCC}
	
clean:
	$(RM) *.o *.i *.bin
	$(RM) *.elf *~ *.log
	
	
