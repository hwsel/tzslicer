.phony: all

all: secure.bin
ARMGNU ?= arm-xilinx-linux-gnueabi

CC  = $(ARMGNU)-gcc
LD  = $(ARMGNU)-ld
COPY= $(ARMGNU)-objcopy
DUMP= $(ARMGNU)-objdump
PLATFORM_LIBGCC = /opt/CodeSourcery/Sourcery_CodeBench_Lite_for_Xilinx_GNU_Linux/lib/gcc/arm-xilinx-linux-gnueabi/4.6.1

secure.bin: secure.elf
	$(COPY) -O binary $< secure-origin.bin
	$(DUMP) -D $< > dump_secure.log
	$(COPY) -I binary -O binary --pad-to 0x4000 --gap-fill=0x00 secure-origin.bin $@
	
secure.elf: secure_start.S monitor.S s_boot.c
	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -Os -nostdlib secure_start.S
#	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -Os -nostdlib secure_startup.S
	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -Os -nostdlib s_boot.c printf.c timer.c uart.c
	$(CC) -c -mcpu=cortex-a9 -mlittle-endian -msoft-float -Wall -Os -nostdlib monitor.S
	$(LD)  -nostartfiles -static -nostdlib -T x-load.lds secure_start.o s_boot.o monitor.o printf.o timer.o uart.o -o secure.elf  -lgcc -L${PLATFORM_LIBGCC}
#	$(LD)  -nostartfiles -static -nostdlib -T x-load.lds secure_start.o s_boot.o monitor.o printf.o timer.o -o secure.elf  -lgcc -L${PLATFORM_LIBGCC}
#	$(LD) -T x-load.lds secure_start.o s_boot.o monitor.o printf.o timer.o -o secure.elf # -lgcc -L${PLATFORM_LIBGCC}

clean:
	$(RM) *.o *.i *.bin
	$(RM) *.elf *~ *.log
	
	
