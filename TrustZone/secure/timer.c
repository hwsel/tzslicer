#include "uart.h"
#include "timer.h"
#include "printf.h"
#include "common.h"


# define do_div(n,base) ({                              \
	unsigned int __base = (base);                       \
	unsigned int __rem;                                 \
	(void)(((typeof((n)) *)0) == ((unsigned long long *)0));  \
	if (((n) >> 32) == 0) {                 \
		__rem = (unsigned int)(n) % __base;         \
		(n) = (unsigned int)(n) / __base;           \
	} else                                          \
		 __rem = __div64_32(&(n), __base);       \
	__rem;                                          \
})

static struct scu_timer *timer_base =(struct scu_timer *)ZYNQ_SCUTIMER_BASEADDR;

unsigned long timer_read_counter(void)
{
	return ~readl(CONFIG_SYS_TIMER_COUNTER);
}

unsigned long long get_ticks(void)
{
	unsigned long timebase_l = 0;
	unsigned long timebase_h = 0;
	unsigned long now = timer_read_counter();

	/* increment tbu if tbl has rolled over */
	if (now < timebase_l)
		timebase_h++;
	timebase_l = now;
	return ((unsigned long long)timebase_h << 32) | timebase_l;
}

/* Returns time in milliseconds */
static unsigned long long tick_to_time(unsigned long long tick)
{
	unsigned long div = 0x13de43;	//get_tbclk();

	tick *= CONFIG_SYS_HZ;
	do_div(tick, div);
	return tick;
}

unsigned long get_timer(unsigned int base)
{
	return tick_to_time(get_ticks()) - base;
}

unsigned long timer_get_us(void)
{	
	return tick_to_time(get_ticks() * 1000);
}


int timer_init(void)
{
	unsigned int tmp_value = 0;

	const unsigned int emask = SCUTIMER_CONTROL_AUTO_RELOAD_MASK |
		(TIMER_PRESCALE << SCUTIMER_CONTROL_PRESCALER_SHIFT) |
		SCUTIMER_CONTROL_ENABLE_MASK;


	/* Load the timer counter register */
	writel(0xFFFFFFFF, &timer_base->load);

	tmp_value = readl(&timer_base->control);
	tmp_value &= (~SCUTIMER_CONTROL_PRESCALER_MASK);
	tmp_value |= emask;
	writel(tmp_value,&timer_base->control);

	return 0;
}

#define GTIMER_ENABLE  (1 << 0)
#define GTIMER_PRESCALER_SHIFT	(8)
#define GTIMER_PRESCALE	255
#define GTIMER_BASE_ADDR 0xF8F00200

int gtimer_init(void)
{
	unsigned int tmp_value = 0;
	const unsigned int emask = (GTIMER_PRESCALE << GTIMER_PRESCALER_SHIFT) | (GTIMER_ENABLE);

	writel(emask, GTIMER_BASE_ADDR + 0x8);
	return 0;
}

unsigned long long gtimer_read_counter(void)
{
	unsigned int counter_l = 0;
	unsigned int counter_h_0 = 0;
	unsigned int counter_h_1 = 0;
	unsigned long long counter = 0;

	counter_h_0 = readl(GTIMER_BASE_ADDR + 0x4);
	counter_l = readl(GTIMER_BASE_ADDR);
	counter_h_1 = readl(GTIMER_BASE_ADDR + 0x4);

	if(counter_h_0 != counter_h_1) {
		counter_l = readl(GTIMER_BASE_ADDR);
	}
	counter_h_0 = readl(GTIMER_BASE_ADDR + 0x4);
	
	counter	= ((unsigned long long)(counter_h_0 << 32)) | counter_l;
	
	return counter;
}

unsigned long long gget_timer(unsigned int base)
{
	return tick_to_time(gtimer_read_counter()) - base;
}

unsigned long long  gtimer_get_us(void)
{
	return tick_to_time(gtimer_read_counter() * 1000);
}

