#ifndef _TIMER_H
#define _TIMER_H

#define CONFIG_SYS_HZ                   1000

#define SCUTIMER_CONTROL_PRESCALER_MASK 0x0000FF00 /* Prescaler */
#define SCUTIMER_CONTROL_PRESCALER_SHIFT        8
#define SCUTIMER_CONTROL_AUTO_RELOAD_MASK       0x00000002 /* Auto-reload */
#define SCUTIMER_CONTROL_ENABLE_MASK            0x00000001 /* Timer enable */

#define ZYNQ_SCUTIMER_BASEADDR          0xF8F00600
#define CONFIG_SYS_TIMER_COUNTER        (CONFIG_SYS_TIMERBASE + 0x4)
#define CONFIG_SYS_TIMERBASE            ZYNQ_SCUTIMER_BASEADDR


#define TIMER_LOAD_VAL 0xFFFFFFFF
#define TIMER_PRESCALE 255

struct scu_timer {
        unsigned int load; /* Timer Load Register */
	unsigned int counter; /* Timer Counter Register */
	unsigned int control; /* Timer Control Register */
};

int timer_init(void);
unsigned long timer_get_us(void);
unsigned long get_timer(unsigned int base);

int gtimer_init(void);
unsigned long long gtimer_read_counter(void);
unsigned long long gget_timer(unsigned int base);
unsigned long long  gtimer_get_us(void);


#endif
