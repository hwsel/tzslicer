
#define writel(v,a)   (*(volatile unsigned int *)(a) = (v))
#define readl(a)         (*(volatile unsigned int *)(a))


#define Asm __asm__ volatile
#define CP15_SET_NSACR(x)       Asm("mcr p15, 0, %0, c1, c1, 2"::"r"(x))
#define CP15_SET_CPACR(x)       Asm("mcr p15, 0, %0, c1, c0, 2"::"r"(x))
#define CP15_GET_SCR(x)         Asm("mrc p15, 0, %0, c1, c1, 0":"=r"(x))
#define CP15_SET_SCR(x)         Asm("mcr p15, 0, %0, c1, c1, 0"::"r"(x))
