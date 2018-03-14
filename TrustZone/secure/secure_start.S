#define cpsr_mode_use	(0x10)
#define cpsr_mode_fiq	(0x11)
#define cpsr_mode_irq	(0x12)
#define cpsr_mode_svc	(0x13)
#define cpsr_mode_mon	(0x16)
#define cpsr_mode_abt	(0x17)
#define cpsr_mode_und	(0x1b)
#define cpsr_mode_sys	(0x1F)

#define cpsr_irq_bit	(0x80)
#define cpsr_fiq_bit	(0x40)
#define cpsr_asyc_bit	(0x100)
#define SVC_MODE_STACK_BASE (0x5000)


.macro GET_CPUID treg
  mrc p15, 0, \treg, c0, c0, 5
  and \treg, \treg, #0x03
.endm

.global NS_vector
.align 5
NS_vector:
    NOP		@ reset
    NOP		@ undefined instruction
    NOP		@ supervisor call
    NOP		@ prefetch abort
    NOP		@ data abort
    NOP		@ not used
    NOP		@ IRQ
    NOP		@ FIQ


.text
.arm
.align 4
.global _start_secure
_start_secure:
    GET_CPUID r0
    cmp r0, #0
    blne gotosleep

#define FIQ_MODE_STACK_BASE 0x100
#define IRQ_MODE_STACK_BASE 0x200 
#define ABT_MODE_STACK_BASE 0x300
#define UND_MODE_STACK_BASE 0x400
#define SYS_MODE_STACK_BASE 0x500
#define MON_MODE_STACK_BASE 0x4000


@ Initialize stacks for some modes
@ set FIQ stack
	cpsid   if, #cpsr_mode_fiq
	ldr     sp, =FIQ_MODE_STACK_BASE

@ set IRQ stack
	cpsid   if, #cpsr_mode_irq
	ldr     sp, =IRQ_MODE_STACK_BASE

@ set ABT stack
	cpsid   if, #cpsr_mode_abt
	ldr     sp, =ABT_MODE_STACK_BASE

@ set UND stack
	cpsid   if, #cpsr_mode_und
	ldr     sp, =UND_MODE_STACK_BASE

@ set user/system stack
	cpsid   if, #cpsr_mode_sys
	ldr     sp, =SYS_MODE_STACK_BASE

@ set monitor stack
	cpsid   if, #cpsr_mode_mon
	ldr     sp, =MON_MODE_STACK_BASE

@ set SVC stack
	cpsid   if, #cpsr_mode_svc
	ldr     sp, =SVC_MODE_STACK_BASE

@ bank System Control Register
	mrc     p15, 0, r0, c1, c0, 0
	bic     r0, r0, #(0x1  <<13)    /* base address 0x00000000 */
	bic     r0, r0, #(0x1  <<12)    /* disable I Cache */
	bic     r0, r0, #(0x1  <<2)     /* disable D Cache */
	bic     r0, r0, #(0x1  <<0)     /* disable MMU */
	orr     r0, r0, #(0x1  <<14)    /* enable RR */
	mcr     p15, 0, r0, c1, c0, 0
	
@ bank Auxillary control register
	mrc     p15, 0, r0, c1, c0, 1

    @disable cache & table type
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #0x00004	@disable data cache
    bic r0, r0, #0x01000	@disable instruction cache
    mcr p15, 0, r0, c1, c0, 0

    @invalidate cahces
    @bl invalidatecaches

    @invalidate TLBs
    mov r0, #0x0
    mcr p15, 0, r0, c8, c7, 0

    @set up domain access control reg
    @mov r0, #0x01
    @mcr p15, 0, r0, c3, c0, 0
	
    bl secure_main
	
    b .
LED_ON:
    ldr r0, =0xe0001030
    mov r1, #0x61
    str r1, [r0]
    bx lr

gotosleep:
    wfi 
    b gotosleep
    bx lr
