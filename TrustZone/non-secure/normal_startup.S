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
.align 5
.global _start_normal
_start_normal:
    GET_CPUID r0
    cmp r0, #0
    blne gotosleep

    @setup stacks
    msr cpsr_c, #(cpsr_mode_svc | cpsr_irq_bit | cpsr_fiq_bit) @sys mode, fiq and irq disable


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

    @set BVAR
    ldr r0, = NS_vector
    mcr p15, 0, r0, c12, c0, 0	@ write current world VBAR

    ldr sp, =0x00022000

    bl normal_main
    b .

gotosleep:
    wfi
    b gotosleep
    bx lr
