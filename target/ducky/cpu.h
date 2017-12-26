/*
 * Ducky virtual CPU header.
 *
 * Copyright (c) 2017 Milos Prchlik <happz@happz.cz>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DUCKY_CPU_H
#define DUCKY_CPU_H

//#define DEBUG_DUCKY_GEN

#include "qemu-common.h"
#include "exec/cpu-defs.h"
#include "hw/core/cpu.h"
#include "qemu/log.h"

#define TYPE_DUCKY_CPU "ducky-cpu"

#define DUCKY_CPU_TYPE_SUFFIX "-" TYPE_DUCKY_CPU
#define DUCKY_CPU_TYPE_NAME(name) (name DUCKY_CPU_TYPE_SUFFIX)
#define CPU_RESOLVING_TYPE TYPE_DUCKY_CPU

#define DUCKY_CPU_CLASS(klass) \
    OBJECT_CLASS_CHECK(DuckyCPUClass, (klass), TYPE_DUCKY_CPU)
#define DUCKY_CPU(obj) \
    OBJECT_CHECK(DuckyCPU, (obj), TYPE_DUCKY_CPU)
#define DUCKY_CPU_GET_CLASS(obj) \
    OBJECT_GET_CLASS(DuckyCPUClass, (obj), TYPE_DUCKY_CPU)

typedef struct DuckyCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    void (*parent_reset)(CPUState *cpu);
} DuckyCPUClass;

#define TARGET_INSN_START_EXTRA_WORDS 0

#define TARGET_WORD_WIDTH 2
#define TARGET_WORD_SIZE (1 << TARGET_WORD_WIDTH)

//#define ALIGNED_ONLY

/* Interrupt */
#define DUCKY_NR_IRQS  16

enum {
  DUCKY_IRQ_TIMER = 1,
  DUCKY_IRQ_UART = 2,
  DUCKY_INT_CPUSTATE = 79
};

#define DEFAULT_BOOTROM_ADDRESS 0x00020000
#define DEFAULT_BOOTROM_SIZE    0x00040000
#define DEFAULT_PT_ADDRESS 0x00010000
#define DEFAULT_EVT_ADDRESS 0x00000000

#define DUCKY_OPCODE_MAX 63

enum {
  DUCKY_SIS_CORE = 0,
  DUCKY_SIS_MATH = 1,
  DUCKY_SIS_MAX = 1
};

enum {
  DUCKY_CTR_REG_CPUID = 0,
  DUCKY_CTR_REG_EVT = 1,
  DUCKY_CTR_REG_PT = 2,
  DUCKY_CTR_REG_FLAGS = 3
};

#define REG_FP 30
#define REG_SP 31
#define REG_SPECIAL (REG_FP)

#define SIGNED_MASK 0x80000000

#define DUCKY_MATH_STACK_SIZE 8

/* Branch flags */
enum {
  BRANCH_EQUAL = 0,
  BRANCH_ZERO = 1,
  BRANCH_OVERFLOW = 2,
  BRANCH_SIGN = 3,
  BRANCH_TRIVIALS = 3,
  BRANCH_LT = 4,
  BRANCH_GT = 5
};

/* Control flags */
enum {
  CTR_FLAG_PT_ENABLED = (1 << 0),
  CTR_FLAG_JIT = (1 << 1),
  CTR_FLAG_VMDEBUG = (1 << 2)
};

/* Status flags */
enum {
  FLAG_PRIVILEGED = (1 << 0),
  FLAG_HWINT_ALLOWED = (1 << 1),
  FLAG_EQUAL = (1 << 2),
  FLAG_ZERO = (1 << 3),
  FLAG_OVERFLOW = (1 << 4),
  FLAG_SIGN = (1 << 5)
};

/* Exceptions indices */
enum {
  EXCP_INVALID_OPCODE = 16,
  EXCP_DIVIDE_BY_ZERO = 17,
  EXCP_UNALIGNED_ACCESS = 19,
  EXCP_PRIVILEGED_INSTR = 20,
  EXCP_DOUBLE_FAULT = 21,
  EXCP_MEMORY_ACCESS = 22,
  EXCP_REGISTER_ACCESS = 23,
  EXCP_INVALID_EXCP = 24,
  EXCP_COPRO_ERROR = 25
};

typedef struct {
  const char *name;
  uint32_t    frequency;
  uint32_t    enabled;
  int64_t     clock_offset;
  QEMUTimer * timer;
  qemu_irq    irq;
} DuckyCPUTimer;

typedef struct CPUDuckyState {
    target_ulong regs[32];

    target_ulong pc;          /* Program counter */

    target_ulong pt_address;  /* Page table address */
    target_ulong evt_address; /* EVT address */
    target_ulong ctr_flags;   /* Control Flags */

    target_ulong cr0;
    target_ulong cr1;
    target_ulong cr2;

    uint32_t privileged;
    uint32_t hwint_enabled;
    uint32_t equal;
    uint32_t zero;
    uint32_t overflow;
    uint32_t sign;

    uint32_t cc_result;
    uint32_t cc_flags_valid;

    uint32_t sis_index;

    uint32_t pending_interrupts;

    uint32_t pt_enabled;
    uint32_t jit_enabled;
    uint32_t vmdebug;

    uint64_t math_stack[DUCKY_MATH_STACK_SIZE];
    int math_stack_ptr;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    DuckyCPUTimer *tick_timer;
    qemu_irq *irqs;
} CPUDuckyState;

typedef struct DuckyCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/
    CPUNegativeOffsetState neg;
    CPUDuckyState env;
} DuckyCPU;

static inline DuckyCPU *ducky_env_get_cpu(CPUDuckyState *env)
{
    return container_of(env, DuckyCPU, env);
}

#define ENV_GET_CPU(e) CPU(ducky_env_get_cpu(e))

#define ENV_OFFSET offsetof(DuckyCPU, env)

static inline uint32_t cpu_get_flags(CPUState *cs)
{
  DuckyCPU *cpu = DUCKY_CPU(cs);
  CPUDuckyState *env = &cpu->env;

  return   (env->privileged << 0)
         | (env->hwint_enabled << 1)
         | (env->equal << 2)
         | (env->zero << 3)
         | (env->overflow << 4)
         | (env->sign << 5);
}

static inline void cpu_set_flags(CPUState *cs, uint32_t flags)
{
  DuckyCPU *cpu = DUCKY_CPU(cs);
  CPUDuckyState *env = &cpu->env;

  env->privileged = (flags & 0x00000001 ? 1 : 0);
  env->hwint_enabled = (flags & 0x00000002 ? 1 : 0);
  env->equal = (flags & 0x00000004 ? 1 : 0);
  env->zero = (flags & 0x00000008 ? 1 : 0);
  env->overflow = (flags & 0x00000010 ? 1 : 0);
  env->sign = (flags & 0x00000020 ? 1 : 0);
}

void cpu_ducky_list(void);
void ducky_cpu_do_interrupt(CPUState *cpu);
bool ducky_cpu_exec_interrupt(CPUState *cpu, int int_req);
void ducky_cpu_dump_state(CPUState *cs, FILE *f, int flags);
void ducky_translate_init(void);

int cpu_ducky_signal_handler(int host_signum, void *pinfo, void *puc);

#define cpu_list cpu_ducky_list
#define cpu_signal_handler cpu_ducky_signal_handler

#ifndef CONFIG_USER_ONLY
extern const struct VMStateDescription vmstate_ducky_cpu;

/* hw/ducky/cpu_pic.c */
extern qemu_irq *ducky_cpu_pic_init(DuckyCPU *cpu);

/* hw/ducky_timer.c */
void cpu_ducky_clock_init(DuckyCPU *cpu);
uint32_t cpu_ducky_count_get(DuckyCPU *cpu);
void cpu_ducky_count_set(DuckyCPU *cpu, uint32_t val);
void cpu_ducky_count_update(DuckyCPU *cpu);
void cpu_ducky_timer_update(DuckyCPU *cpu);
void cpu_ducky_count_start(DuckyCPU *cpu);
void cpu_ducky_count_stop(DuckyCPU *cpu);

void cpu_ducky_mmu_init(DuckyCPU *cpu);
int cpu_ducky_get_phys_nommu(DuckyCPU *cpu,
                                hwaddr *physical,
                                int *prot, target_ulong address, int rw);
int cpu_ducky_get_phys_code(DuckyCPU *cpu,
                               hwaddr *physical,
                               int *prot, target_ulong address, int rw);
int cpu_ducky_get_phys_data(DuckyCPU *cpu,
                               hwaddr *physical,
                               int *prot, target_ulong address, int rw);

bool ducky_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr);

#endif

#define cpu_init(cpu_model) cpu_generic_init(TYPE_DUCKY_CPU, cpu_model)

static inline void cpu_get_tb_cpu_state(CPUDuckyState *env, target_ulong *pc, target_ulong *cs_base, uint32_t *flags)
{
  //DuckyCPU *cpu = ducky_env_get_cpu(env);
  //CPUState *cs = CPU(cpu);

  //fprintf(qemu_logfile, "cpu_get_tb_cpu_state:\n");
  //qemu_log_flush();

  //ducky_cpu_dump_state(cs, qemu_logfile, 0);

  *pc = env->pc;
  *cs_base = 0;
  *flags = 0;
}

/*
 * Instruction encoding
 */
static const char * const regnames[] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "fp", "sp",
};

#ifdef DEBUG_DUCKY_GEN
static const char * const mnemonics[] = {
  "nop", "lw", "ls", "lb", "stw", "sts", "stb", "cas", "la",
  "li", "liu", "mov", "swp", "int", "retint", "call", "ret",
  "cli", "sti", "rst", "hlt", "idle", "lpm", "ipi", "push",
  "pop", "inc", "dec", "add", "sub", "mul", "div", "udiv",
  "mod", "and", "or", "xor", "not", "shl", "shr", "shrs", NULL, NULL,
  NULL, NULL, NULL, "j", "cmp", "cmpu", "set", "br", "sel",
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "ctr",
  "ctw", "fptc", "sis"
};
/*
static const char * const cond_flags[] = {
  "eq", "zero", "overflow", "sign", "...", "..."
};
*/
#endif

struct __attribute__((__packed__)) encoding_opcode {
  uint32_t opcode:6;
};

struct __attribute__((__packed__)) encoding_R {
  uint32_t opcode:6;
  uint32_t reg1:5;
  uint32_t reg2:5;
  uint32_t immediate_flag:1;
  uint32_t immediate:15;
};

struct __attribute__((__packed__)) encoding_C {
  uint32_t opcode:6;
  uint32_t reg:5;
  uint32_t flag:3;
  uint32_t value:1;
  uint32_t immediate_flag:1;
  uint32_t immediate: 16;
};

struct __attribute__((__packed__)) encoding_S {
  uint32_t opcode:6;
  uint32_t reg1:5;
  uint32_t reg2:5;
  uint32_t flag:3;
  uint32_t value:1;
  uint32_t immediate_flag:1;
  uint32_t immediate: 11;
};

struct __attribute__((__packed__)) encoding_I {
  uint32_t opcode:6;
  uint32_t reg:5;
  uint32_t immediate_flag:1;
  uint32_t immediate: 20;
};

struct __attribute__((__packed__)) encoding_A {
  uint32_t opcode:6;
  uint32_t reg1:5;
  uint32_t reg2:5;
  uint32_t reg3:5;
};

union encoding {
  uint32_t raw;
  struct encoding_opcode O;
  struct encoding_R R;
  struct encoding_C C;
  struct encoding_S S;
  struct encoding_I I;
  struct encoding_A A;
};

#define __ENC(_type, _member) struct _type *ENC = &dc->instr._member
#define R_ENC() __ENC(encoding_R, R);
#define C_ENC() __ENC(encoding_C, C);
#define S_ENC() __ENC(encoding_S, S);
#define I_ENC() __ENC(encoding_I, I);
#define A_ENC() __ENC(encoding_A, A);

#define R_SEXT(_encoding) (sextract32((_encoding)->immediate, 0, 15))
#define R_EXT(_encoding)  ( extract32((_encoding)->immediate, 0, 15))
#define C_SEXT(_encoding) (sextract32((_encoding)->immediate, 0, 16))
#define C_EXT(_encoding)  ( extract32((_encoding)->immediate, 0, 16))
#define I_SEXT(_encoding) (sextract32((_encoding)->immediate, 0, 20))
#define I_EXT(_encoding)  ( extract32((_encoding)->immediate, 0, 20))
#define S_SEXT(_encoding) (sextract32((_encoding)->immediate, 0, 11))
#define S_EXT(_encoding)  ( extract32((_encoding)->immediate, 0, 11))

typedef CPUDuckyState CPUArchState;
typedef DuckyCPU ArchCPU;

#include "exec/cpu-all.h"

static inline int cpu_mmu_index(CPUDuckyState *env, bool ifetch)
{
  return 0;
}

static inline AddressSpace *cpu_address_space(CPUState *cs)
{
  return cpu_get_address_space(cs, 0);
}

static inline void cpu_stw(CPUState *cs, target_ulong addr, uint32_t val)
{
  AddressSpace *as = cpu_address_space(cs);

  address_space_stl(as, addr, val, MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t cpu_ldl(CPUState *cs, target_ulong addr)
{
  AddressSpace *as = cpu_address_space(cs);

  return address_space_ldl(as, addr, MEMTXATTRS_UNSPECIFIED, NULL);
}

#endif /* DUCKY_CPU_H */
