/*
 * QEMU Ducky CPU
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

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qapi/error.h"
#include "cpu.h"
#include "qemu-common.h"
#include "exec/exec-all.h"

#include "mmu.h"

#define P(...) do { info->fprintf_func(info->stream, ##__VA_ARGS__); } while(0)
#define REG(_reg) regnames[_reg]

static void __disas_R(disassemble_info *info, bfd_vma addr, struct encoding_R *R, const char *mnemonic)
{
  if (R->immediate_flag == 1) {
    P("%s %s, 0x%08X", mnemonic, REG(R->reg1), R_SEXT(R));
    return;
  }

  P("%s %s, %s", mnemonic, REG(R->reg1), REG(R->reg2));
}

static void __disas_R2_r_m(disassemble_info *info, bfd_vma addr, struct encoding_R *R, const char *mnemonic)
{
  P("%s %s, %s", mnemonic, REG(R->reg1), REG(R->reg2));

  if (R->immediate_flag == 1)
    P("[%X]", R_SEXT(R));
}

static void __disas_R2_m_r(disassemble_info *info, bfd_vma addr, struct encoding_R *R, const char *mnemonic)
{
  P("%s %s", mnemonic, REG(R->reg2));
  if (R->immediate_flag == 1)
    P("[%X]", R_SEXT(R));

  P(", %s", REG(R->reg1));
}

static void __disas_I(disassemble_info *info, bfd_vma addr, struct encoding_I *I, const char *mnemonic, int imm_addr)
{
  if (I->immediate_flag == 1) {
    uint32_t simm = I_SEXT(I);

    if (imm_addr)
      simm <<= 2;

    P("%s 0x%08X (0x%08X)", mnemonic, simm, (uint32_t)addr + 4 + simm);
    return;
  }

  P("%s %s", mnemonic, REG(I->reg));
}

static void __disas_I0(disassemble_info *info, bfd_vma addr, struct encoding_I *I, const char *mnemonic)
{
  P("%s", mnemonic);
}

static void __disas_I1_ri(disassemble_info *info, bfd_vma addr, struct encoding_I *I, const char *mnemonic,
                          int imm_addr, int pcrel)
{
  if (I->immediate_flag == 1) {
    uint32_t simm = I_SEXT(I);

    if (imm_addr)
      simm <<= 2;

    P("%s 0x%08X", mnemonic, simm);

    if (pcrel)
      P(" (0x%08X)", (uint32_t)addr + 4 + simm);
  } else {
    P("%s %s", mnemonic, REG(I->reg));
  }
}
static void __disas_I2_r_i(disassemble_info *info, bfd_vma addr, struct encoding_I *I, const char *mnemonic,
                           int imm_addr, int pcrel)
{
  uint32_t simm = I_SEXT(I);

  if (imm_addr)
    simm <<= 2;

  P("%s %s, 0x%08X", mnemonic, REG(I->reg), simm);

  if (pcrel)
    P(" (0x%08X)", (uint32_t)addr + 4 + simm);
}

static void __disas_BRANCH(disassemble_info *info, bfd_vma addr, struct encoding_C *C)
{
  static const char *__branch_or_not[] = { "n", "" };

  if (C->flag >= 0 && C->flag <= 3) {
    static const char *__branch_simple_flags[] = { "e", "z", "o", "s" };

    P("b%s%s ", __branch_or_not[C->value == 0 ? 0 : 1], __branch_simple_flags[C->flag]);
  } else if (C->flag == 4) {
    P(C->value == 1 ? "bl" : "bge");
  } else {
    P(C->value == 1 ? "bg" : "ble");
  }

  if (C->immediate_flag == 1) {
    uint32_t offset = C_SEXT(C) << 2;

    P(" 0x%08X (0x%08X)", offset, (uint32_t)addr + 4 + offset);
  } else {
    P("%s", REG(C->reg));
  }
}
  
static int ducky_print_insn(bfd_vma pc, disassemble_info *info)
{
  static const char *prefix = "OBJD-T";
  static const char *mnemonics[] = {
    // 0
    "nop",
    "lw",
    "ls",
    "lb",
    "stw",
    // 5
    "sts",
    "stb",
    "cas",
    "la",
    "li",
    // 10
    "liu",
    "mov",
    NULL,
    "int",
    "retint",
    // 15
    "call",
    "ret",
    NULL,
    "sti",
    NULL,
    // 20
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    // 25
    "pop",
    "inc",
    "dec",
    "add",
    "sub",
    // 30
    NULL,
    "ret",
    NULL,
    NULL,
    "and",
    // 35
    "or",
    "xor",
    NULL,
    NULL,
    NULL,
    // 40
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    // 45
    NULL,
    NULL,
    "cmp",
    "cmpu",
    NULL
  };

  union encoding *instr;
  int i, n = info->buffer_length;
  uint8_t *buf = g_malloc(n);
  uint32_t *instr_buf = (uint32_t *)buf;

  info->read_memory_func(pc, buf, n, info);

#define disas_R(_mnemonic) do { __disas_R(info, pc + i, &instr->R, (_mnemonic)); } while(0)
#define disas_I(_mnemonic, _imm_addr) do { __disas_I(info, pc + i, &instr->I, (_mnemonic), _imm_addr); } while(0)
#define disas_BRANCH() do { __disas_BRANCH(info, pc + i, &instr->C); } while(0)

#define disas_R2_r_ri() do { \
  __disas_R(info, pc + i, &instr->R, mnemonics[instr->O.opcode]); \
} while(0)

#define disas_R2_r_m() do { \
  __disas_R2_r_m(info, pc + i, &instr->R, mnemonics[instr->O.opcode]); \
} while(0)

#define disas_R2_m_r() do { \
  __disas_R2_m_r(info, pc + i, &instr->R, mnemonics[instr->O.opcode]); \
} while(0)

#define disas_R2_r_r() do { \
  __disas_R(info, pc + i, &instr->R, mnemonics[instr->O.opcode]); \
} while(0)

#define disas_I0() do { __disas_I0(info, pc + i, &instr->I, mnemonics[instr->O.opcode]); } while(0)
#define disas_I1_ri(_imm_addr, _pcrel) do { \
  __disas_I1_ri(info, pc + i, &instr->I, mnemonics[instr->O.opcode], _imm_addr, _pcrel); \
} while(0)

#define disas_I2_r_i(_imm_addr, _pcrel) do { \
  __disas_I2_r_i(info, pc + i, &instr->I, mnemonics[instr->O.opcode], _imm_addr, _pcrel); \
} while(0)

  for (i = 0; i < n / 4; ++i) {
    info->fprintf_func(info->stream, "\n%s: 0x%08X: 0x%08X ", prefix, (uint32_t)pc + i, instr_buf[i]);

    instr = (union encoding *)&(instr_buf[i]);

    switch(instr->O.opcode) {
      case 1:
      case 2:
      case 3:
        disas_R2_r_m();
        break;

      case 4:
      case 5:
      case 6:
        disas_R2_m_r();
        break;

      case 8: // la
        disas_I2_r_i(0, 1);
        break;

      case 9: // li
      case 10: // liu
        disas_I2_r_i(0, 0);
        break;

      case 11: // mov
        disas_R2_r_r();
        break;

      case 15: // call
        disas_I1_ri(1, 1);
        break;

      case 14: // retint
      case 16: // ret
      case 18: //sti
        disas_I0();
        break;

      case 20:
        disas_I("hlt", 0);
        break;

      case 25:
        disas_I("pop", 0);
        break;

      case 24:
        disas_I("push", 0);
        break;

      case 26:
        disas_R("inc");
        break;

      case 27:
        disas_R("dec");
        break;

      case 28: // add
      case 29: // sub
      case 34: // and
      case 35: // or
      case 36: // xor
      case 47: // cmp
      case 48: // cmpu
        disas_R2_r_ri();
        break;

      case 37:
        disas_I("not", 0);
        break;

      case 46:
        disas_I("j", 0);
        break;

      case 50:
        disas_BRANCH();
        break;

      case 60:
        disas_R("ctr");
        break;

      case 61:
        disas_R("ctw");
        break;

      default:
        P("<%u>", instr->O.opcode);
        break;
    }
  }

  g_free(buf);

  return n;
}

#undef P
#undef REG

static void ducky_disas_set_info(CPUState *cs, disassemble_info *info)
{
  info->print_insn = ducky_print_insn;
  info->cap_insn_unit = 4;
  info->cap_insn_split = 4;
}

static void ducky_cpu_set_pc(CPUState *cs, vaddr value)
{
    DuckyCPU *cpu = DUCKY_CPU(cs);

    cpu->env.pc = value;
}

static bool ducky_cpu_has_work(CPUState *cs)
{
  return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

/* CPUClass::reset() */
static void ducky_cpu_reset(CPUState *s)
{
    DuckyCPU *cpu = DUCKY_CPU(s);
    DuckyCPUClass *occ = DUCKY_CPU_GET_CLASS(cpu);

    occ->parent_reset(s);

    memset(&cpu->env, 0, offsetof(CPUDuckyState, end_reset_fields));

    cpu->env.pc = DEFAULT_BOOTROM_ADDRESS;
    cpu->env.pt_address = DEFAULT_PT_ADDRESS;
    cpu->env.evt_address = DEFAULT_EVT_ADDRESS;
    cpu->env.privileged = 1;
    cpu->env.pt_enabled = 0;
    cpu->env.jit_enabled = 1;
    cpu->env.vmdebug = 0;
    s->exception_index = -1;

    if (cpu->env.tick_timer)
      cpu->env.tick_timer->enabled = 1;
}

static void ducky_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    DuckyCPUClass *occ = DUCKY_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    occ->parent_realize(dev, errp);
}

static void ducky_cpu_initfn(Object *obj)
{
    DuckyCPU *cpu = DUCKY_CPU(obj);

    cpu_set_cpustate_pointers(cpu);
}

/* CPU models */

static ObjectClass *ducky_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    typename = g_strdup_printf(DUCKY_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    if (oc != NULL && (!object_class_dynamic_cast(oc, TYPE_DUCKY_CPU) ||
                       object_class_is_abstract(oc))) {
        return NULL;
    }
    return oc;
}

static void ducky_any_initfn(Object *obj)
{
}

static void ducky_cpu_class_init(ObjectClass *oc, void *data)
{
    DuckyCPUClass *occ = DUCKY_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(occ);
    DeviceClass *dc = DEVICE_CLASS(oc);

    occ->parent_realize = dc->realize;
    dc->realize = ducky_cpu_realizefn;

    occ->parent_reset = cc->reset;
    cc->reset = ducky_cpu_reset;

    cc->class_by_name = ducky_cpu_class_by_name;
    cc->has_work = ducky_cpu_has_work;
    cc->do_interrupt = ducky_cpu_do_interrupt;
    cc->cpu_exec_interrupt = ducky_cpu_exec_interrupt;
    cc->dump_state = ducky_cpu_dump_state;
    cc->set_pc = ducky_cpu_set_pc;
    cc->get_phys_page_debug = ducky_cpu_get_phys_page_debug;
    dc->vmsd = &vmstate_ducky_cpu;
    cc->tlb_fill = ducky_cpu_tlb_fill;
    cc->tcg_initialize = ducky_translate_init;
    cc->disas_set_info = ducky_disas_set_info;
}

/* Sort alphabetically by type name, except for "any". */
static gint ducky_cpu_list_compare(gconstpointer a, gconstpointer b)
{
    ObjectClass *class_a = (ObjectClass *)a;
    ObjectClass *class_b = (ObjectClass *)b;
    const char *name_a, *name_b;

    name_a = object_class_get_name(class_a);
    name_b = object_class_get_name(class_b);

    if (strcmp(name_a, "any-" TYPE_DUCKY_CPU) == 0)
        return 1;

    if (strcmp(name_b, "any-" TYPE_DUCKY_CPU) == 0)
        return -1;

    return strcmp(name_a, name_b);
}

static void ducky_cpu_list_entry(gpointer data, gpointer user_data)
{
    ObjectClass *oc = data;
    const char *typename = object_class_get_name(oc);
    char *name;

    name = g_strndup(typename, strlen(typename) - strlen(DUCKY_CPU_TYPE_SUFFIX));
    qemu_printf("  %s\n", name);
    g_free(name);
}

void cpu_ducky_list(void)
{
  GSList *list;

  list = object_class_get_list(TYPE_DUCKY_CPU, false);
  list = g_slist_sort(list, ducky_cpu_list_compare);
  g_slist_foreach(list, ducky_cpu_list_entry, NULL);
  g_slist_free(list);
}

#define DEFINE_DUCKY_CPU_TYPE(cpu_model, initfn) \
    {                                               \
        .parent = TYPE_DUCKY_CPU,                \
        .instance_init = initfn,                    \
        .name = DUCKY_CPU_TYPE_NAME(cpu_model),  \
    }

static const TypeInfo ducky_cpus_type_infos[] = {
    { /* base class should be registered first */
        .name = TYPE_DUCKY_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(DuckyCPU),
        .instance_init = ducky_cpu_initfn,
        .abstract = true,
        .class_size = sizeof(DuckyCPUClass),
        .class_init = ducky_cpu_class_init,
    },
    DEFINE_DUCKY_CPU_TYPE("ducky", ducky_any_initfn),
    DEFINE_DUCKY_CPU_TYPE("any", ducky_any_initfn),
};

DEFINE_TYPES(ducky_cpus_type_infos)
