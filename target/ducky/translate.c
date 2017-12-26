/*
 * Ducky translation
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
#include "cpu.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "tcg/tcg-op.h"
#include "qemu-common.h"
#include "qemu/log.h"
#include "qemu/bitops.h"
#include "exec/cpu_ldst.h"
#include "exec/translator.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "trace-tcg.h"
#include "exec/log.h"

/* is_jmp field values */
#define DISAS_JUMP    DISAS_TARGET_0 /* only pc was modified dynamically */
#define DISAS_UPDATE  DISAS_TARGET_1 /* cpu state was modified dynamically */
#define DISAS_TB_JUMP DISAS_TARGET_2

/*
static const char *tb_jump[] = {
  "DISAS_NEXT",
  "DISAS_TOO_MANY",
  "DISAS_NORETURN",
  "DISAS_JUMP",
  "DISAS_UPDATE",
  "DISAS_TB_JUMP"
};
*/

#define DEBUG(msg, ...) do { qemu_log("* GEN: 0x%08X: " msg "\n", (dc->base.pc_next - 4), ##__VA_ARGS__); } while(0)

#ifdef DEBUG_DUCKY_GEN
#define DEBUG_GEN(msg, ...) do { qemu_log("* GEN: 0x%08X: " msg "\n", (dc->base.pc_next - 4), ##__VA_ARGS__); } while(0)
#else
#define DEBUG_GEN(msg, ...) do { } while(0)
#endif

typedef struct DisasContext DisasContext;
typedef void (*ducky_instruction_generator)(DisasContext *);

struct DisasContext {
    DisasContextBase base;

    CPUDuckyState *env;
    uint32_t opcode;
    //target_ulong pc;
    uint32_t is_index;
    uint32_t mem_idx;
    uint32_t tb_flags;

    uint32_t raw_instr;
    union encoding instr;

    ducky_instruction_generator *generators;
};

static TCGv CPU_REGSET[32];
static TCGv CPU_PC;
static TCGv CPU_PRIVILEGED;
static TCGv CPU_HWINT_ENABLED;
static TCGv CPU_EQUAL;
static TCGv CPU_ZERO;
static TCGv CPU_OVERFLOW;
static TCGv CPU_SIGN;
static TCGv CPU_SIS_INDEX;
static TCGv CPU_EVT_ADDRESS;

static TCGv CPU_CC_RESULT;
static TCGv CPU_CC_FLAGS_VALID;

#include "exec/gen-icount.h"

void ducky_translate_init(void)
{
    int i;

#define GLOBAL(_global, _member, _name) do { (_global) = tcg_global_mem_new(cpu_env, offsetof(CPUDuckyState, _member), (_name)); } while(0)
#define GLOBAL64(_global, _member, _name) do { (_global) = tcg_global_mem_new_i64(cpu_env, offsetof(CPUDuckyState, _member), (_name)); } while(0)

    GLOBAL(CPU_PC, pc, "pc");
    GLOBAL(CPU_PRIVILEGED, privileged, "privileged");
    GLOBAL(CPU_HWINT_ENABLED, hwint_enabled, "hwint_enabled");
    GLOBAL(CPU_EQUAL, equal, "equal");
    GLOBAL(CPU_ZERO, zero, "zero");
    GLOBAL(CPU_OVERFLOW, overflow, "overflow");
    GLOBAL(CPU_SIGN, sign, "sign");
    GLOBAL(CPU_SIS_INDEX, sis_index, "sis_index");
    GLOBAL(CPU_EVT_ADDRESS, evt_address, "evt-address");

    GLOBAL(CPU_CC_RESULT, cc_result, "cc-result");
    GLOBAL(CPU_CC_FLAGS_VALID, cc_flags_valid, "cc-flags-valid");

    for (i = 0; i < 32; i++)
      GLOBAL(CPU_REGSET[i], regs[i], regnames[i]);
}

#ifndef tcg_temp_new_tl
#  define tcg_temp_new_tl tcg_temp_new_i32
#endif

#ifndef tcg_const_tl
#  define tcg_const_tl tcg_const_i32
#endif

#ifndef tcg_temp_free_tl
#  define tcg_temp_free_tl tcg_temp_free_i32
#endif

#define TCG_CONST(_name, _value) TCGv _name = tcg_const_tl(_value)

#define SAVE_PC() do { tcg_gen_movi_tl(CPU_PC, dc->base.pc_next); } while(0)


static void gen_exception(DisasContext *dc, uint32_t excp)
{
  TCG_CONST(tmp, excp);

  SAVE_PC();

  gen_helper_exception(cpu_env, tmp);

  tcg_temp_free_tl(tmp);
}

/*
static void gen_exception1(DisasContext *dc, uint32_t excp, uint32_t arg)
{
  TCG_CONST(tmp1, excp);
  TCG_CONST(tmp2, arg);

  SAVE_PC();
  gen_helper_exception1(cpu_env, tmp1, tmp2);

  tcg_temp_free_tl(tmp1);
  tcg_temp_free_tl(tmp2);
}

static void gen_exception2(DisasContext *dc, uint32_t excp, uint32_t arg1, uint32_t arg2)
{
  TCG_CONST(tmp1, excp);
  TCG_CONST(tmp2, arg1);
  TCG_CONST(tmp3, arg2);

  SAVE_PC();
  gen_helper_exception2(cpu_env, tmp1, tmp2, tmp3);

  tcg_temp_free_tl(tmp1);
  tcg_temp_free_tl(tmp2);
  tcg_temp_free_tl(tmp3);
}
*/
static void gen_exception3(DisasContext *dc, uint32_t excp, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
  TCG_CONST(tmp1, excp);
  TCG_CONST(tmp2, arg1);
  TCG_CONST(tmp3, arg2);
  TCG_CONST(tmp4, arg3);

  SAVE_PC();
  gen_helper_exception3(cpu_env, tmp1, tmp2, tmp3, tmp4);

  tcg_temp_free_tl(tmp1);
  tcg_temp_free_tl(tmp2);
  tcg_temp_free_tl(tmp3);
  tcg_temp_free_tl(tmp4);
}

static void gen_illegal_opcode_exception(DisasContext *dc)
{
  DEBUG_GEN("illegal opcode: PC=0x%08X, SIS=%02X, opcode=%02u", dc->base.pc_next - 4, dc->env->sis_index, dc->opcode);
  exit(1);

  SAVE_PC();

  gen_exception3(dc, EXCP_INVALID_OPCODE, dc->base.pc_next - 4, dc->env->sis_index, dc->opcode);
  dc->base.is_jmp = DISAS_UPDATE;
}

/*
static inline bool use_goto_tb(DisasContext *dc, target_ulong dest)
{
  if (unlikely(dc->base.singlestep_enabled))
    return false;

  return (dc->tb->pc & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK);
}
*/

static void gen_goto_tb(DisasContext *dc, target_ulong dest)
{
  DEBUG_GEN("goto-tb: dst=0x%08X", dest);

  tcg_gen_movi_tl(CPU_PC, dest);
  tcg_gen_exit_tb(NULL, 0);
}

#define GEN_FLAG_TAU(_test, _dest, _lhs, _rhs) do { tcg_gen_setcondi_tl(_test, _dest, _lhs, _rhs); } while(0)
#define GEN_FLAG_RESET(_dest) do { tcg_gen_movi_tl(_dest, 0); } while(0)

#define GEN_ZERO_TAU(_value) \
  GEN_FLAG_TAU(TCG_COND_EQ, CPU_ZERO, _value, 0)
#define GEN_ZERO_RESET() \
  GEN_FLAG_RESET(CPU_ZERO)

#define GEN_SIGN_TAU(_value) \
  GEN_FLAG_TAU(TCG_COND_GEU, CPU_SIGN, _value, SIGNED_MASK)
#define GEN_SIGN_RESET() \
  GEN_FLAG_RESET(CPU_SIGN)

#define GEN_OVERFLOW_TAU(_value) \
  GEN_FLAG_TAU(TCG_COND_EQ, CPU_OVERFLOW, _value, 0)
#define GEN_OVERFLOW_RESET() \
  GEN_FLAG_RESET(CPU_OVERFLOW)

static inline void gen_cc_record_result(DisasContext *dc, TCGv result)
{
  tcg_gen_mov_tl(CPU_CC_RESULT, result);
  tcg_gen_movi_tl(CPU_CC_FLAGS_VALID, 0);
}

static void gen_cc_sync_flags(DisasContext *dc)
{
  TCGLabel *l1 = gen_new_label();

  // if the flags are valid, just skip this part - one of the previous instructions
  // did set them, and no later instruction had any effect on them.
  tcg_gen_brcondi_tl(TCG_COND_EQ, CPU_CC_FLAGS_VALID, 1, l1);

  tcg_gen_setcondi_tl(TCG_COND_EQ, CPU_ZERO, CPU_CC_RESULT, 0);
  GEN_OVERFLOW_RESET(); // FIXME!
  tcg_gen_setcondi_tl(TCG_COND_GEU, CPU_SIGN, CPU_CC_RESULT, SIGNED_MASK);

  tcg_gen_movi_tl(CPU_CC_FLAGS_VALID, 1);

  gen_set_label(l1);
}

static inline void gen_raw_push(TCGv value)
{
  TCGv sp = CPU_REGSET[REG_SP];

  tcg_gen_subi_tl(sp, sp, TARGET_WORD_SIZE);
  tcg_gen_qemu_st32(value, sp, 0);
}

static inline void gen_raw_pushi(uint32_t imm)
{
  TCGv value = tcg_const_tl(imm);
  gen_raw_push(value);
  tcg_temp_free_tl(value);
}

static inline void gen_raw_pop(TCGv dst)
{
  TCGv sp = CPU_REGSET[REG_SP];

  tcg_gen_qemu_ld32u(dst, sp, 0);
  tcg_gen_addi_tl(sp, sp, TARGET_WORD_SIZE);
}

typedef void (*gen_arith_binop_instr)(TCGv_i32, TCGv_i32, TCGv_i32);
typedef void (*gen_arith_binop_instr_i32)(TCGv_i32, TCGv_i32, int32_t);
typedef void (*gen_arith_binop_instr_u32)(TCGv_i32, TCGv_i32, int32_t);

typedef void (*gen_load_instr_t)(TCGv, TCGv, int);
typedef void (*gen_store_instr_t)(TCGv, TCGv, int);

static void gen_arith_binop_i32(DisasContext *dc, gen_arith_binop_instr gen_rr, gen_arith_binop_instr_i32 gen_ri)
{
  R_ENC();

  DEBUG_GEN("%s reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", mnemonics[ENC->opcode], regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv dst = CPU_REGSET[ENC->reg1];

  if (ENC->immediate_flag == 1) {
    if (ENC->opcode == 31 || ENC->opcode == 32) {
      TCGv tmp = tcg_temp_new_tl();
      tcg_gen_movi_tl(tmp, R_SEXT(ENC));
      gen_rr(dst, dst, tmp);
      tcg_temp_free_tl(tmp);
    } else {
      gen_ri(dst, dst, R_SEXT(ENC));
    }
  } else {
    gen_rr(dst, dst, CPU_REGSET[ENC->reg2]);
  }

  gen_cc_record_result(dc, dst);
}

static void gen_arith_binop_u32(DisasContext *dc, gen_arith_binop_instr gen_rr, gen_arith_binop_instr_u32 gen_ru)
{
  R_ENC();

  DEBUG_GEN("%s reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", mnemonics[ENC->opcode], regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv dst = CPU_REGSET[ENC->reg1];

  if (ENC->immediate_flag == 1) {
    gen_ru(dst, dst, R_SEXT(ENC));
  } else {
    gen_rr(dst, dst, CPU_REGSET[ENC->reg2]);
  }

  gen_cc_record_result(dc, dst);
}

static void gen_load(DisasContext *dc, gen_load_instr_t gen_load_instr)
{
  R_ENC();

  DEBUG_GEN("%s reg1=%s, reg2=%s, if=%u, imm=0x%08X, simm=0X%08X", mnemonics[ENC->opcode], regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv dst = CPU_REGSET[ENC->reg1];

  if (ENC->immediate_flag == 1) {
    TCGv addr = tcg_temp_new_tl();
    tcg_gen_addi_tl(addr, CPU_REGSET[ENC->reg2], R_SEXT(ENC));
    gen_load_instr(dst, addr, 0);
    //gen_helper_debug_load(cpu_env, CPU_PC, addr, dst);
    tcg_temp_free_tl(addr);
  } else {
    gen_load_instr(dst, CPU_REGSET[ENC->reg2], 0);
    //gen_helper_debug_load(cpu_env, CPU_PC, CPU_REGSET[ENC->reg2], dst);
  }

  gen_cc_record_result(dc, dst);
}

static void gen_store(DisasContext *dc, gen_store_instr_t gen_store_instr)
{
  R_ENC();

  DEBUG_GEN("%s reg1=%s, reg2=%s, if=%u, imm=0x%08X, simm=0X%08X", mnemonics[ENC->opcode], regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  if (ENC->immediate_flag == 1) {
    TCGv addr = tcg_temp_new_tl();
    tcg_gen_addi_tl(addr, CPU_REGSET[ENC->reg2], R_SEXT(ENC));
    //gen_helper_debug_store(cpu_env, CPU_PC, addr, CPU_REGSET[ENC->reg1]);
    gen_store_instr(CPU_REGSET[ENC->reg1], addr, 0);
    tcg_temp_free_tl(addr);
  } else {
    //gen_helper_debug_store(cpu_env, CPU_PC, CPU_REGSET[ENC->reg2], CPU_REGSET[ENC->reg1]);
    gen_store_instr(CPU_REGSET[ENC->reg1], CPU_REGSET[ENC->reg2], 0);
  }
}

static void gen_cond_eval(DisasContext *dc, TCGv result, uint32_t flag, uint32_t value)
{
  gen_cc_sync_flags(dc);

  if (flag <= BRANCH_TRIVIALS) {
    TCGv flag0;

    switch(flag) {
      case BRANCH_EQUAL:
        flag0 = CPU_EQUAL;
        break;
      case BRANCH_ZERO:
        flag0 = CPU_ZERO;
        break;
      case BRANCH_OVERFLOW:
        flag0 = CPU_OVERFLOW;
        break;
      case BRANCH_SIGN:
        flag0 = CPU_SIGN;
        break;
    }

    tcg_gen_setcondi_tl(TCG_COND_EQ, result, flag0, value);
  } else if (flag == BRANCH_LT) {
    TCGv flag0 = tcg_temp_new_tl();
    TCGv flag1 = tcg_temp_new_tl();

    if (value == 0) {
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag0, CPU_SIGN, 0);
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag1, CPU_EQUAL, 1);
      tcg_gen_or_tl(result, flag0, flag1);
    } else {
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag0, CPU_SIGN, 1);
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag1, CPU_EQUAL, 0);
      tcg_gen_and_tl(result, flag0, flag1);
    }

    tcg_temp_free_tl(flag0);
    tcg_temp_free_tl(flag1);
  } else if (flag == BRANCH_GT) {
    TCGv flag0 = tcg_temp_new_tl();
    TCGv flag1 = tcg_temp_new_tl();

    if (value == 0) {
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag0, CPU_SIGN, 1);
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag1, CPU_EQUAL, 1);
      tcg_gen_or_tl(result, flag0, flag1);
    } else {
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag0, CPU_SIGN, 0);
      tcg_gen_setcondi_tl(TCG_COND_EQ, flag1, CPU_EQUAL, 0);
      tcg_gen_and_tl(result, flag0, flag1);
    }

    tcg_temp_free_tl(flag0);
    tcg_temp_free_tl(flag1);
  } else {
    gen_illegal_opcode_exception(dc);
  }
}

#define GEN_JUMP(_sign_extender) do {                                             \
  if (ENC->immediate_flag == 1) {                                                 \
    tcg_gen_movi_tl(CPU_PC, dc->base.pc_next + (_sign_extender(ENC) << TARGET_WORD_WIDTH)); \
  } else {                                                                        \
    tcg_gen_mov_tl(CPU_PC, CPU_REGSET[ENC->reg]);                                 \
  }                                                                               \
  dc->base.is_jmp = DISAS_JUMP;                                                        \
} while(0)

static void gen_cond_branchi(DisasContext *dc, int cond, TCGv lhs, int rhs)
{
  C_ENC();

  TCGLabel *l1 = gen_new_label();

  tcg_gen_brcondi_tl(TCG_COND_EQ, lhs, rhs, l1);
  gen_goto_tb(dc, dc->base.pc_next);
  gen_set_label(l1);

  GEN_JUMP(C_SEXT);
}

static void gen_add(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_add_tl, tcg_gen_addi_tl);
}

static void gen_and(DisasContext *dc)
{
  gen_arith_binop_u32(dc, tcg_gen_and_tl, tcg_gen_andi_tl);
}

static void gen_branch(DisasContext *dc)
{
  C_ENC();

  DEBUG_GEN("branch reg=%s, flag=%u, value=%u, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->flag, ENC->value, ENC->immediate_flag, ENC->immediate, C_SEXT(ENC));

  TCGv flag = tcg_temp_new_tl();
  gen_cond_eval(dc, flag, ENC->flag, ENC->value);
  gen_cond_branchi(dc, TCG_COND_EQ, flag, 1);
  tcg_temp_free_tl(flag);
}

static void gen_cmp(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("cmp reg1=%s, reg2=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv lhs = CPU_REGSET[ENC->reg1];
  TCGv rhs = (ENC->immediate_flag ? tcg_const_tl(R_SEXT(ENC)) : CPU_REGSET[ENC->reg2]);

  tcg_gen_setcond_tl(TCG_COND_EQ, CPU_EQUAL, lhs, rhs);

  TCGv tmp0 = tcg_temp_new_tl();
  tcg_gen_setcondi_tl(TCG_COND_EQ, tmp0, lhs, 0);
  tcg_gen_and_tl(CPU_ZERO, tmp0, CPU_EQUAL);
  tcg_temp_free_tl(tmp0);

  tcg_gen_movi_tl(CPU_OVERFLOW, 0);

  tcg_gen_setcond_tl(TCG_COND_LT, CPU_SIGN, lhs, rhs);

  if (ENC->immediate_flag == 1)
    tcg_temp_free_tl(rhs);

  tcg_gen_movi_tl(CPU_CC_FLAGS_VALID, 1);
}

static void gen_cmpu(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("cmp reg1=%s, reg2=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv lhs = CPU_REGSET[ENC->reg1];
  TCGv rhs = (ENC->immediate_flag ? tcg_const_tl(R_SEXT(ENC)) : CPU_REGSET[ENC->reg2]);

  tcg_gen_setcond_tl(TCG_COND_EQ, CPU_EQUAL, lhs, rhs);

  TCGv tmp0 = tcg_temp_new_tl();
  tcg_gen_setcondi_tl(TCG_COND_EQ, tmp0, lhs, 0);
  tcg_gen_and_tl(CPU_ZERO, tmp0, CPU_EQUAL);
  tcg_temp_free_tl(tmp0);

  tcg_gen_movi_tl(CPU_OVERFLOW, 0);

  tcg_gen_setcond_tl(TCG_COND_LTU, CPU_SIGN, lhs, rhs);

  if (ENC->immediate_flag == 1)
    tcg_temp_free_tl(rhs);

  tcg_gen_movi_tl(CPU_CC_FLAGS_VALID, 1);
}

static void gen_ctr(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("ctr reg1=%s, reg2=%s", regnames[ENC->reg1], regnames[ENC->reg2]);

  TCGv reg = CPU_REGSET[ENC->reg1];

  switch(ENC->reg2) {
    case DUCKY_CTR_REG_CPUID:
      tcg_gen_movi_tl(reg, 0x00000000);
      break;
    case DUCKY_CTR_REG_EVT:
      tcg_gen_mov_tl(reg, CPU_EVT_ADDRESS);
      break;
    case DUCKY_CTR_REG_FLAGS:
      tcg_gen_movi_tl(reg,   (dc->env->pt_enabled ? 0 : CTR_FLAG_PT_ENABLED)
                           | (dc->env->jit_enabled ? 0 : CTR_FLAG_JIT)
                           | (dc->env->vmdebug ? 0 : CTR_FLAG_VMDEBUG));
      break;
    default:
      gen_illegal_opcode_exception(dc);
  }

  gen_cc_record_result(dc, reg);
}

static void gen_ctw(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("ctw reg1=%s, reg2=%s", regnames[ENC->reg1], regnames[ENC->reg2]);

  switch(ENC->reg1) {
    case DUCKY_CTR_REG_EVT:
      tcg_gen_mov_tl(CPU_EVT_ADDRESS, CPU_REGSET[ENC->reg2]);
      break;
    case DUCKY_CTR_REG_FLAGS:
      break;
      /*
      tcg_gen_movi_tl(reg,   (dc->env->pt_enabled ? 0 : CTR_FLAG_PT_ENABLED)
                           | (dc->env->jit_enabled ? 0 : CTR_FLAG_JIT)
                           | (dc->env->vmdebug ? 0 : CTR_FLAG_VMDEBUG));
      break;
      */
    default:
      gen_illegal_opcode_exception(dc);
  }
}

static void gen_dec(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("dec %s", regnames[ENC->reg1]);

  TCGv reg = CPU_REGSET[ENC->reg1];

  tcg_gen_subi_tl(reg, reg, 1);

  gen_cc_record_result(dc, reg);
}

static void gen_div(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_div_tl, NULL);
}

static void gen_mod(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_rem_tl, NULL);
}

static void gen_fptc(DisasContext *dc)
{
}

static void gen_la(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("la %s, IF=%u, IMM=0x%08X, SIMM=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  TCGv reg = CPU_REGSET[ENC->reg];

  tcg_gen_movi_tl(reg, dc->base.pc_next);

  if (ENC->immediate_flag == 1)
    tcg_gen_addi_tl(reg, reg, I_SEXT(ENC));

  gen_cc_record_result(dc, reg);
}

static void gen_lb(DisasContext *dc)
{
  gen_load(dc, tcg_gen_qemu_ld8u);
}

static void gen_ls(DisasContext *dc)
{
  gen_load(dc, tcg_gen_qemu_ld16u);
}

static void gen_lw(DisasContext *dc)
{
  gen_load(dc, tcg_gen_qemu_ld32u);
}

static void gen_call(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("call REG=%s, IF=%u, IMM=0x%08X, SIMM=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  gen_raw_pushi(dc->base.pc_next);
  gen_raw_push(CPU_REGSET[REG_FP]);

  tcg_gen_mov_tl(CPU_REGSET[REG_FP], CPU_REGSET[REG_SP]);

  GEN_JUMP(I_SEXT);
}

static void gen_hlt(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("hlt reg=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  if (ENC->immediate_flag == 1) {
    gen_helper_hlt(cpu_env, tcg_const_tl(I_SEXT(ENC)));
  } else {
    gen_helper_hlt(cpu_env, CPU_REGSET[ENC->reg]);
  }

  dc->base.is_jmp = DISAS_NORETURN;
}

static void gen_idle(DisasContext *dc)
{
  DEBUG_GEN("idle");

  SAVE_PC();

  gen_helper_idle(cpu_env);
  dc->base.is_jmp = DISAS_JUMP;
}

static void gen_inc(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("inc %s", regnames[ENC->reg1]);

  TCGv reg = CPU_REGSET[ENC->reg1];

  tcg_gen_addi_tl(reg, reg, 1);

  gen_cc_record_result(dc, reg);
}

static void gen_jump(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("j reg=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  GEN_JUMP(I_SEXT);
}

static void gen_li(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("li reg=%s, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate, I_SEXT(ENC));

  tcg_gen_movi_tl(CPU_REGSET[ENC->reg], I_SEXT(ENC));

  gen_cc_record_result(dc, CPU_REGSET[ENC->reg]);
}

static void gen_liu(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("liu reg=%s, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate, I_SEXT(ENC));

  TCGv reg = CPU_REGSET[ENC->reg];
  TCGv tmp = tcg_temp_new_tl();

  tcg_gen_movi_tl(tmp, I_SEXT(ENC));
  tcg_gen_shli_tl(tmp, tmp, 16);
  tcg_gen_andi_tl(reg, reg, 0x0000FFFF);
  tcg_gen_or_tl(reg, reg, tmp);
  tcg_temp_free_tl(tmp);
}

static void gen_mov(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("mov reg1=%s, reg2=%s", regnames[ENC->reg1], regnames[ENC->reg2]);

  tcg_gen_mov_tl(CPU_REGSET[ENC->reg1], CPU_REGSET[ENC->reg2]);
}

static void gen_swp(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("swp reg1=%s, reg2=%s", regnames[ENC->reg1], regnames[ENC->reg2]);

  TCGv tmp = tcg_temp_new_tl();
  tcg_gen_mov_tl(tmp, CPU_REGSET[ENC->reg2]);
  tcg_gen_mov_tl(CPU_REGSET[ENC->reg2], CPU_REGSET[ENC->reg1]);
  tcg_gen_mov_tl(CPU_REGSET[ENC->reg1], tmp);
  tcg_temp_free_tl(tmp);
}

static void gen_mul(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_mul_tl, tcg_gen_muli_tl);
}

static void gen_nop(DisasContext *dc)
{
  //gen_illegal_opcode_exception(dc);
}

static void gen_not(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("not reg=%s", regnames[ENC->reg1]);

  tcg_gen_not_tl(CPU_REGSET[ENC->reg1], CPU_REGSET[ENC->reg1]);
}

static void gen_or(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_or_tl, tcg_gen_ori_tl);
}

static void gen_pop(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("pop reg=%s", regnames[ENC->reg1]);

  gen_raw_pop(CPU_REGSET[ENC->reg1]);
}

static void gen_push(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("push reg=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  if (ENC->immediate_flag == 1) {
    gen_raw_pushi(I_SEXT(ENC));
  } else {
    gen_raw_push(CPU_REGSET[ENC->reg]);
  }
}

static void gen_ret(DisasContext *dc)
{
  //I_ENC();

  DEBUG_GEN("ret");

  gen_raw_pop(CPU_REGSET[REG_FP]);
  gen_raw_pop(CPU_PC);

  dc->base.is_jmp = DISAS_JUMP;
}

static void gen_int(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("int");

  SAVE_PC();

  if (ENC->immediate_flag == 1) {
    gen_exception(dc, I_SEXT(ENC));
  } else {
    gen_exception(dc, I_SEXT(ENC));
  }

  dc->base.is_jmp = DISAS_JUMP;
}

static void gen_retint(DisasContext *dc)
{
  DEBUG_GEN("retint");

  SAVE_PC();

  gen_helper_exit_exception(cpu_env);
  dc->base.is_jmp = DISAS_JUMP;
}

static void gen_select(DisasContext *dc)
{
  S_ENC();

  DEBUG_GEN("select reg1=%s, reg2=%s, flag=%u, value=%u, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->flag, ENC->value, ENC->immediate_flag, ENC->immediate, S_SEXT(ENC));

  // "one" may be hoisted out of the branches but that leads to crashing TCG
  // because movcond is using a dead argument... No idea why or how, I don't
  // really understand, but this seems to be a workaround :/

  TCGv flag = tcg_temp_new_tl();

  gen_cond_eval(dc, flag, ENC->flag, ENC->value);

  if (ENC->immediate_flag == 1) {
    TCGv one = tcg_const_tl(1);
    TCGv tmp = tcg_const_tl(S_SEXT(ENC));

    tcg_gen_movcond_tl(TCG_COND_EQ, CPU_REGSET[ENC->reg1], flag, one, CPU_REGSET[ENC->reg1], tmp);
    tcg_temp_free_tl(tmp);
    tcg_temp_free_tl(one);
  } else {
    TCGv one = tcg_const_tl(1);
    tcg_gen_movcond_tl(TCG_COND_EQ, CPU_REGSET[ENC->reg1], flag, one, CPU_REGSET[ENC->reg1], CPU_REGSET[ENC->reg2]);
    tcg_temp_free_tl(one);
  }

  tcg_temp_free_tl(flag);
}

static void gen_shl(DisasContext *dc)
{
  gen_arith_binop_u32(dc, tcg_gen_shl_tl, tcg_gen_shli_tl);
}

static void gen_shr(DisasContext *dc)
{
  gen_arith_binop_u32(dc, tcg_gen_shr_tl, tcg_gen_shri_tl);
}

static void gen_shrs(DisasContext *dc)
{
  gen_arith_binop_u32(dc, tcg_gen_sar_tl, tcg_gen_sari_tl);
}

static void gen_sis(DisasContext *dc)
{
  I_ENC();

  DEBUG_GEN("sis reg=%s, if=%u, imm=0x%08X, simm=0x%08X", regnames[ENC->reg], ENC->immediate_flag, ENC->immediate, I_SEXT(ENC));

  //SAVE_PC();

  if (ENC->immediate_flag == 1) {
    tcg_gen_movi_tl(CPU_SIS_INDEX, I_SEXT(ENC));
  } else {
    tcg_gen_mov_tl(CPU_SIS_INDEX, CPU_REGSET[ENC->reg]);
  }

  dc->base.is_jmp = DISAS_UPDATE;
}

static void gen_stb(DisasContext *dc)
{
  gen_store(dc, tcg_gen_qemu_st8);
}

static void gen_cas(DisasContext *dc)
{
  A_ENC();

  DEBUG_GEN("cas reg1=%s, reg2=%s, reg3=%s", regnames[ENC->reg1], regnames[ENC->reg2], regnames[ENC->reg3]);

  TCGv_i32 addr = CPU_REGSET[ENC->reg1];
  TCGv_i32 eval = CPU_REGSET[ENC->reg2];
  TCGv_i32 nval = CPU_REGSET[ENC->reg3];

  tcg_gen_atomic_cmpxchg_tl(eval, addr, eval, nval, dc->mem_idx, MO_TEUL | MO_ALIGN);
}

static void gen_sti(DisasContext *dc)
{
  //I_ENC();

  DEBUG_GEN("sti");

  tcg_gen_movi_tl(CPU_HWINT_ENABLED, 1);
}

static void gen_sts(DisasContext *dc)
{
  gen_store(dc, tcg_gen_qemu_st16);
}

static void gen_stw(DisasContext *dc)
{
  gen_store(dc, tcg_gen_qemu_st32);
}

static void gen_sub(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_sub_tl, tcg_gen_subi_tl);
}

static void gen_udiv(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_divu_tl, NULL);
}

static void gen_xor(DisasContext *dc)
{
  gen_arith_binop_i32(dc, tcg_gen_xor_tl, tcg_gen_xori_tl);
}

static ducky_instruction_generator generators_core[] = {
  gen_nop,  // 0
  gen_lw,
  gen_ls,
  gen_lb,
  gen_stw,
  gen_sts,  // 5
  gen_stb,
  gen_cas,
  gen_la,
  gen_li,
  gen_liu,   // 10
  gen_mov,
  gen_swp,
  gen_int,
  gen_retint,
  gen_call, // 15
  gen_ret,
  NULL,
  gen_sti,
  NULL,
  gen_hlt,  // 20
  gen_idle,
  NULL,
  NULL,
  gen_push,
  gen_pop,  // 25
  gen_inc,
  gen_dec,
  gen_add,
  gen_sub,
  gen_mul,  // 30
  gen_div,
  gen_udiv,
  gen_mod,
  gen_and,
  gen_or,   // 35
  gen_xor,
  gen_not,
  gen_shl,
  gen_shr,
  gen_shrs, // 40
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,     // 45
  gen_jump,
  gen_cmp,
  gen_cmpu,
  NULL,
  gen_branch, // 50
  gen_select,
  NULL,
  NULL,
  NULL,
  NULL,       // 55
  NULL,
  NULL,
  NULL,
  NULL,
  gen_ctr, // 60
  gen_ctw,
  gen_fptc,
  gen_sis
};

static void gen_math_addl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_addl(cpu_env);
}

static void gen_math_divl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_divl(cpu_env);
}

static void gen_math_dup(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_dup(cpu_env);
}

static void gen_math_drop(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.drop reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_drop(cpu_env);
}

static void gen_math_dup2(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_dup2(cpu_env);
}

static void gen_math_loadw(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_sext_push(cpu_env, CPU_REGSET[ENC->reg1]);
}

static void gen_math_loaduw(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("math.loaduw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_zext_push(cpu_env, CPU_REGSET[ENC->reg1]);
}

static void gen_math_modl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_modl(cpu_env);
}

static void gen_math_mull(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_mull(cpu_env);
}

static void gen_math_symmodl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_symmodl(cpu_env);
}

static void gen_math_symdivl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_symdivl(cpu_env);
}

static void gen_math_umodl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_umodl(cpu_env);
}

static void gen_math_udivl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.loadw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_udivl(cpu_env);
}

static void gen_math_popl(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.popw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv hi, lo;
  TCGv_i64 hi_ext, lo_ext;

  hi = tcg_temp_new_tl();
  lo = tcg_temp_new_tl();
  hi_ext = tcg_temp_new_i64();
  lo_ext = tcg_temp_new_i64();

  gen_raw_pop(hi);
  gen_raw_pop(lo);

  tcg_gen_extu_i32_i64(hi_ext, hi);
  tcg_gen_extu_i32_i64(lo_ext, lo);

  tcg_gen_shli_i64(hi_ext, hi_ext, 32);

  tcg_gen_or_i64(hi_ext, hi_ext, lo_ext);

  gen_helper_math_stack_push(cpu_env, hi_ext);

  tcg_temp_free_tl(hi);
  tcg_temp_free_tl(lo);
  tcg_temp_free_i64(hi_ext);
  tcg_temp_free_i64(lo_ext);
}

static void gen_math_popw(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.popw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv value = tcg_temp_new_tl();
  gen_raw_pop(value);
  gen_helper_math_stack_sext_push(cpu_env, value);
  tcg_temp_free_tl(value);
}

static void gen_math_popuw(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.popw reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv value = tcg_temp_new_tl();
  gen_raw_pop(value);
  gen_helper_math_stack_zext_push(cpu_env, value);
  tcg_temp_free_tl(value);
}

static void gen_math_pushw(DisasContext *dc)
{
  TCGv_i64 value;
  TCGv lo;

  value = tcg_temp_new_i64();
  lo = tcg_temp_new_tl();

  gen_helper_math_stack_pop(value, cpu_env);

  tcg_gen_trunc_i64_tl(lo, value);
  gen_raw_push(lo);

  tcg_temp_free_i64(value);
  tcg_temp_free_tl(lo);
}

static void gen_math_pushl(DisasContext *dc)
{
  TCGv_i64 value;
  TCGv hi, lo;

  value = tcg_temp_new_i64();
  hi = tcg_temp_new_tl();
  lo = tcg_temp_new_tl();

  gen_helper_math_stack_pop(value, cpu_env);

  tcg_gen_trunc_i64_tl(lo, value);
  tcg_gen_shri_i64(value, value, 32);
  tcg_gen_trunc_i64_tl(hi, value);

  gen_raw_push(lo);
  gen_raw_push(hi);

  tcg_temp_free_i64(value);
  tcg_temp_free_tl(hi);
  tcg_temp_free_tl(lo);
}

static void gen_math_save(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("math.save reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv_i64 value = tcg_temp_new_i64();

  gen_helper_math_stack_pop(value, cpu_env);

  tcg_gen_trunc_i64_tl(CPU_REGSET[ENC->reg2], value);
  tcg_gen_shri_i64(value, value, 32);
  tcg_gen_trunc_i64_tl(CPU_REGSET[ENC->reg1], value);

  tcg_temp_free_i64(value);
}

static void gen_math_savew(DisasContext *dc)
{
  R_ENC();

  DEBUG_GEN("math.savew reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  TCGv_i64 value = tcg_temp_new_i64();

  gen_helper_math_stack_pop(value, cpu_env);

  tcg_gen_trunc_i64_tl(CPU_REGSET[ENC->reg1], value);

  tcg_temp_free_i64(value);
}

static void gen_math_swp(DisasContext *dc)
{
  //R_ENC();

  //DEBUG_GEN("math.save reg1=%s, reg2=%s, if=%u, imm=0x%08X, sim=0x%08X", regnames[ENC->reg1], regnames[ENC->reg2], ENC->immediate_flag, ENC->immediate, R_SEXT(ENC));

  gen_helper_math_stack_swp(cpu_env);
}

static ducky_instruction_generator generators_math[] = {
  gen_math_popw,
  gen_math_popuw,
  gen_math_pushw,
  gen_math_savew,
  gen_math_loadw,
  gen_math_loaduw,
  gen_math_popl,
  gen_math_save,
  gen_math_pushl,
  NULL,
  gen_math_mull,
  gen_math_divl,
  gen_math_modl,
  gen_math_symdivl,
  gen_math_symmodl,
  gen_math_udivl,
  gen_math_umodl,
  NULL,
  NULL,
  NULL,
  gen_math_dup,
  gen_math_dup2,
  gen_math_swp,
  gen_math_drop,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  gen_math_addl,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  gen_sis
};

static ducky_instruction_generator *generators_map[] = {
  generators_core,
  generators_math
};

static void gen_intermediate_instr(DisasContext *dc)
{
  if (dc->opcode > DUCKY_OPCODE_MAX || !dc->generators[dc->opcode]) {
    gen_illegal_opcode_exception(dc);
    return;
  }

  dc->generators[dc->opcode](dc);
}

static void ducky_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPUDuckyState *env = cs->env_ptr;

    ctx->env = env;
    //ctx->pc = ctx->base.pc_first;
    ctx->mem_idx = cpu_mmu_index(env, false);
    ctx->generators = generators_map[env->sis_index];
}

static void ducky_tr_tb_start(DisasContextBase *db, CPUState *cpu)
{
}

static void ducky_tr_insn_start(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(ctx->base.pc_next);
}

static bool ducky_tr_breakpoint_check(DisasContextBase *dcbase, CPUState *cpu,
                                      const CPUBreakpoint *bp)
{
    return false;
}

static void ducky_tr_translate_insn(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPUDuckyState *env = cpu->env_ptr;

    ctx->raw_instr = cpu_ldl_code(env, ctx->base.pc_next);
    ctx->instr.raw = ctx->raw_instr;
    ctx->opcode = ctx->instr.O.opcode;

    // PC is incremented *before* generating IR code
    ctx->base.pc_next += 4;

    gen_intermediate_instr(ctx);
}

static void ducky_tr_tb_stop(DisasContextBase *dcbase, CPUState *cpu)
{
    DisasContext *dc = container_of(dcbase, DisasContext, base);

    if (dc->base.is_jmp == DISAS_NEXT) {
      SAVE_PC();
      dc->base.is_jmp = DISAS_UPDATE;
    }

    switch (dc->base.is_jmp) {
      case DISAS_NEXT:
          //DEBUG_GEN("gen: finalize NEXT");
          gen_goto_tb(dc, dc->base.pc_next);
          break;
      case DISAS_TOO_MANY:
          gen_goto_tb(dc, dc->base.pc_next);
          break;
      case DISAS_NORETURN:
          break;
      case DISAS_TB_JUMP:
          break;
      case DISAS_JUMP:
      case DISAS_UPDATE:
          //DEBUG_GEN("gen: finalize JUMP");
          tcg_gen_exit_tb(NULL, 0);
          break;
      default:
          DEBUG("gen: is_jmp=%d\n", dc->base.is_jmp);
          g_assert_not_reached();
    }
}

static void ducky_tr_disas_log(const DisasContextBase *dcbase, CPUState *cpu)
{
    qemu_log("IN: %s\n", lookup_symbol(dcbase->pc_first));
    log_target_disas(cpu, dcbase->pc_first, dcbase->tb->size);
}

static const TranslatorOps ducky_tr_ops = {
    .init_disas_context = ducky_tr_init_disas_context,
    .tb_start           = ducky_tr_tb_start,
    .insn_start         = ducky_tr_insn_start,
    .breakpoint_check   = ducky_tr_breakpoint_check,
    .translate_insn     = ducky_tr_translate_insn,
    .tb_stop            = ducky_tr_tb_stop,
    .disas_log          = ducky_tr_disas_log,
};

void gen_intermediate_code(CPUState *cs, struct TranslationBlock *tb, int max_insns)
{
    DisasContext ctx;

    translator_loop(&ducky_tr_ops, &ctx.base, cs, tb, max_insns);
}

void restore_state_to_opc(CPUDuckyState *env, TranslationBlock *tb, target_ulong *data)
{
  env->pc = data[0];
}

void ducky_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    DuckyCPU *cpu = DUCKY_CPU(cs);
    CPUDuckyState *env = &cpu->env;
    int i;

    qemu_fprintf(f, "\nvvvvv vvvvv vvvvv vvvvv vvvvv vvvvv vvvvv vvvvv vvvvv\n\n");

    for (i = 0; i < REG_SPECIAL; ++i)
        qemu_fprintf(f, "R%02d=0x%08X%c", i, env->regs[i], (i % 4) == 3 ? '\n' : ' ');
    qemu_fprintf(f, "\n");

    qemu_fprintf(f, " FP=0x%08X  SP=0x%08X  IP=0x%08X\n", env->regs[REG_FP], env->regs[REG_SP], env->pc);
    qemu_fprintf(f, "flags=%c%c%c%c%c%c%c\n",
        (env->privileged == 1 ? 'P' : '-'),
        (env->hwint_enabled == 1 ? 'H' : '-'),
        (env->equal == 1 ? 'E' : '-'),
        (env->zero == 1 ? 'Z' : '-'),
        (env->overflow == 1 ? 'O' : '-'),
        (env->sign == 1 ? 'S' : '-'),
        (env->cc_flags_valid == 1 ? 'F' : '-'));

    for (i = 0; i < DUCKY_MATH_STACK_SIZE; i++)
      qemu_fprintf(f, " %02u 0x%016lX\n", i, env->math_stack[i]);

    qemu_fprintf(f, "\n^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^ ^^^^^\n");
}
