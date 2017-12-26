/*
 * Exception handling on Ducky CPU.
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
#include "cpu.h"
#include "exec/exec-all.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "sysemu/sysemu.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "qemu-common.h"
#include "exec/gdbstub.h"
#include "qemu/host-utils.h"
#include "hw/loader.h"
#include "hw/irq.h"

#if 0
# define DEBUG(msg, ...) do { qemu_log(msg "\n", ##__VA_ARGS__); fflush(stderr); } while(0)
#else
# define DEBUG(msg, ...) do { } while(0)
#endif

/*
 * Raise an enxception on the CPU, and quit CPU loop.
 */
static void QEMU_NORETURN raise_exception(DuckyCPU *cpu, uint32_t excp)
{
  DEBUG("raise_exception: excp=0x%08X\n", excp);

    CPUState *cs = CPU(cpu);

    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

/*
 * Switch CPU into "idle" mode. Tell QEMU the CPU is halted and waits for external event.
 */
static void __do_idle(CPUDuckyState *env, uint32_t excp)
{
  DEBUG("__do_idle: excp=0x%08X", excp);

  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  cs->halted = 1;

  raise_exception(cpu, excp);
}

static void __do_enter_exception(CPUState *cs, int interrupt, int argc, uint32_t *argv)
{
  DEBUG("__do_enter_exception: interrupt=0x%08X", interrupt);

    DuckyCPU *cpu = DUCKY_CPU(cs);
    CPUDuckyState *env = &cpu->env;

    // for CPUSTATE debug interrupt, we change state of nothing, but simple log message is emmited
    if (interrupt == DUCKY_INT_CPUSTATE) {
        ducky_cpu_dump_state(cs, stderr, 0);
        return;
    }

    // clear the exception flag
    env->pending_interrupts &= ~(1 << interrupt);

    // compute vector address
    target_ulong vector = env->evt_address + interrupt * 8;

    // load exception handler IP and SP
    target_ulong exc_ip = cpu_ldl(cs, vector);
    target_ulong exc_sp = cpu_ldl(cs, vector + 4);

    // store state on top of the exception stack
    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->regs[REG_SP]);

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, cpu_get_flags(cs));

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->sis_index);

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->pc);

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->regs[REG_FP]);

    // push arguments on the stack
    if (argc) {
      int i;

      for(i = 0; argc > 0; i++, argc--) {
        exc_sp -= 4;
        cpu_stw(cs, exc_sp, argv[i]);
      }
    }

    env->pc = exc_ip;
    env->regs[REG_SP] = exc_sp;
    env->privileged = 1;
    env->hwint_enabled = 0;
    env->sis_index = DUCKY_SIS_CORE;

    DEBUG("__do_enter_exception: IP=0x%08X, SP=0x%08X", env->pc, env->regs[REG_SP]);
}

static void __do_exit_exception(CPUState *cs)
{
    DuckyCPU *cpu = DUCKY_CPU(cs);
    CPUDuckyState *env = &cpu->env;

    DEBUG("__do_enter_exception: IP=0x%08X, SP=0x%08X", env->pc, env->regs[REG_SP]);

    uint32_t exc_sp = env->regs[REG_SP];

    env->regs[REG_FP] = cpu_ldl(cs, exc_sp);
    exc_sp += 4;

    env->pc = cpu_ldl(cs, exc_sp);
    exc_sp += 4;

    env->sis_index = cpu_ldl(cs, exc_sp);
    exc_sp += 4;

    cpu_set_flags(cs, cpu_ldl(cs, exc_sp));
    exc_sp += 4;

    env->regs[REG_SP] = cpu_ldl(cs, exc_sp);
    exc_sp += 4;

    DEBUG("__do_enter_exception: IP=0x%08X, SP=0x%08X", env->pc, env->regs[REG_SP]);
}

/*
 * Implements "raise an exception" IR.
 */
void HELPER(exception)(CPUDuckyState *env, uint32_t excp)
{
  DEBUG("gen_helper_exception: excp=0x%08X", excp);

  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  __do_enter_exception(cs, excp, 0, NULL);
}

void HELPER(exception1)(CPUDuckyState *env, uint32_t excp, uint32_t arg1)
{
  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  __do_enter_exception(cs, excp, 1, &arg1);
}

void HELPER(exception2)(CPUDuckyState *env, uint32_t excp, uint32_t arg1, uint32_t arg2)
{
  DEBUG("gen_helper_exception: excp=0x%08X, arg1=0x%08X, arg2=0x%08X", excp, arg1, arg2);

  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  uint32_t argv[] = { arg1, arg2 };
  __do_enter_exception(cs, excp, 2, argv);
}

void HELPER(exception3)(CPUDuckyState *env, uint32_t excp, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
  DEBUG("gen_helper_exception: excp=0x%08X, arg1=0x%08X, arg2=0x%08X, arg3=0x%08X", excp, arg1, arg2, arg3);

  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  uint32_t argv[] = { arg1, arg2, arg3 };
  __do_enter_exception(cs, excp, 3, argv);
}

void HELPER(exit_exception)(CPUDuckyState *env)
{
  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  __do_exit_exception(cs);
}

/*
 * Implements "switch to 'idle' state" IR.
 */
void HELPER(idle)(CPUDuckyState *env)
{
  DEBUG("gen_helper_idle");

  __do_idle(env, EXCP_HALTED);
}

/*
 * Implements "halt the CPU" IR.
 */
void HELPER(hlt)(CPUDuckyState *env, int exit_code)
{
  DEBUG("gen_helper_hlt: exit_code=%u", exit_code);

  qemu_log("vmexit: exit_code=0x%08x\n", exit_code);

  exit(exit_code);
  //qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);

  __do_idle(env, EXCP_HLT);
}

void HELPER(debug_load)(CPUDuckyState *env, int pc, int addr, int value)
{
  fprintf(stderr, "#### load:  0x%08X: 0x%08X => 0x%08X\n", pc, addr, value);
  fflush(stderr);
}

void HELPER(debug_store)(CPUDuckyState *env, int pc, int addr, int value)
{
  fprintf(stderr, "#### store: 0x%08X: 0x%08X => 0x%08X\n", pc, value, addr);
  fflush(stderr);
}

void HELPER(log_cpu_state)(CPUDuckyState *env)
{
  CPUState *cs = ENV_GET_CPU(env);

  ducky_cpu_dump_state(cs, stderr, 0);
}

void HELPER(log_arb)(CPUDuckyState *env, uint64_t value)
{
  fprintf(stderr, "0x%016lX\n", value);
  fflush(stderr);
}

void ducky_cpu_do_interrupt(CPUState *cs)
{
    DuckyCPU *cpu = DUCKY_CPU(cs);
    CPUDuckyState *env = &cpu->env;

  DEBUG("ducky_cpu_do_interrupt: pending_interrupts=0x%08X", env->pending_interrupts);

    if (!env->pending_interrupts)
      return;

    if (env->hwint_enabled != 1) {
      DEBUG("ducky_cpu_do_interrupt: interrupts masked!");
      return;
    }

    int interrupt = __builtin_ffs(env->pending_interrupts) - 1;
    g_assert(interrupt > 0 && interrupt < 32);

    if (interrupt < DUCKY_NR_IRQS)
      qemu_irq_lower(env->irqs[interrupt]);

    __do_enter_exception(cs, interrupt, 0, NULL);

    cs->exception_index = -1;
}

/*
 * Called by QEMU to give CPU chance t oreact on interrupts. If it's a hard interrupt,
 * accept the chance and tell CPU it should run the handler.
 */
bool ducky_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
  DEBUG("ducky_cpu_exec_interrupt: interrupt_request=0x%08X", interrupt_request);
  int idx = -1;

  if ((interrupt_request & CPU_INTERRUPT_HARD))
    idx = EXCP_INTERRUPT;

  if (idx >= 0) {
    cs->exception_index = idx;
    ducky_cpu_do_interrupt(cs);
    return true;
  }

  return false;
}
