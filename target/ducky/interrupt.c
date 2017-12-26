/*
 * Ducky interrupt.
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
#include "qemu-common.h"
#include "exec/gdbstub.h"
#include "qemu/host-utils.h"
#include "hw/loader.h"

#define DEBUG(msg, ...) do { qemu_log(msg, ##__VA_ARGS__); } while(0)

void ducky_cpu_do_interrupt(CPUState *cs)
{
    DuckyCPU *cpu = DUCKY_CPU(cs);
    CPUDuckyState *env = &cpu->env;

    // compute vector address
    target_ulong vector = env->evt_address + cs->exception_index * 8;

    // load exception handler IP and SP
    target_ulong exc_ip = cpu_ldl(cs, vector);
    target_ulong exc_sp = cpu_ldl(cs, vector + 4);

    // store state on top of the exception stack
    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->regs[REG_SP]);

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, cpu_get_flags(cs));

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->pc);

    exc_sp -= 4;
    cpu_stw(cs, exc_sp, env->regs[REG_FP]);

    env->pc = exc_ip;
    env->regs[REG_SP] = exc_sp;
    env->privileged = 1;
    env->hwint_enabled = 0;

    cs->exception_index = -1;

    exit(1);
}

bool ducky_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
  cs->exception_index = EXCP_DEBUG;

  /*
    OpenRISCCPU *cpu = OPENRISC_CPU(cs);
    CPUOpenRISCState *env = &cpu->env;
    int idx = -1;

    if ((interrupt_request & CPU_INTERRUPT_HARD) && (env->sr & SR_IEE)) {
        idx = EXCP_INT;
    }
    if ((interrupt_request & CPU_INTERRUPT_TIMER) && (env->sr & SR_TEE)) {
        idx = EXCP_TICK;
    }
    if (idx >= 0) {
        cs->exception_index = idx;
        openrisc_cpu_do_interrupt(cs);
        return true;
    }
    return false;
  */
  return true;
}
