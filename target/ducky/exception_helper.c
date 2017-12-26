/*
 * Ducky exception helper routines
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
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "sysemu/sysemu.h"
#include "exception.h"

void HELPER(exception)(CPUDuckyState *env, uint32_t excp)
{
    DuckyCPU *cpu = ducky_env_get_cpu(env);

    raise_exception(cpu, excp);
}

static void __do_idle(CPUDuckyState *env)
{
  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  cs->halted = 1;
  cs->exception_index = EXCP_HLT;
}

void HELPER(idle)(CPUDuckyState *env)
{
  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  __do_idle(env);

  cpu_loop_exit(cs);
}

void HELPER(hlt)(CPUDuckyState *env, int exit_code)
{
  DuckyCPU *cpu = ducky_env_get_cpu(env);
  CPUState *cs = CPU(cpu);

  __do_idle(env);

  qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
  cpu_loop_exit(cs);
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
