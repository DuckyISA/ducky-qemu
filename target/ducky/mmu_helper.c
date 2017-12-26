/*
 * Ducky MMU helper routines
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
#include "exec/cpu_ldst.h"

#include "mmu.h"

#define DEBUG(msg, ...) do { qemu_log(msg, ##__VA_ARGS__); } while(0)

#ifndef CONFIG_USER_ONLY

bool ducky_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    int ret;

    ret = ducky_cpu_handle_mmu_fault(cs, address, size, access_type, mmu_idx);

    if (!ret)
      return true;

    if (retaddr) {
        /* now we have a real cpu fault.  */
        cpu_restore_state(cs, retaddr, true);
    }

    /* Raise Exception. */
    cpu_loop_exit(cs);
}

hwaddr ducky_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
  DuckyCPU *cpu = DUCKY_CPU(cs);
  uint32_t phy = addr;
  DuckyMMUResult res;
  int miss;

  miss = ducky_mmu_translate(&res, &cpu->env, addr, 0, 0);
  if (!miss)
    phy = res.phy;

  return phy;
}

#endif
