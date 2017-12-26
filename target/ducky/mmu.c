/*
 * Ducky MMU.
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
#ifndef CONFIG_USER_ONLY
#include "hw/loader.h"
#endif

#include "mmu.h"

#define DEBUG(msg, ...) do { qemu_log(msg, ##__VA_ARGS__); } while(0)

int ducky_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int size, int rw, int mmu_idx)
{
  address &= TARGET_PAGE_MASK;

  tlb_set_page(cs, address, address, PAGE_BITS, mmu_idx, TARGET_PAGE_SIZE);

  return 0;
}

int ducky_mmu_translate(DuckyMMUResult *res, CPUDuckyState *env, uint32_t vaddr, int rw, int mmu_idx)
{
  res->phy = vaddr;
  return 0;
}
