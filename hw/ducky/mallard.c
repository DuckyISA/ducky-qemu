/*
 * "Mallard" board
 *
 * Copyright (c) 2017-2018 Milos Prchlik <happz@happz.cz>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"

#include "hw/sysbus.h"
#include "hw/hw.h"
#include "hw/char/serial.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "qemu/config-file.h"
#include "hw/loader.h"
#include "hw/irq.h"

static int64_t cpu_to_timer_ticks(int64_t cpu_ticks, uint32_t frequency)
{
  return muldiv64(cpu_ticks, NANOSECONDS_PER_SECOND, frequency);
}

static void cpu_timer_set_limit(DuckyCPUTimer *timer, uint64_t limit)
{
  int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

  timer->enabled = 1;

  int64_t expires = cpu_to_timer_ticks(limit, timer->frequency) + timer->clock_offset + now;

  if (expires < now)
    expires = now + 1;

  timer_mod(timer->timer, expires);
}

static void tick_irq(void *opaque)
{
  DuckyCPU *cpu = opaque;
  CPUDuckyState *env = &cpu->env;
  DuckyCPUTimer *timer = env->tick_timer;

  if (!timer->enabled)
    return;

  qemu_irq_raise(timer->irq);

  cpu_timer_set_limit(timer, 20);
}

static DuckyCPUTimer *cpu_timer_create(const char *name, DuckyCPU *cpu, qemu_irq irq, uint32_t frequency)
{
  DuckyCPUTimer *timer = g_malloc0(sizeof(DuckyCPUTimer));

  timer->name = name;
  timer->frequency = frequency;
  timer->enabled = 0;
  timer->clock_offset = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
  timer->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, tick_irq, cpu);
  timer->irq = irq;

  return timer;
}

static void mallard_board_init(MachineState *machine)
{
  CPUState *cs;
  DuckyCPU *cpu;

	/* Configuration map */
  hwaddr ram_base = 0x00000000;
  hwaddr ram_size = 16 * 1024 * 1024;

  hwaddr boot_rom_base = DEFAULT_BOOTROM_ADDRESS;
  hwaddr boot_rom_size = DEFAULT_BOOTROM_SIZE;

  //hwaddr timer0_base = 0x00030700;
  int timer0_irq = DUCKY_IRQ_TIMER;

  hwaddr uart0_base = 0x00003080;
  int uart0_irq = DUCKY_IRQ_UART;

  /* RAM */
  MemoryRegion *address_space = get_system_memory();

  MemoryRegion *ram = g_new(MemoryRegion, 1);
  memory_region_init_ram(ram, NULL, "ducky.ram", ram_size, &error_fatal);
  memory_region_add_subregion(address_space, ram_base, ram);

  MemoryRegion *boot_rom = g_new(MemoryRegion, 1);
  memory_region_init_rom(boot_rom, NULL, "ducky.boot-rom", boot_rom_size, &error_fatal);
  memory_region_add_subregion_overlap(address_space, boot_rom_base, boot_rom, 0);

  /* Create CPU */
  cs = cpu_create(machine->cpu_type);
  if (!cs) {
    fprintf(stderr, "Unable to find CPU definition!\n");
    exit(1);
  }

  cpu = DUCKY_CPU(cs);
  CPUDuckyState *env = &cpu->env;

  /* Create IRQ lines */
  env->irqs = ducky_cpu_pic_init(cpu);

  /* Register timer */
  env->tick_timer = cpu_timer_create("tick", cpu, env->irqs[timer0_irq], 100);
  cpu_timer_set_limit(env->tick_timer, 1);

  /* Register UART */
  serial_mm_init(address_space, uart0_base, 0, env->irqs[uart0_irq], 115200, serial_hd(0), DEVICE_NATIVE_ENDIAN);
}

static void mallard_machine_init(struct MachineClass *mc)
{
    mc->desc = "Mallard Ducky board";
    mc->init = mallard_board_init;
    mc->default_cpu_type = DUCKY_CPU_TYPE_NAME("ducky");
}

DEFINE_MACHINE("mallard-board", mallard_machine_init);
