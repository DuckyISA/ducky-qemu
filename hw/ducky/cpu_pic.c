/*
 * Altera Ducky CPU PIC
 *
 * Copyright (c) 2017 Milos Prchlik <happz@happz.cz>
 *
 * Based on Altera Nios2 CPU PIC
 *
 * Copyright (c) 2016 Marek Vasut <marek.vasut@gmail.com>
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
#include "hw/irq.h"

#include "qemu/config-file.h"

static void ducky_pic_cpu_handler(void *opaque, int irq, int level)
{
    DuckyCPU *cpu = opaque;
    CPUDuckyState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    //fprintf(stderr, "ducky_pic_cpu_handler: irq=%d, level=%d\n", irq, level);
    //fflush(stderr);

    if (level) {
      env->pending_interrupts |= (1 << irq);
      cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else if (!level) {
      cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

qemu_irq *ducky_cpu_pic_init(DuckyCPU *cpu)
{
    return qemu_allocate_irqs(ducky_pic_cpu_handler, cpu, DUCKY_NR_IRQS);
}
