/*
 * Ducky cpu parameters for qemu.
 *
 * Copyright (c) 2017-2018 SiFive, Inc.
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef DUCKY_CPU_PARAM_H
#define DUCKY_CPU_PARAM_H 1

#define TARGET_LONG_BITS 32

#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32

#define TARGET_PAGE_BITS 8

#define NB_MMU_MODES     1
#define MMU_USER_IDX     0

#endif
