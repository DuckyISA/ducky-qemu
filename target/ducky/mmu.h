#ifndef DUCKY_MMU_H
#define DUCKY_MMU_H

#include "cpu.h"

typedef struct {
    uint32_t phy;
    uint32_t pfn;
    int cause_op;
} DuckyMMUResult;

extern int ducky_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int size, int rw, int mmu_idx);
extern int ducky_mmu_translate(DuckyMMUResult *res, CPUDuckyState *env, uint32_t vaddr, int rw, int mmu_idx);
extern hwaddr ducky_cpu_get_phys_page_debug(CPUState *cs, vaddr addr);

#endif /* ifndef DUCKY_MMU_H */
