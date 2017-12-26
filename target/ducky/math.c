#include <math.h>
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"

#define POP() env->math_stack[--env->math_stack_ptr]
#define PUSH(_value) do { env->math_stack[env->math_stack_ptr++] = (_value); } while (0)

static inline void math_stack_push(CPUDuckyState *env, uint64_t value)                                                
{
  env->math_stack[env->math_stack_ptr++] = value;
}

static inline void math_stack_sext_push(CPUDuckyState *env, uint32_t value)
{
  uint64_t u = (uint32_t)value;

  if (u & SIGNED_MASK)
    u |= 0xFFFFFFFF00000000;

  PUSH(u);
}

static inline uint64_t math_stack_pop(CPUDuckyState *env)
{
  return env->math_stack[--env->math_stack_ptr];
}

void HELPER(math_stack_push)(CPUDuckyState *env, uint64_t value)
{
  PUSH(value);
}

void HELPER(math_stack_zext_push)(CPUDuckyState *env, uint32_t value)
{
  PUSH((uint64_t)value);
}

void HELPER(math_stack_sext_push)(CPUDuckyState *env, uint32_t value)
{
  math_stack_sext_push(env, value);
}

uint64_t HELPER(math_stack_pop)(CPUDuckyState *env)
{
  return POP();
}

static inline int64_t __floor_div(int64_t x, int64_t y)
{
  int64_t q = x / y;
  int64_t r = x % y;

  if ((r != 0) && ((r < 0) != (y < 0)))
    --q;

  return q;
}

static inline int64_t __floor_mod(int64_t x, int64_t y)
{
  int64_t r = x % y;
  if ((r != 0) && ((r < 0) != (y < 0)))
    r += y;

  return r;
}

void HELPER(math_stack_divl)(CPUDuckyState *env)
{
  int64_t y = POP();
  int64_t x = POP();

  PUSH(__floor_div(x, y));
}

void HELPER(math_stack_modl)(CPUDuckyState *env)
{
  int64_t y = POP();
  int64_t x = POP();

  PUSH(__floor_mod(x, y));
}

void HELPER(math_stack_addl)(CPUDuckyState *env)
{
  uint64_t x = POP();
  uint64_t y = POP();

  PUSH(x + y);
}

void HELPER(math_stack_symmodl)(CPUDuckyState *env)
{
  int64_t y = POP();
  int64_t x = POP();
  int64_t r;

  if ((x < 0) == (y < 0)) {
    r = x % y;
  } else {
    r = (int64_t)fmod((double)x, (double)y);
  }

  //fprintf(stderr, "math.symmodl: %ld %% %ld = %ld\n", x, y, r);
  //fflush(stderr);

  PUSH(r);
}

void HELPER(math_stack_symdivl)(CPUDuckyState *env)
{
  int64_t y = POP();
  int64_t x = POP();
  int64_t r = x / y;

  //fprintf(stderr, "math.symdivl: %ld / %ld = %ld\n", x, y, r);
  //fflush(stderr);

  PUSH(r);
}

void HELPER(math_stack_umodl)(CPUDuckyState *env)
{
  uint64_t divider = POP();
  uint64_t value = POP();

  PUSH(value % divider);
}

void HELPER(math_stack_udivl)(CPUDuckyState *env)
{
  uint64_t divider = POP();
  uint64_t value = POP();

  PUSH(value / divider);
}

void HELPER(math_stack_mull)(CPUDuckyState *env)
{
  int64_t x = POP();
  int64_t y = POP();
  int64_t r = x * y;

  //fprintf(stderr, "math.mull: %ld * %ld = %ld\n", x, y, r);
  //fflush(stderr);

  PUSH(r);
}

void HELPER(math_stack_swp)(CPUDuckyState *env)
{
  uint64_t x = POP();
  uint64_t y = POP();

  PUSH(x);
  PUSH(y);
}

void HELPER(math_stack_dup)(CPUDuckyState *env)
{
  uint64_t a = POP();

  PUSH(a);
  PUSH(a);
}

void HELPER(math_stack_dup2)(CPUDuckyState *env)
{
  uint64_t a = POP();
  uint64_t b = POP();

  PUSH(b);
  PUSH(a);
  PUSH(b);
  PUSH(a);
}

void HELPER(math_stack_drop)(CPUDuckyState *env)
{
  env->math_stack_ptr--;
}
