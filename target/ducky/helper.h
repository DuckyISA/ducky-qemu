/*
 * Ducky helper defines
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

DEF_HELPER_FLAGS_2(exception,  TCG_CALL_NO_WG, void, env, i32)
DEF_HELPER_FLAGS_3(exception1, TCG_CALL_NO_WG, void, env, i32, i32)
DEF_HELPER_FLAGS_4(exception2, TCG_CALL_NO_WG, void, env, i32, i32, i32)
DEF_HELPER_FLAGS_5(exception3, TCG_CALL_NO_WG, void, env, i32, i32, i32, i32)
DEF_HELPER_FLAGS_1(exit_exception, TCG_CALL_NO_WG, void, env)

DEF_HELPER_1(idle, void, env)
DEF_HELPER_2(hlt, void, env, int)

DEF_HELPER_4(debug_load, void, env, int, int, int)
DEF_HELPER_4(debug_store, void, env, int, int, int)

DEF_HELPER_1(log_cpu_state, void, env)
DEF_HELPER_2(log_arb, void, env, i64)

DEF_HELPER_2(math_stack_push, void, env, i64)
DEF_HELPER_2(math_stack_zext_push, void, env, i32)
DEF_HELPER_2(math_stack_sext_push, void, env, i32)
DEF_HELPER_1(math_stack_pop, i64, env)
DEF_HELPER_1(math_stack_divl, void, env)
DEF_HELPER_1(math_stack_modl, void, env)
DEF_HELPER_1(math_stack_symmodl, void, env)
DEF_HELPER_1(math_stack_symdivl, void, env)
DEF_HELPER_1(math_stack_umodl, void, env)
DEF_HELPER_1(math_stack_udivl, void, env)
DEF_HELPER_1(math_stack_mull, void, env)
DEF_HELPER_1(math_stack_swp, void, env)
DEF_HELPER_1(math_stack_dup2, void, env)
DEF_HELPER_1(math_stack_dup, void, env)
DEF_HELPER_1(math_stack_drop, void, env)
DEF_HELPER_1(math_stack_addl, void, env)
