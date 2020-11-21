/*
    Copyright (c) 2020 jdeokkim

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#ifndef CPU_H
#define CPU_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define CPU_IMPL 
#define INST_IMPL 

#define RAM_SIZE 65536

/*
    SR_FLAG_CARRY:     (0b00000001, 0x01)
    SR_FLAG_PARITY:    (0b00000100, 0x04)
    SR_FLAG_AUX_CARRY: (0b00010000, 0x10)
    SR_FLAG_ZERO:      (0b01000000, 0x40)
    SR_FLAG_SIGN:      (0b10000000, 0x80)
*/

#define SR_FLAG_CARRY 0x01
#define SR_FLAG_PARITY 0x04
#define SR_FLAG_AUX_CARRY 0x10
#define SR_FLAG_ZERO 0x40
#define SR_FLAG_SIGN 0x80
 
/* 인텔 8080 CPU의 레지스터를 나타내는 구조체 */
typedef struct registers {
    uint8_t a;          // 누산기
    uint8_t b;          // ...
    uint8_t c;          // ...
    uint8_t d;          // ...
    uint8_t e;          // ...
    uint8_t h;          // ...
    uint8_t l;          // ...
    uint8_t status;     // 상태 레지스터
    uint16_t stack_ptr; // 스택 포인터
    uint16_t prog_ctr;  // 프로그램 카운터
} Registers;

/* 인텔 8080 CPU 버스를 나타내는 구조체 */
typedef struct buses {
    uint8_t *ram;
} Buses;

/* 인텔 8080 CPU를 나타내는 구조체 */
typedef struct cpu {
    Registers registers;
    Buses buses;
    bool halted;
    bool interrupt;
} CPU;

/* 인텔 8080 CPU의 명령어 피연산자를 나타내는 구조체 */
typedef struct operands {
    uint8_t operand1;
    uint8_t operand2;
} Operands;

/* 인텔 8080 CPU의 명령어를 나타내는 구조체 */
typedef struct instruction {
    const char *name;              // 명령어의 이름
    uint8_t size;                  // 명령어의 크기
    void (*execute)(
        CPU *cpu, 
        Operands ops
    );                             // 명령어에 대응하는 함수
} Instruction;

/* 인텔 8080 CPU의 명령어 집합 (0x00 - 0xff) */
extern const Instruction instruction_set[256];

/* 인텔 8080 CPU 진단 프로그램을 실행한다. */
CPU_IMPL void i8080_cpudiag(CPU *cpu);

/* 인텔 8080 CPU를 에뮬레이트한다. */
CPU_IMPL void i8080_emulate(CPU *cpu);

/* 인텔 8080 CPU의 상태 플래그 값을 해제한다. */
CPU_IMPL void i8080_flag_clear(CPU *cpu, uint8_t flag);

/* 인텔 8080 CPU의 상태 플래그 값을 반환한다. */
CPU_IMPL bool i8080_flag_get(CPU *cpu, uint8_t flag);

/* 인텔 8080 CPU의 상태 플래그 값을 설정한다. */
CPU_IMPL void i8080_flag_set(CPU *cpu, uint8_t flag);

/* 인텔 8080 CPU의 보조 캐리 플래그의 값을 업데이트한다. (산술 연산) */
CPU_IMPL void i8080_flag_update_ac_ari(CPU *cpu, uint8_t value1, uint8_t value2);

/* 인텔 8080 CPU의 캐리 플래그의 값을 업데이트한다. (8비트 산술 연산) */
CPU_IMPL void i8080_flag_update_cy8(CPU *cpu, uint16_t result);

/* 인텔 8080 CPU의 캐리 플래그의 값을 업데이트한다. (16비트 산술 연산) */
CPU_IMPL void i8080_flag_update_cy16(CPU *cpu, uint32_t result);

/* 인텔 8080 CPU의 패리티 플래그, 제로 플래그와 부호 플래그의 값을 업데이트한다. */
CPU_IMPL void i8080_flag_update_zsp(CPU *cpu, uint8_t result);

/* 인텔 8080 CPU의 주기억장치의 `mem_offset` 위치로 파일을 불러온다. */
CPU_IMPL size_t i8080_load_ram(CPU *cpu, const char *file_name, uint16_t mem_offset);

/* 인텔 8080 CPU의 X와 Y 레지스터에 저장된 메모리 주소에 있는 값을 읽는다. */
CPU_IMPL uint8_t i8080_mem_read(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 CPU의 X와 Y 레지스터에 저장된 메모리 주소에 있는 값을 수정한다. */
CPU_IMPL void i8080_mem_write(CPU *cpu, uint8_t *rx, uint8_t *ry, uint8_t value);

/* 인텔 8080 CPU 구조체를 초기화한다. */
CPU_IMPL CPU i8080_new(void);

/* 인텔 8080 명령어: `ADD r(X)` */
INST_IMPL void _i_add(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `SUB r(X)` */
INST_IMPL void _i_sub(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `INX rp(X, Y)` */
INST_IMPL void _i_inx(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 명령어: `DCX rp(X, Y)` */
INST_IMPL void _i_dcx(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 명령어: `DAD rp(X, Y)` */
INST_IMPL void _i_dad(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 명령어: `INR r(X)` */
INST_IMPL void _i_inr(CPU *cpu, uint8_t *rx);

/* 인텔 8080 명령어: `DCR r(X)` */
INST_IMPL void _i_dcr(CPU *cpu, uint8_t *rx);

/* 인텔 8080 명령어: `ANA r(X)` */
INST_IMPL void _i_ana(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `XRA r(X)` */
INST_IMPL void _i_xra(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `ORA r(X)` */
INST_IMPL void _i_ora(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `CMP r(X)` */
INST_IMPL void _i_cmp(CPU *cpu, uint16_t value);

/* 인텔 8080 명령어: `PUSH rp(X, Y)` */
INST_IMPL void _i_push(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 명령어: `POP r(X, Y)` */
INST_IMPL void _i_pop(CPU *cpu, uint8_t *rx, uint8_t *ry);

/* 인텔 8080 명령어: `RST n` */
INST_IMPL void _i_rst(CPU *cpu, uint8_t value);

/* 인텔 8080 명령어: `UNIMPL` (?) */
INST_IMPL void i_unimpl(CPU *cpu, Operands ops);

/* 
    :: DATA TRANSFER GROUP ::
*/

/* 인텔 8080 명령어: `MOV r(B), r(B)` (0x40) */
INST_IMPL void i_mov_b_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(C)` (0x41) */
INST_IMPL void i_mov_b_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(D)` (0x42) */
INST_IMPL void i_mov_b_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(E)` (0x43) */
INST_IMPL void i_mov_b_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(H)` (0x44) */
INST_IMPL void i_mov_b_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(L)` (0x45) */
INST_IMPL void i_mov_b_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), mem` (0x46) */
INST_IMPL void i_mov_b_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(B), r(A)` (0x47) */
INST_IMPL void i_mov_b_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(B)` (0x48) */
INST_IMPL void i_mov_c_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(C)` (0x49) */
INST_IMPL void i_mov_c_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(D)` (0x4a) */
INST_IMPL void i_mov_c_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(E)` (0x4b) */
INST_IMPL void i_mov_c_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(H)` (0x4c) */
INST_IMPL void i_mov_c_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(L)` (0x4d) */
INST_IMPL void i_mov_c_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), mem` (0x4e) */
INST_IMPL void i_mov_c_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(C), r(A)` (0x4f) */
INST_IMPL void i_mov_c_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(B)` (0x50) */
INST_IMPL void i_mov_d_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(C)` (0x51) */
INST_IMPL void i_mov_d_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(D)` (0x52) */
INST_IMPL void i_mov_d_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(E)` (0x53) */
INST_IMPL void i_mov_d_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(H)` (0x54) */
INST_IMPL void i_mov_d_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(L)` (0x55) */
INST_IMPL void i_mov_d_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), mem` (0x56) */
INST_IMPL void i_mov_d_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(D), r(A)` (0x57) */
INST_IMPL void i_mov_d_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(B)` (0x58) */
INST_IMPL void i_mov_e_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(C)` (0x59) */
INST_IMPL void i_mov_e_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(D)` (0x5a) */
INST_IMPL void i_mov_e_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(E)` (0x5b) */
INST_IMPL void i_mov_e_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(H)` (0x5c) */
INST_IMPL void i_mov_e_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(L)` (0x5d) */
INST_IMPL void i_mov_e_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), mem` (0x5e) */
INST_IMPL void i_mov_e_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(E), r(A)` (0x5f) */
INST_IMPL void i_mov_e_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(B)` (0x60) */
INST_IMPL void i_mov_h_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(C)` (0x61) */
INST_IMPL void i_mov_h_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(D)` (0x62) */
INST_IMPL void i_mov_h_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(E)` (0x63) */
INST_IMPL void i_mov_h_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(H)` (0x64) */
INST_IMPL void i_mov_h_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(L)` (0x65) */
INST_IMPL void i_mov_h_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), mem` (0x66) */
INST_IMPL void i_mov_h_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(H), r(A)` (0x67) */
INST_IMPL void i_mov_h_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(B)` (0x68) */
INST_IMPL void i_mov_l_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(C)` (0x69) */
INST_IMPL void i_mov_l_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(D)` (0x6a) */
INST_IMPL void i_mov_l_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(E)` (0x6b) */
INST_IMPL void i_mov_l_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(H)` (0x6c) */
INST_IMPL void i_mov_l_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(L)` (0x6d) */
INST_IMPL void i_mov_l_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), mem` (0x6e) */
INST_IMPL void i_mov_l_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(L), r(A)` (0x6f) */
INST_IMPL void i_mov_l_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(B)` (0x70) */
INST_IMPL void i_mov_mem_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(C)` (0x71) */
INST_IMPL void i_mov_mem_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(D)` (0x72) */
INST_IMPL void i_mov_mem_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(E)` (0x73) */
INST_IMPL void i_mov_mem_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(H)` (0x74) */
INST_IMPL void i_mov_mem_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(L)` (0x75) */
INST_IMPL void i_mov_mem_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV mem, r(A)` (0x77) */
INST_IMPL void i_mov_mem_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(B)` (0x78) */
INST_IMPL void i_mov_a_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(C)` (0x79) */
INST_IMPL void i_mov_a_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(D)` (0x7a) */
INST_IMPL void i_mov_a_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(E)` (0x7b) */
INST_IMPL void i_mov_a_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(H)` (0x7c) */
INST_IMPL void i_mov_a_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(L)` (0x7d) */
INST_IMPL void i_mov_a_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), mem` (0x7e) */
INST_IMPL void i_mov_a_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MOV r(A), r(E)` (0x7f) */
INST_IMPL void i_mov_a_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(B), data(8)` (0x06) */
INST_IMPL void i_mvi_b_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(C), data(8)` (0x0e) */
INST_IMPL void i_mvi_c_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(D), data(8)` (0x16) */
INST_IMPL void i_mvi_d_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(E), data(8)` (0x1e) */
INST_IMPL void i_mvi_e_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(H), data(8)` (0x26) */
INST_IMPL void i_mvi_h_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(L), data(8)` (0x2e) */
INST_IMPL void i_mvi_l_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI mem, data(8)` (0x36) */
INST_IMPL void i_mvi_mem_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `MVI r(A), data(8)` (0x3e) */
INST_IMPL void i_mvi_a_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LXI rp(B, C), data(16)` (0x01) */
INST_IMPL void i_lxi_bc_data16(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LXI rp(D, E), data(16)` (0x11) */
INST_IMPL void i_lxi_de_data16(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LXI rp(H, L), data(16)` (0x21) */
INST_IMPL void i_lxi_hl_data16(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LXI r(SP), data(16)` (0x31) */
INST_IMPL void i_lxi_sp_data16(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LDA addr` (0x3a) */
INST_IMPL void i_lda_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `STA addr` (0x32) */
INST_IMPL void i_sta_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LHLD addr` (0x2a) */
INST_IMPL void i_lhld_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SHLD addr` (0x22) */
INST_IMPL void i_shld_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LDAX rp(B, C)` (0x0a) */
INST_IMPL void i_ldax_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `LDAX rp(D, E)` (0x1a) */
INST_IMPL void i_ldax_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `STAX rp(B, C)` (0x02) */
INST_IMPL void i_stax_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `STAX rp(D, E)` (0x12) */
INST_IMPL void i_stax_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XCHG` (0xeb) */
INST_IMPL void i_xchg(CPU *cpu, Operands ops);

/* 
    :: ARITHMETIC GROUP ::
*/

/* 인텔 8080 명령어: `ADD r(B)` (0x80) */
INST_IMPL void i_add_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(C)` (0x81) */
INST_IMPL void i_add_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(D)` (0x82) */
INST_IMPL void i_add_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(E)` (0x83) */
INST_IMPL void i_add_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(H)` (0x84) */
INST_IMPL void i_add_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(L)` (0x85) */
INST_IMPL void i_add_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD mem` (0x86) */
INST_IMPL void i_add_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADD r(A)` (0x87) */
INST_IMPL void i_add_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(B)` (0x88) */
INST_IMPL void i_adc_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(C)` (0x89) */
INST_IMPL void i_adc_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(D)` (0x8a) */
INST_IMPL void i_adc_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(E)` (0x8b) */
INST_IMPL void i_adc_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(H)` (0x8c) */
INST_IMPL void i_adc_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(L)` (0x8d) */
INST_IMPL void i_adc_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC mem` (0x8e) */
INST_IMPL void i_adc_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADC r(A)` (0x8f) */
INST_IMPL void i_adc_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(B)` (0x90) */
INST_IMPL void i_sub_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(C)` (0x91) */
INST_IMPL void i_sub_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(D)` (0x92) */
INST_IMPL void i_sub_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(E)` (0x93) */
INST_IMPL void i_sub_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(H)` (0x94) */
INST_IMPL void i_sub_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(L)` (0x95) */
INST_IMPL void i_sub_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB mem` (0x96) */
INST_IMPL void i_sub_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUB r(A)` (0x97) */
INST_IMPL void i_sub_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(B)` (0x98) */
INST_IMPL void i_sbb_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(C)` (0x99) */
INST_IMPL void i_sbb_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(D)` (0x9a) */
INST_IMPL void i_sbb_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(E)` (0x9b) */
INST_IMPL void i_sbb_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(H)` (0x9c) */
INST_IMPL void i_sbb_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(L)` (0x9d) */
INST_IMPL void i_sbb_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB mem` (0x9e) */
INST_IMPL void i_sbb_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBB r(A)` (0x9f) */
INST_IMPL void i_sbb_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ADI data(8)` (0xc6) */
INST_IMPL void i_adi_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ACI data(8)` (0xce) */
INST_IMPL void i_aci_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SUI data(8)` (0xd6) */
INST_IMPL void i_sui_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SBI data(8)` (0xde) */
INST_IMPL void i_sbi_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(B)` (0x04) */
INST_IMPL void i_inr_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(C)` (0x0c) */
INST_IMPL void i_inr_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(D)` (0x14) */
INST_IMPL void i_inr_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(E)` (0x1c) */
INST_IMPL void i_inr_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(H)` (0x24) */
INST_IMPL void i_inr_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(L)` (0x2c) */
INST_IMPL void i_inr_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR mem` (0x34) */
INST_IMPL void i_inr_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INR r(A)` (0x3c) */
INST_IMPL void i_inr_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(B)` (0x05) */
INST_IMPL void i_dcr_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(C)` (0x0d) */
INST_IMPL void i_dcr_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(D)` (0x15) */
INST_IMPL void i_dcr_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(E)` (0x1d) */
INST_IMPL void i_dcr_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(H)` (0x25) */
INST_IMPL void i_dcr_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(L)` (0x2d) */
INST_IMPL void i_dcr_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR mem` (0x35) */
INST_IMPL void i_dcr_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCR r(A)` (0x3d) */
INST_IMPL void i_dcr_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INX rp(H, L)` (0x23) */
INST_IMPL void i_inx_hl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCX r(SP)` (0x3b) */
INST_IMPL void i_dcx_sp(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INX rp(B, C)` (0x03) */
INST_IMPL void i_inx_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INX rp(D, E)` (0x13) */
INST_IMPL void i_inx_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `INX r(SP)` (0x33) */
INST_IMPL void i_inx_sp(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCX rp(B, C)` (0x0b) */
INST_IMPL void i_dcx_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCX rp(D, E)` (0x1b) */
INST_IMPL void i_dcx_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DCX rp(H, L)` (0x2b) */
INST_IMPL void i_dcx_hl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DAD rp(B, C)` (0x09) */
INST_IMPL void i_dad_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DAD rp(D, E)` (0x09) */
INST_IMPL void i_dad_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DAD rp(H, L)` (0x29) */
INST_IMPL void i_dad_hl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DAD r(SP)` (0x39) */
INST_IMPL void i_dad_sp(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DAA` (0x27) */
INST_IMPL void i_daa(CPU *cpu, Operands ops);

/* 
    :: LOGICAL GROUP ::
*/

/* 인텔 8080 명령어: `ANA r(B)` (0xa0) */
INST_IMPL void i_ana_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(C)` (0xa1) */
INST_IMPL void i_ana_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(D)` (0xa2) */
INST_IMPL void i_ana_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(E)` (0xa3) */
INST_IMPL void i_ana_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(H)` (0xa4) */
INST_IMPL void i_ana_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(L)` (0xa5) */
INST_IMPL void i_ana_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA mem` (0xa6) */
INST_IMPL void i_ana_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANA r(A)` (0xa7) */
INST_IMPL void i_ana_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(B)` (0xa8) */
INST_IMPL void i_xra_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(C)` (0xa9) */
INST_IMPL void i_xra_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(D)` (0xaa) */
INST_IMPL void i_xra_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(E)` (0xab) */
INST_IMPL void i_xra_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(H)` (0xac) */
INST_IMPL void i_xra_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(L)` (0xad) */
INST_IMPL void i_xra_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA mem` (0xae) */
INST_IMPL void i_xra_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRA r(A)` (0xaf) */
INST_IMPL void i_xra_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(B)` (0xb0) */
INST_IMPL void i_ora_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(C)` (0xb1) */
INST_IMPL void i_ora_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(D)` (0xb2) */
INST_IMPL void i_ora_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(E)` (0xb3) */
INST_IMPL void i_ora_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(H)` (0xb4) */
INST_IMPL void i_ora_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(L)` (0xb5) */
INST_IMPL void i_ora_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA mem` (0xb6) */
INST_IMPL void i_ora_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORA r(A)` (0xb7) */
INST_IMPL void i_ora_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(B)` (0xb8) */
INST_IMPL void i_cmp_b(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(C)` (0xb9) */
INST_IMPL void i_cmp_c(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(D)` (0xba) */
INST_IMPL void i_cmp_d(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(E)` (0xbb) */
INST_IMPL void i_cmp_e(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(H)` (0xbc) */
INST_IMPL void i_cmp_h(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(L)` (0xbd) */
INST_IMPL void i_cmp_l(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP mem` (0xbe) */
INST_IMPL void i_cmp_mem(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMP r(A)` (0xbf) */
INST_IMPL void i_cmp_a(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ANI data(8)` (0xe6) */
INST_IMPL void i_ani_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XRI data(8)` (0xee) */
INST_IMPL void i_xri_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `ORI data(8)` (0xf6) */
INST_IMPL void i_ori_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CPI data(8)` (0xfe) */
INST_IMPL void i_cpi_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RLC` (0x07) */
INST_IMPL void i_rlc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RRC` (0x0f) */
INST_IMPL void i_rrc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RAL` (0x17) */
INST_IMPL void i_ral(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RAR` (0x1f) */
INST_IMPL void i_rar(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMA` (0x2f) */
INST_IMPL void i_cma(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CMC` (0x3f) */
INST_IMPL void i_cmc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `STC` (0x37) */
INST_IMPL void i_stc(CPU *cpu, Operands ops);

/* 
    :: BRANCH GROUP ::
*/

/* 인텔 8080 명령어: `JMP addr` (0xc3) */
INST_IMPL void i_jmp_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JNZ addr` (0xc2) */
INST_IMPL void i_jnz_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JZ addr` (0xca) */
INST_IMPL void i_jz_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JNC addr` (0xd2) */
INST_IMPL void i_jnc_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JC addr` (0xda) */
INST_IMPL void i_jc_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JPO addr` (0xe2) */
INST_IMPL void i_jpo_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JPE addr` (0xea) */
INST_IMPL void i_jpe_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JP addr` (0xf2) */
INST_IMPL void i_jp_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `JM addr` (0xfa) */
INST_IMPL void i_jm_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CALL addr` (0xcd) */
INST_IMPL void i_call_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CNZ addr` (0xc4) */
INST_IMPL void i_cnz_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CZ addr` (0xcc) */
INST_IMPL void i_cz_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CNC addr` (0xd4) */
INST_IMPL void i_cnc_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CC addr` (0xdc) */
INST_IMPL void i_cc_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CPO addr` (0xe4) */
INST_IMPL void i_cpo_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CPE addr` (0xec) */
INST_IMPL void i_cpe_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CP addr` (0xf4) */
INST_IMPL void i_cp_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `CM addr` (0xfc) */
INST_IMPL void i_cm_addr(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RET` (0xc9) */
INST_IMPL void i_ret(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RNZ` (0xc0) */
INST_IMPL void i_rnz(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RZ` (0xc8) */
INST_IMPL void i_rz(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RNC` (0xd0) */
INST_IMPL void i_rnc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RC` (0xd8) */
INST_IMPL void i_rc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RPO` (0xe0) */
INST_IMPL void i_rpo(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RPE` (0xe8) */
INST_IMPL void i_rpe(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RP` (0xf0) */
INST_IMPL void i_rp(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RM` (0xf8) */
INST_IMPL void i_rm(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 0` (0xc7) */
INST_IMPL void i_rst_0(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 1` (0xcf) */
INST_IMPL void i_rst_1(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 2` (0xd7) */
INST_IMPL void i_rst_2(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 3` (0xdf) */
INST_IMPL void i_rst_3(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 4` (0xe7) */
INST_IMPL void i_rst_4(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 5` (0xef) */
INST_IMPL void i_rst_5(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 6` (0xf7) */
INST_IMPL void i_rst_6(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `RST 7` (0xff) */
INST_IMPL void i_rst_7(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `PCHL` (0xe9) */
INST_IMPL void i_pchl(CPU *cpu, Operands ops);

/* 
    :: STACK, I/O AND MACHINE CONTROL GROUP ::
*/

/* 인텔 8080 명령어: `PUSH rp(B, C)` (0xc5) */
INST_IMPL void i_push_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `PUSH rp(D, E)` (0xd5) */
INST_IMPL void i_push_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `PUSH rp(H, L)` (0xe5) */
INST_IMPL void i_push_hl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `PUSH psw` (0xf5) */
INST_IMPL void i_push_psw(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `POP rp(B, C)` (0xc1) */
INST_IMPL void i_pop_bc(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `POP rp(D, E)` (0xd1) */
INST_IMPL void i_pop_de(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `POP rp(H, L)` (0xe1) */
INST_IMPL void i_pop_hl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `POP psw` (0xf1) */
INST_IMPL void i_pop_psw(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `XTHL` (0xe3) */
INST_IMPL void i_xthl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SPHL` (0xf9) */
INST_IMPL void i_sphl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `IN data(8)` (0xdb) */
INST_IMPL void i_in_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `OUT data(8)` (0xd3) */
INST_IMPL void i_out_data8(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `SPHL` (0xf9) */
INST_IMPL void i_sphl(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `EI` (0xf3) */
INST_IMPL void i_ei(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `DI` (0xfb) */
INST_IMPL void i_di(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `HLT` (0x76) */
INST_IMPL void i_hlt(CPU *cpu, Operands ops);

/* 인텔 8080 명령어: `NOP` (0x00) */
INST_IMPL void i_nop(CPU *cpu, Operands ops);

#endif