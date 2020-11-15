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

#include "cpu.h"

/* 
    인텔 8080 CPU의 명령어 집합.
    
    1. r(X): 레지스터 X
    2. rp(X, Y): 레지스터 X와 Y
    3. data(x): x비트의 데이터
    4. addr: 하위 8비트 (첫 번째 피연산자)와 상위 8비트 (두 번째 피연산자)로 이루어진 16비트 주소
    5. mem: 하위 8비트 (레지스터 L)와 상위 8비트 (레지스터 H)로 이루어진 16비트 주소
    6. psw: 누산기 + 상태 레지스터의 플래그
*/
const Instruction instruction_set[256] = {
    
    /* 0x00 - 0x0f */
    
    { "NOP", 1, i_nop },
    { "LXI rp(B, C), data(16)", 3, i_lxi_bc_data16 },
    { "STAX rp(B, C)", 1, i_stax_bc },
    { "INX rp(B, C)", 1, i_inx_bc },
    { "INR r(B)", 1, i_inr_b },
    { "DCR r(B)", 1, i_dcr_b },
    { "MVI r(B), data(8)", 2, i_mvi_b_data8 },
    { "RLC", 1, i_rlc },
    { "UNIMPL", 1, i_unimpl },
    { "DAD rp(B, C)", 1, i_dad_bc },
    { "LDAX rp(B, C)", 1, i_ldax_bc },
    { "DCX rp(B, C)", 1, i_dcx_bc },
    { "INR r(C)", 1, i_inr_c },
    { "DCR r(C)", 1, i_dcr_c },
    { "MVI r(C), data(8)", 2, i_mvi_c_data8 },
    { "RRC", 1, i_rrc },
    
    /* 0x10 - 0x1f */
    
    { "UNIMPL", 1, i_unimpl },
    { "LXI rp(D, E), data(16)", 3, i_lxi_de_data16 },
    { "STAX rp(D, E)", 1, i_stax_de },
    { "INX rp(D, E)", 1, i_inx_de },
    { "INR r(D)", 1, i_inr_d },
    { "DCR r(D)", 1, i_dcr_d },
    { "MVI r(D), data(8)", 2, i_mvi_d_data8 },
    { "RAL", 1, i_ral },
    { "UNIMPL", 1, i_unimpl },
    { "DAD rp(D, E)", 1, i_dad_de },
    { "LDAX rp(D, E)", 1, i_ldax_de },
    { "DCX rp(D, E)", 1, i_dcx_de },
    { "INR r(E)", 1, i_inr_e },
    { "DCR r(E)", 1, i_dcr_e },
    { "MVI r(E), data(8)", 2, i_mvi_e_data8 },
    { "RAR", 1, i_rar },
    
    /* 0x20 - 0x2f */
    
    { "UNIMPL", 1, i_unimpl },
    { "LXI rp(H, L), data(16)", 3, i_lxi_hl_data16 },
    { "SHLD addr", 3, i_shld_addr },
    { "INX rp(H, L)", 1, i_inx_hl },
    { "INR r(H)", 1, i_inr_h },
    { "DCR r(H)", 1, i_dcr_h },
    { "MVI r(H), data(8)", 2, i_mvi_h_data8 },
    { "DAA", 1, i_daa },
    { "UNIMPL", 1, i_unimpl },
    { "DAD rp(H, L)", 1, i_dad_hl },
    { "LHLD addr", 3, i_lhld_addr },
    { "DCX rp(H, L)", 1, i_dcx_hl },
    { "INR r(L)", 1, i_inr_l },
    { "DCR r(L)", 1, i_dcr_l },
    { "MVI r(L), data(8)", 2, i_mvi_l_data8 }, 
    { "CMA", 1, i_cma },
    
    /* 0x30 - 0x3f */
    
    { "UNIMPL", 1, i_unimpl },
    { "LXI r(SP)", 3, i_lxi_sp_data16 },
    { "STA addr", 3, i_sta_addr },
    { "INX r(SP)", 1, i_inx_sp },
    { "INR mem", 1, i_inr_mem },
    { "DCR mem", 1, i_dcr_mem },
    { "MVI mem, data(8)", 2, i_mvi_mem_data8 },
    { "STC", 1, i_stc },
    { "UNIMPL", 1, i_unimpl },
    { "DAD r(SP)", 1, i_dad_sp },
    { "LDA addr", 3, i_lda_addr },
    { "DCX r(SP)", 1, i_dcx_sp },
    { "INR r(A)", 1, i_inr_a },
    { "DCR r(A)", 1, i_dcr_a },
    { "MVI r(A), data(8)", 2, i_mvi_a_data8 },
    { "CMC", 1, i_cmc },
    
    /* 0x40 - 0x4f */
    
    { "MOV r(B), r(B)", 1, i_mov_b_b },
    { "MOV r(B), r(C)", 1, i_mov_b_c },
    { "MOV r(B), r(D)", 1, i_mov_b_d },
    { "MOV r(B), r(E)", 1, i_mov_b_e },
    { "MOV r(B), r(H)", 1, i_mov_b_h },
    { "MOV r(B), r(L)", 1, i_mov_b_l },
    { "MOV r(B), mem", 1, i_mov_b_mem },
    { "MOV r(B), r(A)", 1, i_mov_b_a },
    { "MOV r(C), r(B)", 1, i_mov_c_b },
    { "MOV r(C), r(C)", 1, i_mov_c_c },
    { "MOV r(C), r(D)", 1, i_mov_c_d },
    { "MOV r(C), r(E)", 1, i_mov_c_e },
    { "MOV r(C), r(H)", 1, i_mov_c_h },
    { "MOV r(C), r(L)", 1, i_mov_c_l },
    { "MOV r(C), mem", 1, i_mov_c_mem },
    { "MOV r(C), r(A)", 1, i_mov_c_a },
    
    /* 0x50 - 0x5f */
    
    { "MOV r(D), r(B)", 1, i_mov_d_b },
    { "MOV r(D), r(C)", 1, i_mov_d_c },
    { "MOV r(D), r(D)", 1, i_mov_d_d },
    { "MOV r(D), r(E)", 1, i_mov_d_e },
    { "MOV r(D), r(H)", 1, i_mov_d_h },
    { "MOV r(D), r(L)", 1, i_mov_d_l },
    { "MOV r(D), mem", 1, i_mov_d_mem },
    { "MOV r(D), r(A)", 1, i_mov_d_a },
    { "MOV r(E), r(B)", 1, i_mov_e_b },
    { "MOV r(E), r(C)", 1, i_mov_e_c },
    { "MOV r(E), r(D)", 1, i_mov_e_d },
    { "MOV r(E), r(E)", 1, i_mov_e_e },
    { "MOV r(E), r(H)", 1, i_mov_e_h },
    { "MOV r(E), r(L)", 1, i_mov_e_l },
    { "MOV r(E), mem", 1, i_mov_e_mem },
    { "MOV r(E), r(A)", 1, i_mov_e_a },
    
    /* 0x60 - 0x6f */
    
    { "MOV r(H), r(B)", 1, i_mov_h_b },
    { "MOV r(H), r(C)", 1, i_mov_h_c },
    { "MOV r(H), r(D)", 1, i_mov_h_d },
    { "MOV r(H), r(E)", 1, i_mov_h_e },
    { "MOV r(H), r(H)", 1, i_mov_h_h },
    { "MOV r(H), r(L)", 1, i_mov_h_l },
    { "MOV r(H), mem", 1, i_mov_h_mem },
    { "MOV r(H), r(A)", 1, i_mov_h_a },
    { "MOV r(L), r(B)", 1, i_mov_l_b },
    { "MOV r(L), r(C)", 1, i_mov_l_c },
    { "MOV r(L), r(D)", 1, i_mov_l_d },
    { "MOV r(L), r(E)", 1, i_mov_l_e },
    { "MOV r(L), r(H)", 1, i_mov_l_h },
    { "MOV r(L), r(L)", 1, i_mov_l_l },
    { "MOV r(L), mem", 1, i_mov_l_mem },
    { "MOV r(L), r(A)", 1, i_mov_l_a },
    
    /* 0x70 - 0x7f */
    
    { "MOV mem, r(B)", 1, i_mov_mem_b },
    { "MOV mem, r(C)", 1, i_mov_mem_c },
    { "MOV mem, r(D)", 1, i_mov_mem_d },
    { "MOV mem, r(E)", 1, i_mov_mem_e },
    { "MOV mem, r(H)", 1, i_mov_mem_h },
    { "MOV mem, r(L)", 1, i_mov_mem_l },
    { "HLT", 1, i_hlt },
    { "MOV mem, r(A)", 1, i_mov_mem_a },
    { "MOV r(A), r(B)", 1, i_mov_a_b },
    { "MOV r(A), r(C)", 1, i_mov_a_c },
    { "MOV r(A), r(D)", 1, i_mov_a_d },
    { "MOV r(A), r(E)", 1, i_mov_a_e },
    { "MOV r(A), r(H)", 1, i_mov_a_h },
    { "MOV r(A), r(L)", 1, i_mov_a_l },
    { "MOV r(A), mem", 1, i_mov_a_mem },
    { "MOV r(A), r(A)", 1, i_mov_a_a },
    
    /* 0x80 - 0x8f */
    
    { "ADD r(B)", 1, i_add_b },
    { "ADD r(C)", 1, i_add_c },
    { "ADD r(D)", 1, i_add_d },
    { "ADD r(E)", 1, i_add_e },
    { "ADD r(H)", 1, i_add_h },
    { "ADD r(L)", 1, i_add_l },
    { "ADD mem", 1, i_add_mem },
    { "ADD r(A)", 1, i_add_a },
    { "ADC r(B)", 1, i_adc_b },
    { "ADC r(C)", 1, i_adc_c },
    { "ADC r(D)", 1, i_adc_d },
    { "ADC r(E)", 1, i_adc_e },
    { "ADC r(H)", 1, i_adc_h },
    { "ADC r(L)", 1, i_adc_l },
    { "ADC mem", 1, i_adc_mem },
    { "ADC r(A)", 1, i_adc_a },
    
    /* 0x90 - 0x9f */
    
    { "SUB r(B)", 1, i_sub_b },
    { "SUB r(C)", 1, i_sub_c },
    { "SUB r(D)", 1, i_sub_d },
    { "SUB r(E)", 1, i_sub_e },
    { "SUB r(H)", 1, i_sub_h },
    { "SUB r(L)", 1, i_sub_l },
    { "SUB mem", 1, i_sub_mem },
    { "SUB r(A)", 1, i_sub_a },
    { "SBB r(B)", 1, i_sbb_b },
    { "SBB r(C)", 1, i_sbb_c },
    { "SBB r(D)", 1, i_sbb_d },
    { "SBB r(E)", 1, i_sbb_e },
    { "SBB r(H)", 1, i_sbb_h },
    { "SBB r(L)", 1, i_sbb_l },
    { "SBB mem", 1, i_sbb_mem },
    { "SBB r(A)", 1, i_sbb_a },
    
    /* 0xa0 - 0xaf */
    
    { "ANA r(B)", 1, i_ana_b },
    { "ANA r(C)", 1, i_ana_c },
    { "ANA r(D)", 1, i_ana_d },
    { "ANA r(E)", 1, i_ana_e },
    { "ANA r(H)", 1, i_ana_h },
    { "ANA r(L)", 1, i_ana_l },
    { "ANA mem", 1, i_ana_mem },
    { "ANA r(A)", 1, i_ana_a },
    { "XRA r(B)", 1, i_xra_b },
    { "XRA r(C)", 1, i_xra_c },
    { "XRA r(D)", 1, i_xra_d },
    { "XRA r(E)", 1, i_xra_e },
    { "XRA r(H)", 1, i_xra_h },
    { "XRA r(L)", 1, i_xra_l },
    { "XRA mem", 1, i_xra_mem },
    { "XRA r(A)", 1, i_xra_a },
    
    /* 0xb0 - 0xbf */
    
    { "ORA r(B)", 1, i_ora_b },
    { "ORA r(C)", 1, i_ora_c }, 
    { "ORA r(D)", 1, i_ora_d },
    { "ORA r(E)", 1, i_ora_e },
    { "ORA r(H)", 1, i_ora_h },
    { "ORA r(L)", 1, i_ora_l },
    { "ORA mem", 1, i_ora_mem },
    { "ORA r(A)", 1, i_ora_a },
    { "CMP r(B)", 1, i_cmp_b },
    { "CMP r(C)", 1, i_cmp_c },
    { "CMP r(D)", 1, i_cmp_d },
    { "CMP r(E)", 1, i_cmp_e },
    { "CMP r(H)", 1, i_cmp_h },
    { "CMP r(L)", 1, i_cmp_l },
    { "CMP mem", 1, i_cmp_mem },
    { "CMP r(A)", 1, i_cmp_a },
    
    /* 0xc0 - 0xcf */
    
    { "RNZ", 1, i_rnz },
    { "POP rp(B, C)", 1, i_pop_bc },
    { "JNZ addr", 3, i_jnz_addr },
    { "JMP addr", 3, i_jmp_addr },
    { "CNZ addr", 3, i_cnz_addr },
    { "PUSH rp(B, C)", 1, i_push_bc },
    { "ADI data(8)", 2, i_adi_data8 },
    { "RST 0", 1, i_rst_0 },
    { "RZ", 1, i_rz },
    { "RET", 1, i_ret },
    { "JZ addr", 3, i_jz_addr },
    { "UNIMPL", 1, i_unimpl },
    { "CZ addr", 3, i_cz_addr }, 
    { "CALL addr", 3, i_call_addr },
    { "ACI data(8)", 2, i_aci_data8 },
    { "RST 1", 1, i_rst_1 },
    
    /* 0xd0 - 0xdf */
    
    { "RNC", 1, i_rnc },
    { "POP rp(D, E)", 1, i_pop_de },
    { "JNC addr", 3, i_jnc_addr },
    { "OUT data(8)", 2, i_out_data8 },
    { "CNC addr", 3, i_cnc_addr },
    { "PUSH rp(D, E)", 1, i_push_de },
    { "SUI data(8)", 2, i_sui_data8 },
    { "RST 2", 1, i_rst_2 },
    { "RC", 1, i_rc },
    { "UNIMPL", 1, i_unimpl },
    { "JC addr", 3, i_jc_addr },
    { "IN data(8)", 2, i_in_data8 },
    { "CC addr", 3, i_cc_addr },
    { "UNIMPL", 1, i_unimpl },
    { "SBI data(8)", 2, i_sbi_data8 },
    { "RST 3", 1, i_rst_3 },
    
    /* 0xe0 - 0xef */
    
    { "RPO", 1, i_rpo },
    { "POP rp(H, L)", 1, i_pop_hl },
    { "JPO addr", 3, i_jpo_addr },
    { "XTHL", 1, i_xthl },
    { "CPO addr", 3, i_cpo_addr },
    { "PUSH rp(H, L)", 1, i_push_hl },
    { "ANI data(8)", 2, i_ani_data8 },
    { "RST 4", 1, i_rst_4 },
    { "RPE", 1, i_rpe },
    { "PCHL", 1, i_pchl },
    { "JPE addr", 3, i_jpe_addr },
    { "XCHG", 1, i_xchg },
    { "CPE addr", 3, i_cpe_addr },
    { "UNIMPL", 1, i_unimpl },
    { "XRI data(8)", 2, i_xri_data8 },
    { "RST 5", 1, i_rst_5 },
    
    /* 0xf0 - 0xff */
    
    { "RP", 1, i_rp },
    { "POP psw", 1, i_pop_psw },
    { "JP addr", 3, i_jp_addr },
    { "DI", 1, i_unimpl },
    { "CP addr", 3, i_cp_addr },
    { "PUSH psw", 1, i_push_psw },
    { "ORI data(8)", 2, i_ori_data8 },
    { "RST 6", 1, i_rst_6 },
    { "RM", 1, i_rm },
    { "SPHL", 1, i_sphl },
    { "JM addr", 3, i_jm_addr },
    { "EI", 1, i_unimpl },
    { "CM addr", 3, i_cm_addr },
    { "UNIMPL", 1, i_unimpl },
    { "CPI data(8)", 2, i_cpi_data8 },
    { "RST 7", 1, i_rst_7 },
};

/* 인텔 8080 진단 프로그램을 실행한다. */
CPU_IMPL void i8080_cpudiag(CPU *cpu) {
    size_t file_size;
    
    cpu->registers.prog_ctr = 0x100;
    
#ifndef CPUDIAG_PATH
#define CPUDIAG_PATH "res/cpudiag.bin"
#endif
    
    file_size = i8080_load_ram(cpu, CPUDIAG_PATH, 0x100);
    
    /* `HLT` 명령어로 종료 */
    cpu->buses.ram[0x00] = 0x76;
    
    /* `OUT` 명령어로 메시지 출력 */
    cpu->buses.ram[0x05] = 0xd3;
    cpu->buses.ram[0x06] = 0x00;
    cpu->buses.ram[0x07] = 0xc9;
    
    info("areum: running %s\n", CPUDIAG_PATH);
    
    while (!cpu->halted)
        i8080_emulate(cpu);
    
#ifdef DEBUG
    debug("areum (0x%04x): emulation finished.\n", cpu->registers.prog_ctr);
#else
    info("areum: emulation finished.\n");
#endif
}

/* 인텔 8080을 에뮬레이트한다. */
CPU_IMPL void i8080_emulate(CPU *cpu) {
    Operands ops;
    
    uint8_t *op_code;
    char *instruction_str;
    
    ops = (Operands) { 0, 0 };
    
    op_code = &cpu->buses.ram[cpu->registers.prog_ctr];
    instruction_str = (char *) calloc(16, sizeof(char));
    
    if (instruction_set[*op_code].size <= 0
       || instruction_set[*op_code].size > 3) {
        panic(
                "areum: error: invalid instruction size (0x%02x)\n", 
                *op_code
            );
    } else {        
        switch (instruction_set[*op_code].size) {
            case 1:
                sprintf(
                    instruction_str, 
                    "%02x", 
                    *(op_code)
                );
                
                break;
                
            case 2:
                ops.operand1 = *(op_code + 1);
                
                sprintf(
                    instruction_str, 
                    "%02x %02x", 
                    *(op_code), 
                    *(op_code + 1)
                );
                
                break;
                
            case 3:               
                ops.operand1 = *(op_code + 1);
                ops.operand2 = *(op_code + 2);
                
                sprintf(
                    instruction_str, 
                    "%02x %02x %02x", 
                    *(op_code), 
                    *(op_code + 1), 
                    *(op_code + 2)
                );
                
                break;
        }

#ifdef DEBUG
        debug(
            "areum (0x%04x): %s ... (%s) | [BC: 0x%04x, DE: 0x%04x, HL: 0x%04x, A: 0x%02x, "
            "SP: 0x%04x, C: %d, P: %d, AC: %d, Z: %d, S: %d]\n",
            cpu->registers.prog_ctr,
            instruction_str,
            instruction_set[*op_code].name,
            (cpu->registers.b) << 8 | cpu->registers.c,
            (cpu->registers.d) << 8 | cpu->registers.e,
            (cpu->registers.h) << 8 | cpu->registers.l,
            cpu->registers.a,
            cpu->registers.stack_ptr,
            i8080_flag_get(cpu, SR_FLAG_CARRY),
            i8080_flag_get(cpu, SR_FLAG_PARITY),
            i8080_flag_get(cpu, SR_FLAG_AUX_CARRY),
            i8080_flag_get(cpu, SR_FLAG_ZERO),
            i8080_flag_get(cpu, SR_FLAG_SIGN)
        );
#else
        info(
            "areum (0x%04x): %s\n",
            cpu->registers.prog_ctr,
            instruction_set[*op_code].name
        );
#endif
        cpu->registers.prog_ctr += instruction_set[*op_code].size;
        
        instruction_set[*op_code].execute(cpu, ops);
    }
}

/* 인텔 8080 CPU의 상태 플래그 값을 해제한다. */
CPU_IMPL void i8080_flag_clear(CPU *cpu, uint8_t flag) {
    cpu->registers.status &= ~flag;
}

/* 인텔 8080 CPU의 상태 플래그 값을 반환한다. */
CPU_IMPL bool i8080_flag_get(CPU *cpu, uint8_t flag) {
    return (cpu->registers.status & flag);
}

/* 인텔 8080 CPU의 상태 플래그 값을 설정한다. */
CPU_IMPL void i8080_flag_set(CPU *cpu, uint8_t flag) {
    cpu->registers.status |= flag;
}

/* 인텔 8080 CPU의 보조 캐리 플래그의 값을 업데이트한다. (산술 연산) */
CPU_IMPL void i8080_flag_update_ac_ari(CPU *cpu, uint8_t value1, uint8_t value2) {
    /*
        보조 캐리 플래그는 연산 과정 중에 아래에서부터 4번째 비트가 
        5번째 비트로 자리올림이 되었을 때 설정되는 플래그이다.
        
        예시)
        
              0b00001010
            + 0b00001100
            ------------
              0b00010110 -> 자리 올림 발생!
              
        그렇다면 보조 캐리 플래그 설정 조건은?
        
        1. 어차피 하위 4개 비트가 제일 중요하므로 `value1`과 `value2`의 
           상위 비트를 `& 0x0f`로 날려버린다.
        2. 수정된 `value1`과 `value2`를 더했을 때 아래에서부터 5번째 비트가 
           1이 된다면 보조 캐리 플래그를 설정한다.
        
    */
    
    value1 &= 0x0f;
    value2 &= 0x0f;
    
    if (((value1 + value2) & 0x10) == 0x10)
        i8080_flag_set(cpu, SR_FLAG_AUX_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
}

/* 인텔 8080 CPU의 캐리 플래그의 값을 업데이트한다. (8비트 산술 연산) */
CPU_IMPL void i8080_flag_update_cy8(CPU *cpu, uint16_t result) {
    if (result & 0xff00)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 CPU의 캐리 플래그의 값을 업데이트한다. (16비트 산술 연산) */
CPU_IMPL void i8080_flag_update_cy16(CPU *cpu, uint32_t result) {
    if (result & 0xffff0000)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 CPU의 패리티 플래그, 제로 플래그와 부호 플래그의 값을 업데이트한다. */
CPU_IMPL void i8080_flag_update_zsp(CPU *cpu, uint8_t result) {
    if (parity(result))
        i8080_flag_set(cpu, SR_FLAG_PARITY);
    else
        i8080_flag_clear(cpu, SR_FLAG_PARITY);
    
    if (result == 0x00)
        i8080_flag_set(cpu, SR_FLAG_ZERO);
    else
        i8080_flag_clear(cpu, SR_FLAG_ZERO);
    
    if (result & 0x80)
        i8080_flag_set(cpu, SR_FLAG_SIGN);
    else
        i8080_flag_clear(cpu, SR_FLAG_SIGN);
}

/* 인텔 8080 CPU의 주기억장치의 `mem_offset` 위치로 파일을 불러온다. */
CPU_IMPL size_t i8080_load_ram(CPU *cpu, const char *file_name, uint16_t mem_offset) {
    FILE *file;
    
    size_t read_size;
    
    if ((file = fopen(file_name, "rb")) == NULL)
        panic("areum: error: failed to open file %s", file_name);
    
    fseek(file, 0L, SEEK_END);    
    read_size = ftell(file);    
    fseek(file, 0L, SEEK_SET);
    
    fread(&cpu->buses.ram[mem_offset], read_size, 1, file);
    fclose(file);
    
    return read_size;
}

/* 인텔 8080 CPU의 H와 L 레지스터에 저장된 메모리 주소에 있는 값을 읽는다. */
CPU_IMPL uint8_t i8080_mem_read_hl(CPU *cpu) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    return cpu->buses.ram[mem_offset];
}

/* 인텔 8080 CPU의 H와 L 레지스터에 저장된 메모리 주소에 있는 값을 수정한다. */
CPU_IMPL void i8080_mem_write_hl(CPU *cpu, uint8_t value) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    cpu->buses.ram[mem_offset] = value;
}

/* 인텔 8080 구조체를 초기화한다. */
CPU_IMPL CPU i8080_new(void) {
    CPU _i8080 = {
        // designated initializers!
        .registers = {
            /* 
                `PUSH psw`에서는 하위 두 번째 플래그 비트의
                값이 1로 설정되어 있기 때문에 기본값을 0x02로 한다.
            */
            .status = 0x02
        }
    };
    
    // 주기억장치 초기화
    _i8080.buses.ram = (uint8_t *) calloc(RAM_SIZE, sizeof(uint8_t));
    
    return _i8080;
}

/* 인텔 8080 명령어: `ADD r(X)` */
INST_IMPL void _i_add(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a + value;
    
    i8080_flag_update_ac_ari(cpu, cpu->registers.a, value);
    i8080_flag_update_cy8(cpu, result);
    i8080_flag_update_zsp(cpu, result);
    
    cpu->registers.a = (uint8_t) result;
}

/* 인텔 8080 명령어: `SUB r(X)` */
INST_IMPL void _i_sub(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a - value;
    
    i8080_flag_update_ac_ari(cpu, cpu->registers.a, -value);
    i8080_flag_update_cy8(cpu, result);
    i8080_flag_update_zsp(cpu, result);
    
    cpu->registers.a = (uint8_t) result;
}

/* 인텔 8080 명령어: `INX rp(X, Y)` */
INST_IMPL void _i_inx(CPU *cpu, uint8_t *reg1, uint8_t *reg2) {
    (*reg2)++;
    
    /*
        예시)
        
               0b00000000 11111111
            -> 0b00000001 00000000
    */
    if (*reg2 == 0)
        (*reg1)++;
}

/* 인텔 8080 명령어: `DCX rp(X, Y)` */
INST_IMPL void _i_dcx(CPU *cpu, uint8_t *reg1, uint8_t *reg2) {
    (*reg2)--;
    
    /*
        예시)
        
               0b00000001 00000000
            -> 0b00000000 11111111
    */
    if (*reg2 == 0xff)
        (*reg1)--;
}

/* 인텔 8080 명령어: `DAD rp(X, Y)` */
INST_IMPL void _i_dad(CPU *cpu, uint8_t *reg1, uint8_t *reg2) {
    uint32_t result;
    
    /*
        single precision: 16-bit (0x00000000 - 0x0000ffff)
        double precision: 32-bit (0x00000000 - 0xffffffff)
    */
    result = ((uint32_t) (cpu->registers.h) << 8 | (uint32_t) cpu->registers.l)
             + ((uint32_t) (*reg1) << 8 | (uint32_t) (*reg2));
    
    i8080_flag_update_cy16(cpu, result);
    
    cpu->registers.h = (result & 0xff00) >> 8;
	cpu->registers.l = result & 0xff;
}

/* 인텔 8080 명령어: `INR r(X)` */
INST_IMPL void _i_inr(CPU *cpu, uint8_t *reg) {
    (*reg)++;
    
    i8080_flag_update_ac_ari(cpu, *reg, 1);
    i8080_flag_update_zsp(cpu, *reg);
}

/* 인텔 8080 명령어: `DCR r(X)` */
INST_IMPL void _i_dcr(CPU *cpu, uint8_t *reg) {
    (*reg)--;
    
    i8080_flag_update_ac_ari(cpu, *reg, 1);
    i8080_flag_update_zsp(cpu, *reg);
}

/* 인텔 8080 명령어: `ANA r(X)` */
INST_IMPL void _i_ana(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a & value;
    
    /* TODO: SR_FLAG_AUX_CARRY */
    
    i8080_flag_update_zsp(cpu, result);
    i8080_flag_clear(cpu, SR_FLAG_CARRY);
    
    cpu->registers.a = (uint8_t) result;
}

/* 인텔 8080 명령어: `XRA r(X)` */
INST_IMPL void _i_xra(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a ^ value;
    
    i8080_flag_clear(cpu, SR_FLAG_CARRY);
    i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
    i8080_flag_update_zsp(cpu, result);
    
    cpu->registers.a = (uint8_t) result;
}

/* 인텔 8080 명령어: `ORA r(X)` */
INST_IMPL void _i_ora(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a | value;
    
    i8080_flag_clear(cpu, SR_FLAG_CARRY);
    i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
    i8080_flag_update_zsp(cpu, result);
    
    cpu->registers.a = (uint8_t) result;
}

/* 인텔 8080 명령어: `CMP r(X)` */
INST_IMPL void _i_cmp(CPU *cpu, uint16_t value) {
    uint16_t result;
    
    result = (uint16_t) cpu->registers.a - value;
    
    if (cpu->registers.a < value)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
    
    i8080_flag_update_ac_ari(cpu, cpu->registers.a, -value);
    i8080_flag_update_zsp(cpu, result);
}

/* 인텔 8080 명령어: `RST n` */
INST_IMPL void _i_rst(CPU *cpu, uint8_t value) {
    /*
        프로그램 카운터를 먼저 증가시키고 명령어를 실행했으므로 
        `cpu->registers.prog_ctr + 3`이 아니라 
        `cpu->registers.prog_ctr`이다. 주의할 것!
    */
    
    uint16_t ret_addr = cpu->registers.prog_ctr;
    
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = (uint8_t) (ret_addr << 8);
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = (uint8_t) ret_addr;
    
    cpu->registers.stack_ptr -= 2;
    
    cpu->registers.prog_ctr = 8 * value;
}

/* 인텔 8080 명령어: `UNIMPL` (?) */
INST_IMPL void i_unimpl(CPU *cpu, Operands ops) {
    /* 구현되지 않은 명령어이므로 오류 출력 */
    panic("areum: error: unimplemented instruction\n");
}

/* 
    :: DATA TRANSFER GROUP ::
*/

/* 인텔 8080 명령어: `MOV r(B), r(B)` (0x40) */
INST_IMPL void i_mov_b_b(CPU *cpu, Operands ops) {
    // cpu->registers.b = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(B), r(C)` (0x41) */
INST_IMPL void i_mov_b_c(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(B), r(D)` (0x42) */
INST_IMPL void i_mov_b_d(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(B), r(E)` (0x43) */
INST_IMPL void i_mov_b_e(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(B), r(H)` (0x44) */
INST_IMPL void i_mov_b_h(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(B), r(L)` (0x45) */
INST_IMPL void i_mov_b_l(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(B), mem` (0x46) */
INST_IMPL void i_mov_b_mem(CPU *cpu, Operands ops) {
    cpu->registers.b = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(B), r(A)` (0x47) */
INST_IMPL void i_mov_b_a(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV r(C), r(B)` (0x48) */
INST_IMPL void i_mov_c_b(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(C), r(C)` (0x49) */
INST_IMPL void i_mov_c_c(CPU *cpu, Operands ops) {
    // cpu->registers.c = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(C), r(D)` (0x4a) */
INST_IMPL void i_mov_c_d(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(C), r(E)` (0x4b) */
INST_IMPL void i_mov_c_e(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(C), r(H)` (0x4c) */
INST_IMPL void i_mov_c_h(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(C), r(L)` (0x4d) */
INST_IMPL void i_mov_c_l(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(C), mem` (0x4e) */
INST_IMPL void i_mov_c_mem(CPU *cpu, Operands ops) {
    cpu->registers.c = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(C), r(A)` (0x4f) */
INST_IMPL void i_mov_c_a(CPU *cpu, Operands ops) {
    cpu->registers.c = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV r(D), r(B)` (0x50) */
INST_IMPL void i_mov_d_b(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(D), r(C)` (0x51) */
INST_IMPL void i_mov_d_c(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(D), r(D)` (0x52) */
INST_IMPL void i_mov_d_d(CPU *cpu, Operands ops) {
    // cpu->registers.d = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(D), r(E)` (0x53) */
INST_IMPL void i_mov_d_e(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(D), r(H)` (0x54) */
INST_IMPL void i_mov_d_h(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(D), r(L)` (0x55) */
INST_IMPL void i_mov_d_l(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(D), mem` (0x56) */
INST_IMPL void i_mov_d_mem(CPU *cpu, Operands ops) {
    cpu->registers.d = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(D), r(A)` (0x57) */
INST_IMPL void i_mov_d_a(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV r(E), r(B)` (0x58) */
INST_IMPL void i_mov_e_b(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(E), r(C)` (0x59) */
INST_IMPL void i_mov_e_c(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(E), r(D)` (0x5a) */
INST_IMPL void i_mov_e_d(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(E), r(E)` (0x5b) */
INST_IMPL void i_mov_e_e(CPU *cpu, Operands ops) {
    // cpu->registers.e = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(E), r(H)` (0x5c) */
INST_IMPL void i_mov_e_h(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(E), r(L)` (0x5d) */
INST_IMPL void i_mov_e_l(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(E), mem` (0x5e) */
INST_IMPL void i_mov_e_mem(CPU *cpu, Operands ops) {
    cpu->registers.e = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(E), r(A)` (0x5f) */
INST_IMPL void i_mov_e_a(CPU *cpu, Operands ops) {
    cpu->registers.e = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV r(H), r(B)` (0x60) */
INST_IMPL void i_mov_h_b(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(H), r(C)` (0x61) */
INST_IMPL void i_mov_h_c(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(H), r(D)` (0x62) */
INST_IMPL void i_mov_h_d(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(H), r(E)` (0x63) */
INST_IMPL void i_mov_h_e(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(H), r(H)` (0x64) */
INST_IMPL void i_mov_h_h(CPU *cpu, Operands ops) {
    // cpu->registers.h = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(H), r(L)` (0x65) */
INST_IMPL void i_mov_h_l(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(H), mem` (0x66) */
INST_IMPL void i_mov_h_mem(CPU *cpu, Operands ops) {
    cpu->registers.h = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(H), r(A)` (0x67) */
INST_IMPL void i_mov_h_a(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV r(L), r(B)` (0x68) */
INST_IMPL void i_mov_l_b(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(L), r(C)` (0x69) */
INST_IMPL void i_mov_l_c(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(L), r(D)` (0x6a) */
INST_IMPL void i_mov_l_d(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(L), r(E)` (0x6b) */
INST_IMPL void i_mov_l_e(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(L), r(H)` (0x6c) */
INST_IMPL void i_mov_l_h(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(L), r(L)` (0x6d) */
INST_IMPL void i_mov_l_l(CPU *cpu, Operands ops) {
    // cpu->registers.l = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(L), mem` (0x6e) */
INST_IMPL void i_mov_l_mem(CPU *cpu, Operands ops) {
    cpu->registers.l = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(L), r(A)` (0x6f) */
INST_IMPL void i_mov_l_a(CPU *cpu, Operands ops) {
    cpu->registers.l = cpu->registers.a;
}

/* 인텔 8080 명령어: `MOV mem, r(B)` (0x70) */
INST_IMPL void i_mov_mem_b(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `MOV mem, r(C)` (0x71) */
INST_IMPL void i_mov_mem_c(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `MOV mem, r(D)` (0x72) */
INST_IMPL void i_mov_mem_d(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `MOV mem, r(E)` (0x73) */
INST_IMPL void i_mov_mem_e(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `MOV mem, r(H)` (0x74) */
INST_IMPL void i_mov_mem_h(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `MOV mem, r(L)` (0x75) */
INST_IMPL void i_mov_mem_l(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `MOV mem, r(A)` (0x77) */
INST_IMPL void i_mov_mem_a(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `MOV r(A), r(B)` (0x78) */
INST_IMPL void i_mov_a_b(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.b;
}

/* 인텔 8080 명령어: `MOV r(A), r(C)` (0x79) */
INST_IMPL void i_mov_a_c(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.c;
}

/* 인텔 8080 명령어: `MOV r(A), r(D)` (0x7a) */
INST_IMPL void i_mov_a_d(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.d;
}

/* 인텔 8080 명령어: `MOV r(A), r(E)` (0x7b) */
INST_IMPL void i_mov_a_e(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.e;
}

/* 인텔 8080 명령어: `MOV r(A), r(H)` (0x7c) */
INST_IMPL void i_mov_a_h(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.h;
}

/* 인텔 8080 명령어: `MOV r(A), r(L)` (0x7d) */
INST_IMPL void i_mov_a_l(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->registers.l;
}

/* 인텔 8080 명령어: `MOV r(A), mem` (0x7e) */
INST_IMPL void i_mov_a_mem(CPU *cpu, Operands ops) {
    cpu->registers.a = i8080_mem_read_hl(cpu);
}

/* 인텔 8080 명령어: `MOV r(A), r(E)` (0x7f) */
INST_IMPL void i_mov_a_a(CPU *cpu, Operands ops) {
    // cpu->registers.a = cpu->registers.a;
}

/* 인텔 8080 명령어: `MVI r(B), data(8)` (0x06) */
INST_IMPL void i_mvi_b_data8(CPU *cpu, Operands ops) {
    cpu->registers.b = ops.operand1;
}

/* 인텔 8080 명령어: `MVI r(C), data(8)` (0x0e) */
INST_IMPL void i_mvi_c_data8(CPU *cpu, Operands ops) {
    cpu->registers.c = ops.operand1;
}

/* 인텔 8080 명령어: `MVI r(D), data(8)` (0x16) */
INST_IMPL void i_mvi_d_data8(CPU *cpu, Operands ops) {
    cpu->registers.d = ops.operand1;
}

/* 인텔 8080 명령어: `MVI r(E), data(8)` (0x1e) */
INST_IMPL void i_mvi_e_data8(CPU *cpu, Operands ops) {
    cpu->registers.e = ops.operand1;
}

/* 인텔 8080 명령어: `MVI r(H), data(8)` (0x26) */
INST_IMPL void i_mvi_h_data8(CPU *cpu, Operands ops) {
    cpu->registers.h = ops.operand1;
}

/* 인텔 8080 명령어: `MVI r(L), data(8)` (0x2e) */
INST_IMPL void i_mvi_l_data8(CPU *cpu, Operands ops) {
    cpu->registers.l = ops.operand1;
}

/* 인텔 8080 명령어: `MVI mem, data(8)` (0x36) */
INST_IMPL void i_mvi_mem_data8(CPU *cpu, Operands ops) {
    i8080_mem_write_hl(cpu, ops.operand1);
}

/* 인텔 8080 명령어: `MVI r(A), data(8)` (0x3e) */
INST_IMPL void i_mvi_a_data8(CPU *cpu, Operands ops) {
    cpu->registers.a = ops.operand1;
}

/* 인텔 8080 명령어: `LXI rp(B, C), data(16)` (0x01) */
INST_IMPL void i_lxi_bc_data16(CPU *cpu, Operands ops) {
    cpu->registers.b = ops.operand2;
    cpu->registers.c = ops.operand1;
}

/* 인텔 8080 명령어: `LXI rp(D, E), data(16)` (0x11) */
INST_IMPL void i_lxi_de_data16(CPU *cpu, Operands ops) {
    cpu->registers.d = ops.operand2;
    cpu->registers.e = ops.operand1;
}

/* 인텔 8080 명령어: `LXI rp(H, L), data(16)` (0x21) */
INST_IMPL void i_lxi_hl_data16(CPU *cpu, Operands ops) {
    cpu->registers.h = ops.operand2;
    cpu->registers.l = ops.operand1;
}

/* 인텔 8080 명령어: `LXI r(SP), data(16)` (0x31) */
INST_IMPL void i_lxi_sp_data16(CPU *cpu, Operands ops) {
    cpu->registers.stack_ptr = (ops.operand2 << 8) | ops.operand1;
}

/* 인텔 8080 명령어: `LDA addr` (0x3a) */
INST_IMPL void i_lda_addr(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (ops.operand2 << 8) | ops.operand1;
    
    cpu->registers.a = cpu->buses.ram[mem_offset];
}

/* 인텔 8080 명령어: `STA addr` (0x32) */
INST_IMPL void i_sta_addr(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (ops.operand2 << 8) | ops.operand1;
    
    cpu->buses.ram[mem_offset] = cpu->registers.a;
}

/* 인텔 8080 명령어: `LHLD addr` (0x2a) */
INST_IMPL void i_lhld_addr(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (ops.operand2 << 8) | ops.operand1;
    
    cpu->registers.l = cpu->buses.ram[mem_offset];
    cpu->registers.h = cpu->buses.ram[mem_offset + 1];
}

/* 인텔 8080 명령어: `SHLD addr` (0x22) */
INST_IMPL void i_shld_addr(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (ops.operand2 << 8) | ops.operand1;
    
    cpu->buses.ram[mem_offset] = cpu->registers.l;
    cpu->buses.ram[mem_offset + 1] = cpu->registers.h;
}

/* 인텔 8080 명령어: `LDAX rp(B, C)` (0x0a) */
INST_IMPL void i_ldax_bc(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.b << 8) | cpu->registers.c;
    
    cpu->registers.a = cpu->buses.ram[mem_offset];
}

/* 인텔 8080 명령어: `LDAX rp(D, E)` (0x1a) */
INST_IMPL void i_ldax_de(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.d << 8) | cpu->registers.e;
    
    cpu->registers.a = cpu->buses.ram[mem_offset];
}

/* 인텔 8080 명령어: `STAX rp(B, C)` (0x02) */
INST_IMPL void i_stax_bc(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.b << 8) | cpu->registers.c;
    
    cpu->buses.ram[mem_offset] = cpu->registers.a;
}

/* 인텔 8080 명령어: `STAX rp(D, E)` (0x12) */
INST_IMPL void i_stax_de(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.d << 8) | cpu->registers.e;
    
    cpu->buses.ram[mem_offset] = cpu->registers.a;
}

/* 인텔 8080 명령어: `XCHG` (0xeb) */
INST_IMPL void i_xchg(CPU *cpu, Operands ops) {
    uint8_t tmp1;
    uint8_t tmp2;
    
    tmp1 = cpu->registers.h;
    tmp2 = cpu->registers.l;
    
    cpu->registers.h = cpu->registers.d;
    cpu->registers.l = cpu->registers.e;
    
    cpu->registers.d = tmp1;
    cpu->registers.e = tmp2;
}

/* 
    :: ARITHMETIC GROUP ::
*/

/* 인텔 8080 명령어: `ADD r(B)` (0x80) */
INST_IMPL void i_add_b(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `ADD r(C)` (0x81) */
INST_IMPL void i_add_c(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `ADD r(D)` (0x82) */
INST_IMPL void i_add_d(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `ADD r(E)` (0x83) */
INST_IMPL void i_add_e(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `ADD r(H)` (0x84) */
INST_IMPL void i_add_h(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `ADD r(L)` (0x85) */
INST_IMPL void i_add_l(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `ADD mem` (0x86) */
INST_IMPL void i_add_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_add(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `ADD r(A)` (0x87) */
INST_IMPL void i_add_a(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `ADC r(B)` (0x88) */
INST_IMPL void i_adc_b(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.b + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(C)` (0x89) */
INST_IMPL void i_adc_c(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.c + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(D)` (0x8a) */
INST_IMPL void i_adc_d(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.d + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(E)` (0x8b) */
INST_IMPL void i_adc_e(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.e + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(H)` (0x8c) */
INST_IMPL void i_adc_h(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.h + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(L)` (0x8d) */
INST_IMPL void i_adc_l(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.l + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC mem` (0x8e) */
INST_IMPL void i_adc_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_add(cpu, cpu->buses.ram[mem_offset] + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADC r(A)` (0x8f) */
INST_IMPL void i_adc_a(CPU *cpu, Operands ops) {
    _i_add(cpu, cpu->registers.a + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SUB r(B)` (0x90) */
INST_IMPL void i_sub_b(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `SUB r(C)` (0x91) */
INST_IMPL void i_sub_c(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `SUB r(D)` (0x92) */
INST_IMPL void i_sub_d(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `SUB r(E)` (0x93) */
INST_IMPL void i_sub_e(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `SUB r(H)` (0x94) */
INST_IMPL void i_sub_h(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `SUB r(L)` (0x95) */
INST_IMPL void i_sub_l(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `SUB mem` (0x96) */
INST_IMPL void i_sub_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_sub(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `SUB r(A)` (0x97) */
INST_IMPL void i_sub_a(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `SBB r(B)` (0x98) */
INST_IMPL void i_sbb_b(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.b + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(C)` (0x99) */
INST_IMPL void i_sbb_c(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.c + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(D)` (0x9a) */
INST_IMPL void i_sbb_d(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.d + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(E)` (0x9b) */
INST_IMPL void i_sbb_e(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.e + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(H)` (0x9c) */
INST_IMPL void i_sbb_h(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.h + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(L)` (0x9d) */
INST_IMPL void i_sbb_l(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.l + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB mem` (0x9e) */
INST_IMPL void i_sbb_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_sub(cpu, cpu->buses.ram[mem_offset] + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SBB r(A)` (0x9f) */
INST_IMPL void i_sbb_a(CPU *cpu, Operands ops) {
    _i_sub(cpu, cpu->registers.a + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `ADI data(8)` (0xc6) */
INST_IMPL void i_adi_data8(CPU *cpu, Operands ops) {
    _i_add(cpu, ops.operand1);
}

/* 인텔 8080 명령어: `ACI data(8)` (0xce) */
INST_IMPL void i_aci_data8(CPU *cpu, Operands ops) {
    _i_add(cpu, ops.operand1 + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `SUI data(8)` (0xd6) */
INST_IMPL void i_sui_data8(CPU *cpu, Operands ops) {
    _i_sub(cpu, ops.operand1);
}

/* 인텔 8080 명령어: `SBI data(8)` (0xde) */
INST_IMPL void i_sbi_data8(CPU *cpu, Operands ops) {
    _i_sub(cpu, ops.operand1 + i8080_flag_get(cpu, SR_FLAG_CARRY));
}

/* 인텔 8080 명령어: `INR r(B)` (0x04) */
INST_IMPL void i_inr_b(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.b);
}

/* 인텔 8080 명령어: `INR r(C)` (0x0c) */
INST_IMPL void i_inr_c(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.c);
}

/* 인텔 8080 명령어: `INR r(D)` (0x14) */
INST_IMPL void i_inr_d(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.d);
}

/* 인텔 8080 명령어: `INR r(E)` (0x1c) */
INST_IMPL void i_inr_e(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.e);
}

/* 인텔 8080 명령어: `INR r(H)` (0x24) */
INST_IMPL void i_inr_h(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.h);
}

/* 인텔 8080 명령어: `INR r(L)` (0x2c) */
INST_IMPL void i_inr_l(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.l);
}

/* 인텔 8080 명령어: `INR mem` (0x34) */
INST_IMPL void i_inr_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_inr(cpu, &cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `INR r(A)` (0x3c) */
INST_IMPL void i_inr_a(CPU *cpu, Operands ops) {
    _i_inr(cpu, &cpu->registers.a);
}

/* 인텔 8080 명령어: `DCR r(B)` (0x05) */
INST_IMPL void i_dcr_b(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.b);
}

/* 인텔 8080 명령어: `DCR r(C)` (0x0d) */
INST_IMPL void i_dcr_c(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.c);
}

/* 인텔 8080 명령어: `DCR r(D)` (0x15) */
INST_IMPL void i_dcr_d(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.d);
}

/* 인텔 8080 명령어: `DCR r(E)` (0x1d) */
INST_IMPL void i_dcr_e(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.e);
}

/* 인텔 8080 명령어: `DCR r(H)` (0x25) */
INST_IMPL void i_dcr_h(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.h);
}

/* 인텔 8080 명령어: `DCR r(L)` (0x2d) */
INST_IMPL void i_dcr_l(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.l);
}

/* 인텔 8080 명령어: `DCR mem` (0x35) */
INST_IMPL void i_dcr_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_dcr(cpu, &cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `DCR r(A)` (0x3d) */
INST_IMPL void i_dcr_a(CPU *cpu, Operands ops) {
    _i_dcr(cpu, &cpu->registers.a);
}

/* 인텔 8080 명령어: `INX rp(B, C)` (0x03) */
INST_IMPL void i_inx_bc(CPU *cpu, Operands ops) {
    _i_inx(cpu, &cpu->registers.b, &cpu->registers.c);
}

/* 인텔 8080 명령어: `INX rp(D, E)` (0x13) */
INST_IMPL void i_inx_de(CPU *cpu, Operands ops) {
    _i_inx(cpu, &cpu->registers.d, &cpu->registers.e);
}

/* 인텔 8080 명령어: `INX rp(H, L)` (0x23) */
INST_IMPL void i_inx_hl(CPU *cpu, Operands ops) {
    _i_inx(cpu, &cpu->registers.h, &cpu->registers.l);
}

/* 인텔 8080 명령어: `INX r(SP)` (0x33) */
INST_IMPL void i_inx_sp(CPU *cpu, Operands ops) {
    cpu->registers.stack_ptr++;
}

/* 인텔 8080 명령어: `DCX rp(B, C)` (0x0b) */
INST_IMPL void i_dcx_bc(CPU *cpu, Operands ops) {
    _i_dcx(cpu, &cpu->registers.b, &cpu->registers.c);
}

/* 인텔 8080 명령어: `DCX rp(D, E)` (0x1b) */
INST_IMPL void i_dcx_de(CPU *cpu, Operands ops) {
    _i_dcx(cpu, &cpu->registers.d, &cpu->registers.e);
}

/* 인텔 8080 명령어: `DCX rp(H, L)` (0x2b) */
INST_IMPL void i_dcx_hl(CPU *cpu, Operands ops) {
    _i_dcx(cpu, &cpu->registers.h, &cpu->registers.l);
}

/* 인텔 8080 명령어: `DCX r(SP)` (0x3b) */
INST_IMPL void i_dcx_sp(CPU *cpu, Operands ops) {
    cpu->registers.stack_ptr--;
}

/* 인텔 8080 명령어: `DAD rp(B, C)` (0x09) */
INST_IMPL void i_dad_bc(CPU *cpu, Operands ops) {
    _i_dad(cpu, &cpu->registers.b, &cpu->registers.c);
}

/* 인텔 8080 명령어: `DAD rp(D, E)` (0x09) */
INST_IMPL void i_dad_de(CPU *cpu, Operands ops) {
    _i_dad(cpu, &cpu->registers.d, &cpu->registers.e);
}

/* 인텔 8080 명령어: `DAD rp(H, L)` (0x29) */
INST_IMPL void i_dad_hl(CPU *cpu, Operands ops) {
    _i_dad(cpu, &cpu->registers.h, &cpu->registers.l);
}

/* 인텔 8080 명령어: `DAD r(SP)` (0x39) */
INST_IMPL void i_dad_sp(CPU *cpu, Operands ops) {
    uint32_t result;
    
    result = (uint32_t) (cpu->registers.h) << 8 | (uint32_t) cpu->registers.l
             + (uint32_t) cpu->registers.stack_ptr;
    
    i8080_flag_update_cy16(cpu, result);
    
    cpu->registers.stack_ptr = (uint16_t) result;
}

/* 인텔 8080 명령어: `DAA` (0x27) */
INST_IMPL void i_daa(CPU *cpu, Operands ops) {
    /*
        1. `cpu->registers.a`의 하위 4비트가 9보다 크거나, 
           보조 캐리 플래그가 설정되어 있을 경우 `cpu->registers.a += 0x06`
        
        2. 1번 과정이 끝난 후에 `cpu->registers.a`의 상위 4비트가 
           9보다 크거나, 캐리 플래그가 설정되어 있을 경우 `cpu->registers.a += 0x60`
    */
    
    uint8_t result;
    
    result = cpu->registers.a;
    
    if ((cpu->registers.a & 0x0f) > 0x09 
        || i8080_flag_get(cpu, SR_FLAG_AUX_CARRY)) {
        result += 0x06;
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    } else {
        i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
    }
    
    if (cpu->registers.a > 0x9f 
        || i8080_flag_get(cpu, SR_FLAG_CARRY)) {
        result += 0x60;
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    } else {
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
    }
    
    i8080_flag_update_zsp(cpu, result);
    
    cpu->registers.a = result;
}

/* 
    :: LOGICAL GROUP ::
*/

/* 인텔 8080 명령어: `ANA r(B)` (0xa0) */
INST_IMPL void i_ana_b(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `ANA r(C)` (0xa1) */
INST_IMPL void i_ana_c(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `ANA r(D)` (0xa2) */
INST_IMPL void i_ana_d(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `ANA r(E)` (0xa3) */
INST_IMPL void i_ana_e(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `ANA r(H)` (0xa4) */
INST_IMPL void i_ana_h(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `ANA r(L)` (0xa5) */
INST_IMPL void i_ana_l(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `ANA mem` (0xa6) */
INST_IMPL void i_ana_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_ana(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `ANA r(A)` (0xa7) */
INST_IMPL void i_ana_a(CPU *cpu, Operands ops) {
    _i_ana(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `XRA r(B)` (0xa8) */
INST_IMPL void i_xra_b(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `XRA r(C)` (0xa9) */
INST_IMPL void i_xra_c(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `XRA r(D)` (0xaa) */
INST_IMPL void i_xra_d(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `XRA r(E)` (0xab) */
INST_IMPL void i_xra_e(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `XRA r(H)` (0xac) */
INST_IMPL void i_xra_h(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `XRA r(L)` (0xad) */
INST_IMPL void i_xra_l(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `XRA mem` (0xae) */
INST_IMPL void i_xra_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_xra(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `XRA r(A)` (0xaf) */
INST_IMPL void i_xra_a(CPU *cpu, Operands ops) {
    _i_xra(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `ORA r(B)` (0xb0) */
INST_IMPL void i_ora_b(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `ORA r(C)` (0xb1) */
INST_IMPL void i_ora_c(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `ORA r(D)` (0xb2) */
INST_IMPL void i_ora_d(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `ORA r(E)` (0xb3) */
INST_IMPL void i_ora_e(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `ORA r(H)` (0xb4) */
INST_IMPL void i_ora_h(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `ORA r(L)` (0xb5) */
INST_IMPL void i_ora_l(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `ORA mem` (0xb6) */
INST_IMPL void i_ora_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_ora(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `ORA r(A)` (0xb7) */
INST_IMPL void i_ora_a(CPU *cpu, Operands ops) {
    _i_ora(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `CMP r(B)` (0xb8) */
INST_IMPL void i_cmp_b(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.b);
}

/* 인텔 8080 명령어: `CMP r(C)` (0xb9) */
INST_IMPL void i_cmp_c(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.c);
}

/* 인텔 8080 명령어: `CMP r(D)` (0xba) */
INST_IMPL void i_cmp_d(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.d);
}

/* 인텔 8080 명령어: `CMP r(E)` (0xbb) */
INST_IMPL void i_cmp_e(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.e);
}

/* 인텔 8080 명령어: `CMP r(H)` (0xbc) */
INST_IMPL void i_cmp_h(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.h);
}

/* 인텔 8080 명령어: `CMP r(L)` (0xbd) */
INST_IMPL void i_cmp_l(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.l);
}

/* 인텔 8080 명령어: `CMP mem` (0xbe) */
INST_IMPL void i_cmp_mem(CPU *cpu, Operands ops) {
    uint16_t mem_offset = (cpu->registers.h << 8) | (cpu->registers.l);
    
    _i_cmp(cpu, cpu->buses.ram[mem_offset]);
}

/* 인텔 8080 명령어: `CMP r(A)` (0xbf) */
INST_IMPL void i_cmp_a(CPU *cpu, Operands ops) {
    _i_cmp(cpu, cpu->registers.a);
}

/* 인텔 8080 명령어: `ANI data(8)` (0xe6) */
INST_IMPL void i_ani_data8(CPU *cpu, Operands ops) {
    _i_ana(cpu, ops.operand1);
    
    i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
}

/* 인텔 8080 명령어: `XRI data(8)` (0xee) */
INST_IMPL void i_xri_data8(CPU *cpu, Operands ops) {
    _i_xra(cpu, ops.operand1);
    
    i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
}

/* 인텔 8080 명령어: `ORI data(8)` (0xf6) */
INST_IMPL void i_ori_data8(CPU *cpu, Operands ops) {
    _i_ora(cpu, ops.operand1);
    
    i8080_flag_clear(cpu, SR_FLAG_AUX_CARRY);
}

/* 인텔 8080 명령어: `CPI data(8)` (0xfe) */
INST_IMPL void i_cpi_data8(CPU *cpu, Operands ops) {
    _i_cmp(cpu, ops.operand1);
}

/* 인텔 8080 명령어: `RLC` (0x07) */
INST_IMPL void i_rlc(CPU *cpu, Operands ops) {
    uint8_t temp;
    
    temp = cpu->registers.a;
    
    /*
        비트를 왼쪽으로 1비트 회전한다.
        
        예시) 
        
            0b10101100 <- 가운데의 `010110`에 주목!
            0b01011001 <- `010110`은 한 칸 왼쪽으로 가고,
                          왼쪽에서부터 첫 번째 비트였던 `1`이
                          맨 오른쪽으로 이동하였다.
    */
    
    cpu->registers.a = (temp << 1) | ((temp & 0x80) >> 7);
    
    if (temp & 0x80)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 명령어: `RRC` (0x0f) */
INST_IMPL void i_rrc(CPU *cpu, Operands ops) {
    uint8_t temp;
    
    temp = cpu->registers.a;
    
    /*
        비트를 오른쪽으로 1비트 회전한다.
        
        예시) 
        
            0b10101100
            0b01010110 <- 모든 비트가 한 칸씩 오른쪽으로
                          이동하였다.
    */
    
    cpu->registers.a = ((temp & 1) << 7) | (temp >> 1);
    
    if (temp & 1)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 명령어: `RAL` (0x17) */
INST_IMPL void i_ral(CPU *cpu, Operands ops) {
    uint8_t temp;
    
    temp = cpu->registers.a;
    
    cpu->registers.a = (temp << 1) | i8080_flag_get(cpu, SR_FLAG_CARRY);
    
    if (temp & 0x80)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 명령어: `RAR` (0x1f) */
INST_IMPL void i_rar(CPU *cpu, Operands ops) {
    uint8_t temp;
    
    temp = cpu->registers.a;
    
    cpu->registers.a = (i8080_flag_get(cpu, SR_FLAG_CARRY) << 7) | (temp >> 1);

    if (temp & 1)
        i8080_flag_set(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
}

/* 인텔 8080 명령어: `CMA` (0x2f) */
INST_IMPL void i_cma(CPU *cpu, Operands ops) {
    cpu->registers.a = ~cpu->registers.a;
}

/* 인텔 8080 명령어: `CMC` (0x3f) */
INST_IMPL void i_cmc(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY))
        i8080_flag_clear(cpu, SR_FLAG_CARRY);
    else
        i8080_flag_set(cpu, SR_FLAG_CARRY);;
}

/* 인텔 8080 명령어: `STC` (0x37) */
INST_IMPL void i_stc(CPU *cpu, Operands ops) {
    i8080_flag_set(cpu, SR_FLAG_CARRY);
}

/* 
    :: BRANCH GROUP ::
*/

/* 인텔 8080 명령어: `JMP addr` (0xc3) */
INST_IMPL void i_jmp_addr(CPU *cpu, Operands ops) {
    cpu->registers.prog_ctr = (ops.operand2) << 8 | ops.operand1;
}

/* 인텔 8080 명령어: `JNZ addr` (0xc2) */
INST_IMPL void i_jnz_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 0)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JZ addr` (0xca) */
INST_IMPL void i_jz_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 1)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JNC addr` (0xd2) */
INST_IMPL void i_jnc_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 0)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JC addr` (0xda) */
INST_IMPL void i_jc_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 1)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JPO addr` (0xe2) */
INST_IMPL void i_jpo_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 0)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JPE addr` (0xea) */
INST_IMPL void i_jpe_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 1)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JP addr` (0xf2) */
INST_IMPL void i_jp_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 0)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `JM addr` (0xfa) */
INST_IMPL void i_jm_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 1)
        i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CALL addr` (0xcd) */
INST_IMPL void i_call_addr(CPU *cpu, Operands ops) {
    /*
        프로그램 카운터를 먼저 증가시키고 명령어를 실행했으므로 
        `cpu->registers.prog_ctr + 3`이 아니라 
        `cpu->registers.prog_ctr`이다. 주의할 것!
    */
    
    uint16_t ret_addr = cpu->registers.prog_ctr;
    
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = (uint8_t) (ret_addr >> 8);
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = (uint8_t) ret_addr;
    
    cpu->registers.stack_ptr -= 2;
    
    i_jmp_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CNZ addr` (0xc4) */
INST_IMPL void i_cnz_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 0)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CZ addr` (0xcc) */
INST_IMPL void i_cz_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 1)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CNC addr` (0xd4) */
INST_IMPL void i_cnc_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 0)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CC addr` (0xdc) */
INST_IMPL void i_cc_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 1)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CPO addr` (0xe4) */
INST_IMPL void i_cpo_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 0)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CPE addr` (0xec) */
INST_IMPL void i_cpe_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 1)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CP addr` (0xf4) */
INST_IMPL void i_cp_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 0)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `CM addr` (0xfc) */
INST_IMPL void i_cm_addr(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 1)
        i_call_addr(cpu, ops);
}

/* 인텔 8080 명령어: `RET` (0xc9) */
INST_IMPL void i_ret(CPU *cpu, Operands ops) {
    uint16_t orig_addr = (cpu->buses.ram[cpu->registers.stack_ptr + 1] << 8) 
                         | cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->registers.prog_ctr = orig_addr;
    
    cpu->registers.stack_ptr += 2;
}

/* 인텔 8080 명령어: `RNZ` (0xc0) */
INST_IMPL void i_rnz(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 0)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RZ` (0xc8) */
INST_IMPL void i_rz(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_ZERO) == 1)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RNC` (0xd0) */
INST_IMPL void i_rnc(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 0)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RC` (0xd8) */
INST_IMPL void i_rc(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_CARRY) == 1)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RPO` (0xe0) */
INST_IMPL void i_rpo(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 0)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RPE` (0xe8) */
INST_IMPL void i_rpe(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_PARITY) == 1)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RP` (0xf0) */
INST_IMPL void i_rp(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 0)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RM` (0xf8) */
INST_IMPL void i_rm(CPU *cpu, Operands ops) {
    if (i8080_flag_get(cpu, SR_FLAG_SIGN) == 1)
        i_ret(cpu, ops);
}

/* 인텔 8080 명령어: `RST 0` (0xc7) */
INST_IMPL void i_rst_0(CPU *cpu, Operands ops) {
    _i_rst(cpu, 0);
}

/* 인텔 8080 명령어: `RST 1` (0xcf) */
INST_IMPL void i_rst_1(CPU *cpu, Operands ops) {
    _i_rst(cpu, 1);
}

/* 인텔 8080 명령어: `RST 2` (0xd7) */
INST_IMPL void i_rst_2(CPU *cpu, Operands ops) {
    _i_rst(cpu, 2);
}

/* 인텔 8080 명령어: `RST 3` (0xdf) */
INST_IMPL void i_rst_3(CPU *cpu, Operands ops) {
    _i_rst(cpu, 3);
}

/* 인텔 8080 명령어: `RST 4` (0xe7) */
INST_IMPL void i_rst_4(CPU *cpu, Operands ops) {
    _i_rst(cpu, 4);
}

/* 인텔 8080 명령어: `RST 5` (0xef) */
INST_IMPL void i_rst_5(CPU *cpu, Operands ops) {
    _i_rst(cpu, 5);
}

/* 인텔 8080 명령어: `RST 6` (0xf7) */
INST_IMPL void i_rst_6(CPU *cpu, Operands ops) {
    _i_rst(cpu, 6);
}

/* 인텔 8080 명령어: `RST 7` (0xff) */
INST_IMPL void i_rst_7(CPU *cpu, Operands ops) {
    _i_rst(cpu, 7);
}

/* 인텔 8080 명령어: `PCHL` (0xe9) */
INST_IMPL void i_pchl(CPU *cpu, Operands ops) {
    cpu->registers.prog_ctr = (cpu->registers.h << 8) | (cpu->registers.l);
}

/* 
    :: STACK, I/O AND MACHINE CONTROL GROUP ::
*/

/* 인텔 8080 명령어: `PUSH rp(B, C)` (0xc5) */
INST_IMPL void i_push_bc(CPU *cpu, Operands ops) {
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = cpu->registers.b;
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = cpu->registers.c;
    
    cpu->registers.stack_ptr -= 2;
}

/* 인텔 8080 명령어: `PUSH rp(D, E)` (0xd5) */
INST_IMPL void i_push_de(CPU *cpu, Operands ops) {
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = cpu->registers.d;
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = cpu->registers.e;
    
    cpu->registers.stack_ptr -= 2;
}

/* 인텔 8080 명령어: `PUSH rp(H, L)` (0xe5) */
INST_IMPL void i_push_hl(CPU *cpu, Operands ops) {
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = cpu->registers.h;
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = cpu->registers.l;
    
    cpu->registers.stack_ptr -= 2;
}

/* 인텔 8080 명령어: `PUSH psw` (0xf5) */
INST_IMPL void i_push_psw(CPU *cpu, Operands ops) {
    cpu->buses.ram[cpu->registers.stack_ptr - 1] = cpu->registers.a;
    cpu->buses.ram[cpu->registers.stack_ptr - 2] = cpu->registers.status;
    
    cpu->registers.stack_ptr -= 2;
}

/* 인텔 8080 명령어: `POP rp(B, C)` (0xc1) */
INST_IMPL void i_pop_bc(CPU *cpu, Operands ops) {
    cpu->registers.b = cpu->buses.ram[cpu->registers.stack_ptr + 1];
    cpu->registers.c = cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->registers.stack_ptr += 2;
}

/* 인텔 8080 명령어: `POP rp(D, E)` (0xd1) */
INST_IMPL void i_pop_de(CPU *cpu, Operands ops) {
    cpu->registers.d = cpu->buses.ram[cpu->registers.stack_ptr + 1];
    cpu->registers.e = cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->registers.stack_ptr += 2;
}

/* 인텔 8080 명령어: `POP rp(H, L)` (0xe1) */
INST_IMPL void i_pop_hl(CPU *cpu, Operands ops) {
    cpu->registers.h = cpu->buses.ram[cpu->registers.stack_ptr + 1];
    cpu->registers.l = cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->registers.stack_ptr += 2;
}

/* 인텔 8080 명령어: `POP psw` (0xf1) */
INST_IMPL void i_pop_psw(CPU *cpu, Operands ops) {
    cpu->registers.a = cpu->buses.ram[cpu->registers.stack_ptr + 1];
    cpu->registers.status = cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->registers.stack_ptr += 2;
}

/* 인텔 8080 명령어: `XTHL` (0xe3) */
INST_IMPL void i_xthl(CPU *cpu, Operands ops) {
    uint8_t tmp1;
    uint8_t tmp2;
    
    tmp1 = cpu->registers.h;
    tmp2 = cpu->registers.l;
    
    cpu->registers.h = cpu->buses.ram[cpu->registers.stack_ptr + 1];
    cpu->registers.l = cpu->buses.ram[cpu->registers.stack_ptr];
    
    cpu->buses.ram[cpu->registers.stack_ptr + 1] = tmp1;
    cpu->buses.ram[cpu->registers.stack_ptr] = tmp2;
}

/* 인텔 8080 명령어: `SPHL` (0xf9) */
INST_IMPL void i_sphl(CPU *cpu, Operands ops) {
    cpu->registers.stack_ptr = (cpu->registers.h << 8) | (cpu->registers.l);
}

/* 인텔 8080 명령어: `IN data(8)` (0xdb) */
INST_IMPL void i_in_data8(CPU *cpu, Operands ops) {
    /* ... */
}

/* 인텔 8080 명령어: `OUT data(8)` (0xd3) */
INST_IMPL void i_out_data8(CPU *cpu, Operands ops) {
#ifdef CPUDIAG_PATH
    uint16_t mem_offset;
    
    mem_offset = (cpu->registers.d << 8) | (cpu->registers.e);
    
    if (ops.operand1 == 0x00) {
        if (cpu->registers.c == 2) {
            info("%c", cpu->registers.e);
        } else if (cpu->registers.c == 9) {
            do {
                info("%c", cpu->buses.ram[mem_offset++]);
            } while (cpu->buses.ram[mem_offset] != '$');
            
            info("\n");
        } else {
            /* 아무 것도 하지 않는다. */
        }
    }
#endif
}

/* 인텔 8080 명령어: `HLT` (0x76) */
INST_IMPL void i_hlt(CPU *cpu, Operands ops) {
    /* TODO: interrupts? */
    
    cpu->halted = true;
}

/* 인텔 8080 명령어: `NOP` (0x00) */
INST_IMPL void i_nop(CPU *cpu, Operands ops) {
    // 아무 작업도 하지 않는다.
}