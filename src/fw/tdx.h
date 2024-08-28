#ifndef __TDX_H
#define __TDX_H

#include "types.h"

/*
 * For entering Long Mode
 */
#define MSR_EFER        0xC0000080

#define PTES_PER_TABLE 512
#define PTE(addr) ((addr & ~0xFFF) | 0x3) // RW | P
#define HPTE(addr) ((addr & ~0x3FFFFFFF) | 0x83) // PS | RW | P

/*
 * Leaf value (in eax) calling GETSEC
 */
#define CAPABILITIES    0
#define ENTERACCS       2
#define EXITAC          3
#define SENTER          4
#define SEXIT           5
#define PARAMETERS      6
#define SMCTRL          7
#define WAKEUP          8

/*
 * TDX MSRs
 */
#define MSR_IA32_SEAMRR_PHYS_BASE   0x1400
#define MSR_IA32_SEAMRR_PHYS_MASK   0x1401

#define SEAMRR_BLOCK_SIZE           0x2000000
#define SEAMRR_CONFIGURE_OFFSET     3
#define SEAMRR_LOCK_OFFSET          10
#define SEAMRR_ENABLE_OFFSET        11

typedef union {
    struct {
        u32 reserved0   : 3;
        u8  configured  : 1;
        u32 reserved1   : 21;
        u64 base        : 39;
    };
    u64 raw;
} seamrr_base_t;

typedef union {
    struct {
        u16 reserved0   : 10;
        u8  locked      : 1;
        u8  enabled     : 1;
        u16 reserved1   : 13;
        u64 mask        : 39;
    };
    u64 raw;
} seamrr_mask_t;

/* 
 * Intel Trusted Execution Technology (Intel TXT) Software Development Guide
 *    A.1.1 ACM Header Format
 */
typedef struct {
    // 00000000
    u16 module_type;
    u16 module_sub_type;
    u32 header_len;
    u32 header_version;
    u16 chipset_id;
    u16 flags;

    // 00000010
    u32 module_vendor;
    u32 date;
    u32 size;
    u16 txt_svn;
    u16 sgx_svn;

    // 00000020
    u32 code_control;
    u32 error_entry_point;
    u32 gdt_limit;
    u32 gdt_base_ptr;

    // 00000030
    u32 seg_sel;
    u32 entry_point;
    u8 reserved2[64];

    // 00000078
    u32 key_size;
    u32 scratch_size; // should be 208 in Version 3.0
    u8 rsa_pub_key[384]; // currently only Version 3.0 is allowed
    // u0 rsa_pub_exp;

    // 00000200
    u8 rsa_sig[384]; // Version 3.0

    // 00000380
    u8 scratch[832]; // 832 = scratch_size * 4 in Version 3.0

    // 000006c0
    u8 user_area[]; // modulo-64 byte increment
} npseamldr_t; 


__attribute__((used)) void opentdx_setup(void); // Force symbol remains

#endif