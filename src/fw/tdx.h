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

/* SEAMCALL Leafs */
#define SEAMLDR_INFO                0x0
#define SEAMLDR_INSTALL             0x1

/* SEAMLDR PARAMS */
#define SEAMLDR_PARAMS_MAX_MODULE_PAGES 496
#define SIGSTRUCT_MODULUS_SIZE          384
#define SIGSTRUCT_SIGNATURE_SIZE        384
#define SIGSTRUCT_SEAMHASH_SIZE         48

#define SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE 255

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

typedef struct __attribute__((__packed__))
{
    u64 valid;
    u16 current_seam_svn;
    u8 last_patch_se_svn;
    u8 reserved0[13];
    u8 mrseam[48];
    u8 mrsigner[48];
    u64 attributes;
    u8 seam_ready;
    u8 system_under_debug;
    u8 p_seamldr_ready;
    u8 reserved1[5];
} seamextend_t;

typedef struct {
    u32 version;
    u32 attributes;
    u32 vendor_id;
    u32 build_date;
    u16 build_num;
    u16 minor;
    u16 major;
    u16 reserved0;
    u32 acm_x2apic;
    u32 num_remaining_updates;
    seamextend_t seamextend;
    u8 reserved1[88];
} seamldr_info_t;

typedef union
{
    struct
    {
        u32 reserved        : 31;
        u32 is_debug_signed :1;
    };

    u32 raw;
} module_type_t;

typedef union
{
    struct
    {
        u8 seam_minor_svn;
        u8 seam_major_svn;
    };

    u16 raw;
} seam_svn_t;

typedef struct {
    u32 header_type;
    u32 header_length;
    u32 header_version;
    module_type_t module_type;
    u32 module_vendor;
    u32 date;
    u32 size;
    u32 key_size;
    u32 modulus_size;
    u32 exponent_size;
    u8 reserved0[88];

    u8 modulus[SIGSTRUCT_MODULUS_SIZE];
    u32 exponent;
    u8 signature[SIGSTRUCT_SIGNATURE_SIZE];

    u8 seamhash[SIGSTRUCT_SEAMHASH_SIZE];
    seam_svn_t seamsvn;
    u64 attributes;
    u32 rip_offset;
    u8 num_stack_pages;
    u8 num_tls_pages;
    u16 num_keyhole_pages;
    u16 num_global_data_pages;
    u16 max_tdmrs;
    u16 max_rsvd_per_tdmr;
    u16 pamt_entry_size_4k;
    u16 pamt_entry_size_2m;
    u16 pamt_entry_size_1g;
    u8 reserved1[6];
    u16 module_hv;
    u16 min_update_hv;
    u8 no_downgrade;
    u8 reserved2[1];
    u16 num_handoff_pages;

    u32 gdt_idt_offset;
    u32 fault_wrapper_offset;
    u8 reserved3[24];

    u32 cpuid_table_size;
    u32 cpuid_table[SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE];
} seam_sigstruct_t;

typedef struct {
    u32 version;
    u32 scenario;
    u64 sigstruct_pa;
    u8 reserved[104];
    u64 num_module_pages;
    u64 mod_pages_pa_list[SEAMLDR_PARAMS_MAX_MODULE_PAGES];
} seamldr_params_t;


__attribute__((used)) void opentdx_setup(void); // Force symbol remains

#endif