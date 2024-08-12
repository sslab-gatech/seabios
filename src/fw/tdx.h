#ifndef __TDX_H
#define __TDX_H

#include "types.h"

/* 
Intel Trusted Execution Technology (Intel TXT) Software Development Guide
    A.1.1 ACM Header Format   
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


void opentdx_setup(void);

#endif