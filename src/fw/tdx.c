#include "output.h"
#include "romfile.h"
#include "malloc.h"
#include "e820map.h"
#include "x86.h"
#include "tdx.h"

#define tdx_dprintf(lvl, fmt, args...) dprintf(lvl, "[OpenTDX] " fmt, ##args)

static void *setup_seam_range(u32 size);
static void *load_npseamldr(void);
static void dump_acm_header(npseamldr_t *npseamldr);
static int check_acm_header(npseamldr_t *npseamldr);
static int enter_npseamldr(void *npseamldr, u32 npseamldr_size);

u64 pml4[PTES_PER_TABLE] VARFSEG __aligned(4096);
u64 pdptr[PTES_PER_TABLE] VARFSEG __aligned(4096) = { 
    HPTE(0x0), HPTE(0x40000000), HPTE(0x80000000), HPTE(0xC0000000), 0,
    };

extern struct descloc_s rombios32_gdt_48;

u64 rombios64_gdt[] VARFSEG __aligned(8) = {
    // First entry can't be used.
    0x0000000000000000LL,
    // 64 bit code segment for long mode
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_L,
    // 64 bit code segment for protected mode
    GDT_GRANLIMIT(0xffffffff) | GDT_CODE | GDT_B,
};

struct descloc_s_64 rombios64_gdt_80 VARFSEG = {
    .length = sizeof(rombios64_gdt) - 1,
    .addr_low = (u32)rombios64_gdt,
    .addr_high = (u32) 0,
};

static u64 rsp;

static inline void enter_longmode()
{
    tdx_dprintf(1, "entering long mode\n");

    asm volatile(
        "movl %%cr4, %%eax\n\t"
        "btsl $5, %%eax\n\t"
        "movl %%eax, %%cr4\n\t" // Enable Page Address Extension (PAE) in CR4
        "movl %1, %%cr3\n\t" // Set page table base address
        "movl %[efer], %%ecx\n\t"
        "rdmsr\n\t"
        "btsl $8, %%eax\n\t" // Enable long mode in EFER
        "wrmsr\n\t"
        "movl %%cr0, %%eax\n\t"
        "btsl $31, %%eax\n\t" // Enable paging in CR0
        "movl %%eax, %%cr0\n\t"
        "lgdt (%%ebx)\n\t"
        "ljmpl $0x8, $1f\n\t"
        "1:\n\t"
        :
        : "b" (&rombios64_gdt_80), "r" (pml4), [efer] "g" (MSR_EFER)
        : "eax", "ecx", "memory"
    );
}

static inline void exit_longmode()
{
    asm volatile(
        "movl %%esp, %%ebx\n\t"
        "andl $0x7, %%ebx\n\t"
        "subl %%ebx, %%esp\n\t" // Align stack address to 8 bytes
        ".byte 0x6a, 0x10\n\t" // push 0x10
        ".byte 0x48, 0x8d, 0x05, 0x05, 0x00, 0x00, 0x00\n\t" // lea [rip + 0x5], rax
        "pushl %%eax\n\t" // push rax
        ".byte 0x48, 0xff, 0x2c, 0x24\n\t" // ljmp *rsp
        "1:\n\t" // From here, we are in X86 mode
        "movl %%cr0, %%eax\n\t"
        "btrl $31, %%eax\n\t"
        "movl %%eax, %%cr0\n\t" // Disable paging in CR0
        "movl %[efer], %%ecx\n\t"
        "rdmsr\n\t"
        "btrl $8, %%eax\n\t"
        "wrmsr\n\t" // Disable long mode in EFER
        "movl %[cr3], %%cr3\n\t" // Unset page table base address
        "movl %%cr4, %%eax\n\t"
        "btrl $5, %%eax\n\t"
        "movl %%eax, %%cr4\n\t" // Disable PAE in CR4
        "add %%ebx, %%esp\n\t" // Restore 4-byte aligned stack address
        "lgdtl %[gdt32]\n\t"
        "ljmpl $0x8, $2f\n\t"
        "2:\n\t"
        :
        : "b" (&rombios64_gdt_80), [cr3] "r" (0), [efer] "g" (MSR_EFER), [gdt32] "m" (rombios32_gdt_48)
        : "eax", "esp", "ecx", "memory"
    );

    tdx_dprintf(1, "exited from long mode\n");
}


static inline u32 enteraccs(void *npseamldr, u32 npseamldr_size)
{
    u32 ret;

    // Store registers
    asm volatile(
        "movl %%esp, %%ebx\n\t"
        "andl $0x7, %%ebx\n\t"
        "subl %%ebx, %%esp\n\t" // Align esp to 8-bytes and save remainder to ebx
        "pushl %%ecx\n\t"
        "pushl %%edx\n\t"
        "pushl %%ebx\n\t"
        "pushl %%ebp\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        ".byte 0x48, 0x89, 0x20\n\t"  // mov rsp, (rax)
        :
        : "a" ((u32) &rsp)
        : "ebx", "esp", "memory"
    );

    asm volatile(
        ".byte 0x49, 0x89, 0xc1\n\t" // mov rax, r9
        ".byte 0x48, 0x8d, 0x05, 0x18, 0x00, 0x00, 0x00\n\t" // lea [rip + 0x18], rax
        ".byte 0x49, 0x89, 0xc2\n\t" // mov rax, r10
        "mov %%cr3, %%eax\n\t"
        ".byte 0x49, 0x89, 0xc3\n\t" // mov rax, r11
        "mov %[idt], %%eax\n\t"
        ".byte 0x49, 0x89, 0xc4\n\t" // mov rax, r12
        "mov %[enteraccs], %%eax\n\t"
        "getsec\n\t"
        "end:\n\t"
        ".byte 0x4c, 0x89, 0xc8\n\t" // mov r9, rax
        : "=a" (ret)
        :   "a" (&rombios64_gdt), [idt] "g" (0),
            [enteraccs] "g" (ENTERACCS), "b" (npseamldr), "c" (npseamldr_size)
        :
    );

    // Restore registers
    asm volatile(
        ".byte 0x48, 0x8b, 0x23\n\t" // mov (rbx), rsp
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebp\n\t"
        "popl %%ebx\n\t"
        "popl %%edx\n\t"
        "popl %%ecx\n\t"
        "addl %%ebx, %%esp\n\t" // Restore original 4-byte aligned stack
        :
        : "b" ((u32) &rsp)
        : "esp"
    );

    return ret;
}

void
opentdx_setup(void)
{
    npseamldr_t *npseamldr;
    u32 seam_range_size = 64 * 1024 * 1024;
    void *seam_range_base;
    int ret;

    tdx_dprintf(1, "setup open-tdx\n");

    seam_range_base = setup_seam_range(seam_range_size);
    if (!seam_range_base) {
        return;
    }

    tdx_dprintf(1, "configured seam range [%p, %p)\n", seam_range_base, seam_range_base + seam_range_size);


    npseamldr = (npseamldr_t *) load_npseamldr();
    if (!npseamldr) {
        return;
    }

    tdx_dprintf(1, "loaded npseamldr to %p\n", npseamldr);

    dump_acm_header(npseamldr);

    if (check_acm_header(npseamldr)) {
        tdx_dprintf(1, "invalid ACM header\n");
        return;
    }

    // Setup huge page table
    pml4[0] = PTE((u64) pdptr);

    ret = enter_npseamldr((void *)npseamldr, npseamldr->size * 4);
    if (ret) {
        tdx_dprintf(1, "failed to enter npseamldr (exit code: %d)\n", ret);
        return;
    }

    tdx_dprintf(1, "npseamldr exited with %d\n", ret);

    return;
}

static void *setup_seam_range(u32 size)
{
    seamrr_base_t seamrr_base;
    seamrr_mask_t seamrr_mask;
    u64 n, i, min_size;
    u64 start = 0;

    if (size % SEAMRR_BLOCK_SIZE) {
        tdx_dprintf(1, "seam_range_size is not aligned to 32MB\n");
        return NULL;
    }

    // Compute minimum size of memory space to allocate `size` of memory
    // at `SEAMRR_BLOCK_SIZE` aligned address
    n = size / SEAMRR_BLOCK_SIZE;
    min_size = (n + 1) * SEAMRR_BLOCK_SIZE;

    for (i = 0; i < e820_count; i++) {
        struct e820entry *e = &e820_list[i];
        if (e->type == E820_RESERVED)
            continue;
        if (e->size < min_size)
            continue;

        start = (e->start + (SEAMRR_BLOCK_SIZE - 1)) & ~(SEAMRR_BLOCK_SIZE - 1);
        break;
    }

    if (!start) {
        tdx_dprintf(1, "failed to malloc(seam_range_size)\n");
        return NULL;
    }

    e820_add(start, size, E820_RESERVED);

    seamrr_base.raw = start | (1 << SEAMRR_CONFIGURE_OFFSET);
    seamrr_mask.raw = size | (1 << SEAMRR_ENABLE_OFFSET);

    wrmsr(MSR_IA32_SEAMRR_PHYS_BASE, seamrr_base.raw);
    wrmsr(MSR_IA32_SEAMRR_PHYS_MASK, seamrr_mask.raw);

    return (void *) start;
}

static void *load_npseamldr(void)
{
    struct romfile_s *file;
    void *dst;

    file = romfile_find("opt/opentdx.npseamldr");
    if (!file) {
        tdx_dprintf(1, "failed to find 'opt/opentdx.npseamldr'\n");
        return NULL;
    }

    dst = malloc_high(file->size);
    if (!dst) {
        tdx_dprintf(1, "failed to malloc(npsaemldr->size)\n");
        return NULL;
    }

    int ret = file->copy(file, dst, file->size);
    if (ret < 0) {
        tdx_dprintf(1, "failed to copy npseamldr\n");
        return NULL;
    }

    return dst;
}

static void dump_acm_header(npseamldr_t *npseamldr)
{
    tdx_dprintf(1, \
"""ACM Header\n\
\tModuleType: %d\n\
\tModuleSubType: %d\n\
\tHeaderLen: %d\n\
\tHeaderVersion: 0x%05X\n\
\tChipsetID: 0x%04X\n\
\tFlags: 0x%04X\n\
\tModuleVendor: 0x%08X\n\
\tDate: %08X\n\
\tSize: %d\n\
\tTXT SVN: %d\n\
\tSGX SVN: %d\n\
\tCodeControl: 0x%08X\n\
\tErrorEntryPoint: 0x%08x\n\
\tGDTLimit: 0x%08X\n\
\tGDTBasePtr: 0x%08X\n\
\tSegSel: 0x%08X\n\
\tEntryPoint: 0x%08X\n\
\tKeySize: %d\n\
\tScratchSize: %d\n\
""", npseamldr->module_type, npseamldr->module_sub_type, 
     npseamldr->header_len, npseamldr->header_version,
     npseamldr->chipset_id, npseamldr->flags,
     npseamldr->module_vendor, npseamldr->date, 
     npseamldr->size, npseamldr->txt_svn, 
     npseamldr->sgx_svn, npseamldr->code_control,
     npseamldr->error_entry_point, npseamldr->gdt_limit,
     npseamldr->gdt_base_ptr, npseamldr->seg_sel,
     npseamldr->entry_point, npseamldr->key_size, 
     npseamldr->scratch_size);
}

static int check_acm_header(npseamldr_t *npseamldr)
{
    if (npseamldr->module_type != 2) {
        return -1;
    }

    if (npseamldr->module_sub_type != 0) {
        return -1;
    }

    if ((npseamldr->header_len != 224) ||
        (npseamldr->header_version != 0x30000) ||
        (npseamldr->key_size != 96) ||
        (npseamldr->scratch_size != 208)) {
        return -1;
    }
    return 0;
}

#define CPUID_ECX_SMX 6
#define CR4_SMXE 14
#define MSR_IA32_FEATURE_CONTROL 0x0000003a

static int enter_npseamldr(void *npseamldr, u32 npseamldr_size)
{ 
    u32 eax, ebx, ecx, edx;
    u32 cr4;
    u32 feature_control;
    int ret;

    /* Intel SDM Vol 2D. 7.3 */
    cpuid(1, &eax, &ebx, &ecx, &edx);
    tdx_dprintf(1, "CPUID.01H:ECX = 0x%08X\n", ecx);

    if (!(ecx & (1 << CPUID_ECX_SMX))) {
        return -1;
    }

    cr4 = cr4_read();
    cr4 |= 1 << CR4_SMXE;
    cr4_write(cr4);
    tdx_dprintf(1, "CR4 = 0x%08X\n", cr4);

    feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
    tdx_dprintf(1, "IA32_FEATURE_CONTROL = 0x%08X\n", feature_control);

    eax = CAPABILITIES;
    ebx = 0;
    asm volatile(
        "getsec\n\t"
        : "=a" (eax)
        : "a" (eax), "b" (ebx)
        : "memory"
    );
    tdx_dprintf(1, "GETSEC[CAPABILITIES] = 0x%08X\n", eax);

    tdx_dprintf(1, "execute GETSEC[ENTERACCS]\n");

    enter_longmode();
    ret = (int) enteraccs(npseamldr, npseamldr_size);
    exit_longmode();

    return ret;
}