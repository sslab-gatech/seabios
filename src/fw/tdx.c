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

    ret = enter_npseamldr((void *)npseamldr, npseamldr->size * 4);
    if (ret) {
        tdx_dprintf(1, "failed to enter npseamldr\n");
        return;
    }

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

    eax = ENTERACCS;
    asm volatile(
        "getsec\n\t"
        : "=a" (eax)
        : "a" (eax), "b" (npseamldr), "c" (npseamldr_size)
        : "memory"
    );

    return 0;
}