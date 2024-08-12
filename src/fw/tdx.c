#include "output.h"
#include "romfile.h"
#include "malloc.h"
#include "x86.h"
#include "tdx.h"

#define tdx_dprintf(lvl, fmt, args...) dprintf(lvl, "[OpenTDX] " fmt, ##args)

static void *load_npseamldr(void);
static void dump_acm_header(npseamldr_t *npseamldr);
static int check_acm_header(npseamldr_t *npseamldr);
static int enter_npseamldr(void *npseamldr);

void
opentdx_setup(void)
{
    npseamldr_t *npseamldr;
    int ret;

    tdx_dprintf(1, "setup open-tdx\n");

    npseamldr = (npseamldr_t *) load_npseamldr();

    tdx_dprintf(1, "loaded npseamldr to %p\n", npseamldr);

    dump_acm_header(npseamldr);

    if (check_acm_header(npseamldr)) {
        tdx_dprintf(1, "invalid ACM header\n");
        return;
    }

    ret = enter_npseamldr((void *)npseamldr);
    if (ret) {
        tdx_dprintf(1, "failed to enter npseamldr\n");
    }
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

static int enter_npseamldr(void *npseamldr)
{ 
    u32 eax, ebx, ecx, edx;
    u32 cr4;

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

    eax = ENTERACCS;
    asm volatile(
        "getsec\n\t"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (eax)
        : "memory"
    );

    return 0;
}