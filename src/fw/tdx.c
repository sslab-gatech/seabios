#include "output.h"
#include "romfile.h"
#include "malloc.h"
#include "tdx.h"

#define tdx_dprintf(lvl, fmt, args...) dprintf(lvl, "[OpenTDX] " fmt, ##args)

static void *load_npseamldr(void);
static void dump_acm_header(npseamldr_t *npseamldr);

void
opentdx_setup(void)
{
    npseamldr_t *npseamldr;

    tdx_dprintf(1, "setup open-tdx\n");

    npseamldr = (npseamldr_t *) load_npseamldr();

    tdx_dprintf(1, "loaded npseamldr to %p\n", npseamldr);

    dump_acm_header(npseamldr);
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