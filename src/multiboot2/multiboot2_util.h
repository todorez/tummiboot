#ifndef __MULTIBOOT2_UTIL_H
#define __MULTIBOOT2_UTIL_H

#include <efi.h>
#include "multiboot2.h"

#define EFI_LOAD_ELF			50

#define E820_MAX_ENTRIES		128
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3
#define E820_NVS        4
#define E820_EXEC_CODE  5


#define MULTIBOOT_OS_CONSOLE_EGA_TEXT 1
#define MULTIBOOT_CONSOLE_FRAMEBUFFER 2

#define cs_sel      1<<3
#define ds_sel      2<<3
#define gdt_cs_flags_limit  0x9a /* present, system, DPL-0, execute/read     */
#define gdt_ds_flags_limit  0x92 /* present, system, DPL-0, read/write       */

#define ALIGN_UP(addr, align) \
        ((addr + (typeof (addr)) align - 1) & ~((typeof (addr)) align - 1))

enum loader_type {
        LOADER_UNDEFINED,
        LOADER_EFI,
        LOADER_LINUX
};

typedef struct {
        CHAR16 *file;
        CHAR16 *title_show;
        CHAR16 *title;
        CHAR16 *version;
        CHAR16 *machine_id;
        EFI_HANDLE *device;
        enum loader_type type;
        CHAR16 *loader;
        CHAR16 *initrd;
        CHAR16 *multiboot2;
        CHAR16 *acm;
        CHAR16 *options;
        CHAR16 *mboot2_options;
        CHAR16 *splash;
        CHAR16 key;
        EFI_STATUS (*call)(void);
        BOOLEAN no_autoselect;
        BOOLEAN non_unique;
} ConfigEntry;

typedef struct {
        ConfigEntry **entries;
        UINTN entry_count;
        INTN idx_default;
        INTN idx_default_efivar;
        UINTN timeout_sec;
        UINTN timeout_sec_config;
        INTN timeout_sec_efivar;
        CHAR16 *entry_default_pattern;
        CHAR16 *splash;
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL *background;
        CHAR16 *entry_oneshot;
        CHAR16 *options_edit;
        CHAR16 *entries_auto;
} Config;

typedef struct {
  UINTN                 mmap_size;
  EFI_MEMORY_DESCRIPTOR *mmap;
  UINTN                 mapkey;
  UINTN                 desc_size;
  UINT32                desc_ver;
}efi_mmap_t;

typedef struct{
	UINT64 start;
	UINT64 size;
	UINT32 type;
} __attribute__((packed)) e820_entry_t;

typedef struct{
	  unsigned int r_mask_sz;
	  unsigned int r_fld_pos;
	  unsigned int g_mask_sz;
	  unsigned int g_fld_pos;
	  unsigned int b_mask_sz;
	  unsigned int b_fld_pos;
	  unsigned int res_mask_sz;
	  unsigned int res_fld_pos;

}fb_rgbr_mask_field_t ;

struct seg_desc {

    uint16_t limit_15_0;
    uint16_t base_addr_15_0;
    uint8_t base_addr_23_16;

    /* 4 bits flags + 4 bits limit*/
    uint8_t flags_lim;

    /* Bits 16-19 in the segment limiter. */
    uint8_t limit_19_16:4;

    uint8_t u:1;
    uint8_t x:1;

    /*  D=0 16-bit segment, D=1, 32-bit */
    uint8_t d:1;

    /* Granularity G=0 1 byte, G=1 4KB */
    uint8_t g:1;
    uint8_t base_addr_31_24;
} __attribute__((__packed__));

/* Build a 4KB granular segment descriptor. */
#define populate_4k_seg_descriptor(base_addr, limit, bits, flags_limit) ((struct seg_desc) {	\
        .limit_15_0 = ((limit) >> 12) & 0xffff,                                                 \
        .limit_19_16 = ((limit) >> 28) & 0xf,							\
        .base_addr_15_0 = (base_addr) & 0xffff,							\
        .base_addr_23_16 = ((base_addr) >> 16) & 0xff,						\
        .base_addr_31_24 = ((base_addr) >> 24) & 0xff,						\
        .u = 0,											\
        .x = 0,											\
        .d = (bits),										\
        .g = 1,											\
        .flags_lim = (flags_limit)})

typedef enum { false, true } bool;

typedef struct multiboot_header mboot_hdr_t ;
typedef mboot_hdr_t* mboot_hdr_p ;

typedef struct multiboot_header_tag mboot_hdr_tag_t ;
typedef mboot_hdr_tag_t* mboot_hdr_tag_p ;

typedef struct multiboot_header_tag_information_request mboot_hdr_tag_info_req_t ;
typedef mboot_hdr_tag_info_req_t* mboot_hdr_tag_info_req_p ;

typedef struct multiboot_header_tag_address mboot_hdr_tag_addr_t ;
typedef mboot_hdr_tag_addr_t* mboot_hdr_tag_addr_p ;

typedef struct multiboot_header_tag_entry_address mboot_hdr_tag_entry_addr_t ;
typedef mboot_hdr_tag_entry_addr_t* mboot_hdr_tag_entry_addr_p ;

typedef struct multiboot_header_tag_console_flags mboot_hdr_tag_con_flags_t ;
typedef mboot_hdr_tag_con_flags_t* mboot_hdr_tag_con_flags_p ;


typedef struct multiboot_header_tag_framebuffer mboot_hdr_tag_fbuf_t ;
typedef mboot_hdr_tag_fbuf_t* mboot_hdr_tag_fbuf_p ;

EFI_STATUS copy_file_buf(EFI_HANDLE parent_image, CHAR16 *mboot_file, CHAR8 **buf, UINTN *mboot_len) ;
EFI_STATUS parse_header(CHAR8 *buf, UINTN len) ;
EFI_STATUS load_elf(CHAR8 *buf, void **entry) ;
void start_elf(void *buf, void* mbi2_buf) ;
EFI_STATUS populate_mbi2(EFI_HANDLE parent_image, const ConfigEntry *entry, void** mbi2_buf) ;
void *memcpy(void *dst0, const void *src0, unsigned long length) ;
int memcmp (const void *s1, const void *s2, unsigned n) ;


#endif
