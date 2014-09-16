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
        CHAR16 *options;
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
void start_elf(void *buf) ;
EFI_STATUS populate_mbi2(EFI_HANDLE parent_image, const ConfigEntry *entry) ;
void *memcpy(void *dst0, const void *src0, unsigned long length) ;
int memcmp (const void *s1, const void *s2, unsigned n) ;


#endif
