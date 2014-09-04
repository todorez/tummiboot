#ifndef __MULTIBOOT2_UTIL_H
#define __MULTIBOOT2_UTIL_H

#include <efi.h>
#include "multiboot2.h"

#define EFI_LOAD_ELF	50
#define MULTIBOOT_OS_CONSOLE_EGA_TEXT 1
#define MULTIBOOT_CONSOLE_FRAMEBUFFER 2

#define ALIGN_UP(addr, align) \
        ((addr + (typeof (addr)) align - 1) & ~((typeof (addr)) align - 1))

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
EFI_STATUS load_elf(CHAR8 *buf) ;
void *memcpy(void *dst0, const void *src0, unsigned long length) ;


#endif
