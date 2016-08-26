#include <multiboot2_util.h>
#include <efilib.h>
#include "elf.h"

static inline void *
memset (void *b, int c, uint32_t len) {
  char *bb;

  for (bb = (char *) b; len--;)
    *bb++ = c;

  return (b);
}

EFI_STATUS load_elf(CHAR8 *buf, void **entry)
{
	int i ;
	elf_header_t * elf = NULL ;

  if ( buf == NULL ) {
    print_msg ("multiboot2.c", __LINE__, ERR_ELF_HDR, 'o');
    return EFI_LOAD_ERROR;
  }else
    elf = (elf_header_t *) buf ;

  /* validate the ELF header */
  if (elf->e_ident[EI_MAG0] != ELFMAG0
    || elf->e_ident[EI_MAG1] != ELFMAG1
    || elf->e_ident[EI_MAG2] != ELFMAG2
    || elf->e_ident[EI_MAG3] != ELFMAG3
    || elf->e_ident[EI_DATA] != ELFDATA2LSB){

    print_msg ("multiboot2.c", __LINE__, ERR_ELF_MAGIC, 'o');
    return EFI_LOAD_ERROR;
  }

  if (elf->e_ident[EI_CLASS] != ELFCLASS32 || elf->e_machine != EM_386
    || elf->e_version != EV_CURRENT){
    print_msg ("multiboot2.c", __LINE__, ERR_ELF_CLASS, 'o');
    return EFI_LOAD_ERROR;
  }

  if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN){
    print_msg ("multiboot2.c", __LINE__, ERR_ELF_TYPE, 'o');
    return EFI_LOAD_ERROR;
  }

  /* load loadable segments into memory */
  for (i = 0; i < elf->e_phnum; i++) {
    elf_program_header_t *ph = (elf_program_header_t *)
      ((void *) elf + elf->e_phoff + i * elf->e_phentsize);

    if (ph->p_type == PT_LOAD) {
      memcpy ((void *) (uint64_t) ph->p_paddr, (void *) elf + ph->p_offset,
	      ph->p_filesz);

      memset ((void *) (uint64_t) (ph->p_paddr + ph->p_filesz), 0,
	      ph->p_memsz - ph->p_filesz);
    }
  }

  *entry = (void *) (uint64_t) elf->e_entry;
  return EFI_SUCCESS;
}

void
start_elf (void *buf, void *mbi2_buf) {

  struct seg_desc global_desc_table[] = {
    /* NULL descriptor 0x0 */
    {0,},
    /* Code32 segment descriptor 0x08 */
    populate_4k_seg_descriptor (0, 0xffffffff, 0x1, gdt_cs_flags_limit),
    /* Data32 segment descriptor 0x10 */
    populate_4k_seg_descriptor (0, 0xffffffff, 0x1, gdt_ds_flags_limit),
    /* Task state segment descriptor 0x18 */
    {0,},
    /* Code16 segment descriptor 0x20 */
    populate_4k_seg_descriptor (0, 0xffffffff, 0x0, gdt_cs_flags_limit),

    /* Data16 segment descriptor 0x28 */
    populate_4k_seg_descriptor (0, 0xffffffff, 0x0, gdt_ds_flags_limit)
  };

  struct {
    /* GDT size - 1 */
    uint16_t sz;
    /* GDT address */
    uint32_t addr;
  } __attribute__ ((__packed__)) gdt_desc;

  gdt_desc.sz = sizeof (global_desc_table) - 1;
  gdt_desc.addr = (uint64_t) global_desc_table;

  if (!buf) {
    print_msg ("multiboot2.c", __LINE__, ERR_ELF_ENTRY, 'o');
    uefi_call_wrapper (RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS, 0, 0);
  }

  if (!mbi2_buf) {
    print_msg ("multiboot2.c", __LINE__, ERR_MBI2_BUF, 'o');
    uefi_call_wrapper (RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS, 0, 0);
  }

  __asm__ __volatile__ (
	"lgdt %0                ;"	/* load GDT into GDTR */
	"pushq %1               ;"	/* push code segment selector on the stack */
	"leaq 1f(%%rip), %%rax  ;"	/* address to jump into */
	"pushq %%rax            ;"	/* push jump address on the stack */
	"retfq                  ;"
	"1:mov %2, %%ax         ;"	/* we are in compatibility mode */
	"mov %%ax, %%ds         ;"	/* reset the data segments */
	"mov %%ax, %%es         ;"
	"mov %%ax, %%fs         ;"
	"mov %%ax, %%gs         ;"
	"mov %%ax, %%ss         ;"
	"mov %%cr0, %%rax       ;"
	"btcl $31, %%eax        ;"	/* disable paging */
	"mov %%rax, %%cr0       ;"
	"movl $0x0c0000080, %%ecx ;"	/* EFER MSR number */
	"rdmsr                    ;"	/* Read EFER. */
	"btcl $8, %%eax           ;"	/* Set LME=0. */
	"wrmsr                    ;"	/* Write EFER. */
	::"m" (gdt_desc), "i" (cs_sel), "i" (ds_sel));
	/* Goodbye long mode, we are back to protected mode */

  /* hand over to tboot */
  /* EAX - multiboot2 magic
     EBX - MBI2
     ECX - tboot entry point */

  __asm__ __volatile__ (
	"push %2                  ;"
	"mov  $0x36d76289, %%eax  ;"	/* Shouldn't be really needed, but EAX gets corrupted */
	"ret                      ;"
	::"a"(MULTIBOOT2_BOOTLOADER_MAGIC),"b" (mbi2_buf), "c" (buf));

  /* WE SHOULD NEVER REACH HERE */
}
