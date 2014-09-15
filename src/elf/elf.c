#include <multiboot2_util.h>
#include <efilib.h>
#include "elf.h"

extern VOID *mbi2_buf ;

static inline void *memset(void *b, int c, uint32_t len)
{
	char *bb;

	for (bb = (char *)b; len--; )
		*bb++ = c;

	return (b);
}

EFI_STATUS load_elf(CHAR8 *buf, void **entry)
{
	elf_header_t * elf = NULL ;

	int i ;

    if ( buf == NULL ) {
        Print(L"elf.c : %d: Buffer is zero.\n", __LINE__);
        uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
        return EFI_LOAD_ERROR;
    }else
    	elf = (elf_header_t *) buf ;

    /* validate the ELF header */
    if (elf->e_ident[EI_MAG0] != ELFMAG0
    		|| elf->e_ident[EI_MAG1] != ELFMAG1
    		|| elf->e_ident[EI_MAG2] != ELFMAG2
    		|| elf->e_ident[EI_MAG3] != ELFMAG3
    		|| elf->e_ident[EI_DATA] != ELFDATA2LSB){
        Print(L"elf.c : %d: Invalid ELF magic.\n", __LINE__);
    	uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
    	return EFI_LOAD_ERROR;
      }

    if (elf->e_ident[EI_CLASS] != ELFCLASS32 || elf->e_machine != EM_386
    		|| elf->e_version != EV_CURRENT){
        Print(L"elf.c : %d: Invalid ELF class.\n", __LINE__);
    	uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
    	return EFI_LOAD_ERROR;
    }

    if (elf->e_type != ET_EXEC && elf->e_type != ET_DYN){
        Print(L"elf.c : %d: Invalid ELF type.\n", __LINE__);
    	uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
    	return EFI_LOAD_ERROR;
    }

    /* load loadable segments into memory */
    for ( i = 0; i < elf->e_phnum; i++ ) {
        elf_program_header_t *ph = (elf_program_header_t *)
				 ((void *)elf + elf->e_phoff + i*elf->e_phentsize);

        if ( ph->p_type == PT_LOAD ) {
            memcpy((void *)(uint64_t)ph->p_paddr, (void *)elf + ph->p_offset,
                   ph->p_filesz);
            memset((void *)(uint64_t)(ph->p_paddr + ph->p_filesz), 0,
                   ph->p_memsz - ph->p_filesz);
        }
    }

    *entry = (void*) (uint64_t)elf->e_entry;


    return EFI_SUCCESS;
}

void start_elf(void *buf){

    if(!buf){
    		Print(L"elf.c : %d : Missing ELF entry point. Resetting.\n", __LINE__);
    		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
    		uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS,0,0);
    }

    if(!mbi2_buf){
    		Print(L"elf.c : %d : Missing MBI2 buffer. Resetting.\n", __LINE__);
    		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
    		uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS,0,0);

    }

    Print(L"elf.c : %d: MAGIC 			%x.\n", __LINE__, MULTIBOOT2_BOOTLOADER_MAGIC);
    Print(L"elf.c : %d: MBI2 ADDRESS 	%x.\n", __LINE__, mbi2_buf);
    Print(L"elf.c : %d: ENTRY ADDRESS 	%x.\n\n", __LINE__, buf);
    Print(L"elf.c : %d: LAUNCHING\n", __LINE__);

    uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

    /* EAX - multiboot2 magic, EBX - MBI2, ECX - entry point */
    __asm__ __volatile__ (
          "    jmp *%%rcx;    "
          "    ud2;          "
          :: "a" (MULTIBOOT2_BOOTLOADER_MAGIC), "b" (mbi2_buf), "c" (buf));


}
