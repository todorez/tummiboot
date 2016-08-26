
#include <efi.h>
#include <efilib.h>
#include "multiboot2_util.h"

static efi_mmap_t efi_mmap ;


EFI_STATUS copy_file_buf(EFI_HANDLE parent_image, CHAR16 *file, CHAR8 **buf, UINTN *buf_len ){
    EFI_STATUS err;
	EFI_LOADED_IMAGE *loaded_image;
	EFI_FILE_HANDLE root_dir ;
    EFI_FILE_HANDLE file_handle;
    UINTN tmp_sz ;
    EFI_FILE_INFO tmp_buf;

	err = uefi_call_wrapper(BS->OpenProtocol, 6, parent_image, &LoadedImageProtocol, (void **)&loaded_image,
			parent_image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (EFI_ERROR(err)) {
		Print(L"Error getting a LoadedImageProtocol handle: %r ", err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
	}

	root_dir = LibOpenRoot(loaded_image->DeviceHandle);
	if (!root_dir) {
		Print(L"Unable to open root directory: %r ", err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return EFI_LOAD_ERROR;
	}

	err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file_handle, file, EFI_FILE_MODE_READ, 0ULL);
	if (EFI_ERROR(err)){
		Print(L"Unable to open file: %r ", err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return err;
	}

	/*read the whole file*/
	if(*buf_len == 0){

		tmp_sz = SIZE_OF_EFI_FILE_INFO + (StrLen(file) * sizeof(CHAR16));
		err  = uefi_call_wrapper(file_handle->GetInfo, 4, file_handle, &GenericFileInfo, &tmp_sz , &tmp_buf);

		if (EFI_ERROR(err)){
			Print(L"Unable to get file size: err : %d\n", err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			uefi_call_wrapper(file_handle->Close, 1, file_handle);
			return EFI_LOAD_ERROR;
		}

		*buf_len = tmp_buf.FileSize ;
	}

	*buf = AllocateZeroPool(*buf_len);
	err = uefi_call_wrapper(file_handle->Read, 3, file_handle, buf_len, *buf);


	if (EFI_ERROR(err) || *buf_len < 32) {
		Print(L"Unable to read file: erro : %r bytes read : %d\n", err, *buf_len);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		uefi_call_wrapper(file_handle->Close, 1, file_handle);
		return EFI_LOAD_ERROR;
	} else{
		Print(L"Read file : %s bytes read : %d\n", file, *buf_len);
		uefi_call_wrapper(BS->Stall, 1, 2 * 1000 * 1000);
	}

	uefi_call_wrapper(file_handle->Close, 1, file_handle);
	return EFI_SUCCESS;
}

EFI_STATUS parse_header(CHAR8 *buf, UINTN len){
	bool has_entry_addr_tag = false ;
	bool console_required = false;
	bool keep_bs = false;


	mboot_hdr_p hdr ;
	mboot_hdr_tag_p tag;
	mboot_hdr_tag_addr_p addr_tag = NULL;
	uint32_t entry_addr_tag ;
	mboot_hdr_tag_fbuf_p fbtag = NULL;

	int supported_consoles = MULTIBOOT_OS_CONSOLE_EGA_TEXT;

	/*look for the header magic in the buffer, validate the checksum and the arch*/
	for(hdr = (mboot_hdr_p)buf; ((char *) hdr <= (char *) buf + len - 16) || (hdr = 0);
			hdr = (mboot_hdr_p) ((uint32_t *) hdr + 2)){
		if (hdr->magic == MULTIBOOT2_HEADER_MAGIC){
			if(!(hdr->magic + hdr->architecture+ hdr->header_length + hdr->checksum)){
				if(hdr->architecture != MULTIBOOT_ARCHITECTURE_I386){
					Print(L"multiboot2 : Error: Invalid architecture %d.\n", __LINE__);
					uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
				}
				break ;
			}else{
				Print(L"multiboot2 : Error: Invalid checksum %d.\n", __LINE__);
				uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			}
		}
	}

	if (hdr == 0){
		Print(L"multiboot2 : Error: Multiboot2 header not found %d.\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	for (tag = (mboot_hdr_tag_p) (hdr + 1);
	       tag->type != MULTIBOOT_TAG_TYPE_END;
	       tag = (mboot_hdr_tag_p) ((uint32_t *) tag
           + ALIGN_UP (tag->size, 2))){

		switch(tag->type){
			case MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST:
			{
				unsigned short int i;
				mboot_hdr_tag_info_req_p req_tag = (mboot_hdr_tag_info_req_p) tag;

				if (req_tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)
					break;

				for (i = 0; i < (req_tag->size - sizeof (req_tag)) / sizeof (req_tag->requests[0]); i++)

				switch (req_tag->requests[i])
				{
					case MULTIBOOT_TAG_TYPE_END:
					case MULTIBOOT_TAG_TYPE_CMDLINE:
					case MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME:
					case MULTIBOOT_TAG_TYPE_MODULE:
				  case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
				  case MULTIBOOT_TAG_TYPE_BOOTDEV:
				  case MULTIBOOT_TAG_TYPE_MMAP:
				  case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
				  case MULTIBOOT_TAG_TYPE_VBE:
				  case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
				  case MULTIBOOT_TAG_TYPE_APM:
				  case MULTIBOOT_TAG_TYPE_EFI32:
				  case MULTIBOOT_TAG_TYPE_EFI64:
				  case MULTIBOOT_TAG_TYPE_ACPI_OLD:
				  case MULTIBOOT_TAG_TYPE_ACPI_NEW:
				  case MULTIBOOT_TAG_TYPE_NETWORK:
				  case MULTIBOOT_TAG_TYPE_EFI_MMAP:
				  case MULTIBOOT_TAG_TYPE_EFI_BS:
				  break;

				  default:
            Print(L"Unsupported information tag: 0x%x",
				      req_tag->requests[i]);
				    uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
				    return EFI_LOAD_ERROR;
				}
				break;
			}

			case MULTIBOOT_HEADER_TAG_ADDRESS:
				addr_tag = (mboot_hdr_tag_addr_p) tag;
				break;

			case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
				has_entry_addr_tag = true ;
				entry_addr_tag = ((mboot_hdr_tag_entry_addr_p) tag)->entry_addr;
				break;

			case MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
				if (!(((mboot_hdr_tag_con_flags_p) tag)->console_flags
						& MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED))
					supported_consoles &= ~MULTIBOOT_OS_CONSOLE_EGA_TEXT;
				if (((struct multiboot_header_tag_console_flags *) tag)->console_flags
						& MULTIBOOT_CONSOLE_FLAGS_CONSOLE_REQUIRED)
					console_required = true;

				break;

			case MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
				fbtag = (mboot_hdr_tag_fbuf_p) tag;
				supported_consoles |= MULTIBOOT_CONSOLE_FRAMEBUFFER;
				break;

			case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
				break;

			case MULTIBOOT_HEADER_TAG_EFI_BS:
				keep_bs = true;
				break;

			default:
        if (! (tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)){
          Print(L"Unsupported tag: 0x%x",tag->type);
          uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
          return EFI_LOAD_ERROR;
        }
        break ;
		}
	}

	if (addr_tag && !has_entry_addr_tag){
		Print(L"ERROR: OS entry address not found!\n");
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	if (addr_tag){
		Print(L"TODO - parse address tag. Feature not implemented yet.\n");
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
	}else{
		Print(L"%s : %d: Loading as ELF binary \n", __FILE__, __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
		return EFI_LOAD_ELF ;
	}

	return EFI_SUCCESS;

}


EFI_STATUS get_efi_mmap(){

	EFI_STATUS err ;
	UINTN mmap_size = 0 ;
	EFI_MEMORY_DESCRIPTOR *mmap = NULL;
	UINTN                 mapkey;
	UINTN                 desc_size;
	UINT32                desc_ver;

	err = uefi_call_wrapper(BS->GetMemoryMap,5,
			&mmap_size, NULL, NULL, &desc_size, NULL);

	/* Get mmap size only. BUFFER TOO SMALL expected here */
	if (err != EFI_BUFFER_TOO_SMALL) {
		Print(L"multiboot2:%d ERROR: %d Unable to get efi memory map size\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	mmap = (EFI_MEMORY_DESCRIPTOR *) AllocateZeroPool(mmap_size) ;
	if (!mmap)
		Print(L"multiboot2:%d ERROR:%d Unable to allocate efi mmap memory\n", __LINE__, err);

	/* get the real memory map */
	err = uefi_call_wrapper(BS->GetMemoryMap,5,
				&mmap_size, mmap, &mapkey, &desc_size, &desc_ver);
	if (EFI_ERROR(err)) {
		Print(L"multiboot2:%d ERROR:%d Unable to get efi memory map\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	efi_mmap.mmap_size = mmap_size ;
	efi_mmap.mmap = mmap ;
	efi_mmap.mapkey = mapkey ;
	efi_mmap.desc_size = desc_size ;
	efi_mmap.desc_ver = desc_ver ;

	Print(L"cmd line : mmap_size : %d desc_size : %d.\n", mmap_size, desc_size );
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

	return EFI_SUCCESS ;

}

static UINT32 get_mbi2_size (const ConfigEntry *entry)
{
	UINT32 mbi2_size ;
	EFI_STATUS err ;

	err = get_efi_mmap() ;
	if (EFI_ERROR(err)) {
		Print(L"multiboot2:%d ERROR:%d Unable to get efi memory map\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	mbi2_size =

	/******************** FIXED PART ********************/

	/* total_size */
	sizeof (UINT32)

	/* reserved */
	+ sizeof (UINT32)

	/******************** TAGS PART ********************/

    /* cmd line */
	 + (sizeof (struct multiboot_tag_string)
	       + ALIGN_UP (StrLen(entry->options) * sizeof(CHAR16), MULTIBOOT_TAG_ALIGN))

	/* bootloader name */
	+ (sizeof (struct multiboot_tag_string)
	       + ALIGN_UP (sizeof (PACKAGE_STRING), MULTIBOOT_TAG_ALIGN))

    /* modules - kernel + initrd */
	+ 2 * (sizeof (struct multiboot_tag_module))

  /* memory info */
  + ALIGN_UP (sizeof (struct multiboot_tag_basic_meminfo),
  MULTIBOOT_TAG_ALIGN)

	/* boot device - BIOS */

	/* TODO - ELF symbols */

	/* TODO - mmap */

	/* framebuffer info */
	+ ALIGN_UP (sizeof (struct multiboot_tag_framebuffer),
  MULTIBOOT_TAG_ALIGN)

	/* EFI32 - WE ARE 64BIT*/

	/* EFI64 */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi64),
  MULTIBOOT_TAG_ALIGN)

	/* TODO - ACPI old */

	/* TODO -ACPI new */

	/* TODO - Network */

	/* EFI mmap */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi_mmap)
				+ efi_mmap.mmap_size, MULTIBOOT_TAG_ALIGN)

	/* VBE - BIOS */

	/* APM - BIOS */

	/* END TAG */
	+ sizeof (struct multiboot_tag);

	Print(L"cmd line : cmd %s num %d.\n", entry->options,
			ALIGN_UP (StrLen(entry->options) * sizeof(CHAR16), MULTIBOOT_TAG_ALIGN));
			uefi_call_wrapper(BS->Stall, 1, 5 * 1000 * 1000);
  return mbi2_size ;
}

EFI_STATUS populate_mbi2(EFI_HANDLE parent_image, const ConfigEntry *entry){

	EFI_STATUS err ;
	VOID *mbi2_buf = NULL, *tmp = NULL ;
	CHAR8 *kernel_buf, *initrd_buf = NULL ;
	UINTN kern_sz = 0, initrd_sz = 0 ;

	mbi2_buf = AllocateZeroPool(get_mbi2_size(entry)) ;
	if(!mbi2_buf){
		Print(L"cmd line : Error populating mbi2 %d.\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

		return EFI_LOAD_ERROR ;
	}
	else{
		Print(L"multiboot2.c : Populating mbi2 %d.\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

		tmp = mbi2_buf ;

		/******************** FIXED PART ********************/

		/* total_size - populate at the end */
		((UINT32 *) tmp)[0] = 0 ;

		/* reserved */
		((UINT32 *) tmp)[1] = 0 ;
		tmp += 2 * sizeof(UINT32) ;
		/******************** TAGS PART ********************/

		/* cmd line */
		struct multiboot_tag_string *cmd_line_tag = (struct multiboot_tag_string *) tmp;
		cmd_line_tag->type = MULTIBOOT_TAG_TYPE_CMDLINE;
		cmd_line_tag->size = sizeof (struct multiboot_tag_string) + (StrLen(entry->options) * sizeof(CHAR16));
		memcpy(cmd_line_tag->string, entry->options, (StrLen(entry->options) * sizeof(CHAR16))) ;
		tmp += ALIGN_UP (cmd_line_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* bootloader name */
		struct multiboot_tag_string *bootloader_tag = (struct multiboot_tag_string *) tmp;
		bootloader_tag->type = MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME;
		bootloader_tag->size = sizeof (struct multiboot_tag_string) + sizeof (PACKAGE_STRING);
		memcpy(bootloader_tag->string, PACKAGE_STRING, sizeof (PACKAGE_STRING)) ;
		tmp += ALIGN_UP (bootloader_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* modules - kernel + initrd */
		err = copy_file_buf(parent_image, entry->loader, &kernel_buf, &kern_sz) ;
		if (EFI_ERROR(err) || !kernel_buf || !kern_sz){
			Print(L"cmd line : Error loading kernel %d.\n", __LINE__);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		struct multiboot_tag_module *kernel_mod_tag = (struct multiboot_tag_module *) tmp;
		kernel_mod_tag->type = MULTIBOOT_TAG_TYPE_MODULE;
		kernel_mod_tag->size = sizeof (struct multiboot_tag_module) + sizeof(NULL);
		kernel_mod_tag->mod_start = kernel_buf;
		kernel_mod_tag->mod_end = kernel_mod_tag->mod_start + kern_sz;
		kernel_mod_tag->cmdline[0] = "";
		tmp += ALIGN_UP (kernel_mod_tag->size, MULTIBOOT_TAG_ALIGN) ;

		err = copy_file_buf(parent_image, entry->initrd, &initrd_buf, &initrd_sz) ;
		if (EFI_ERROR(err) || !initrd_buf || !initrd_sz){
			Print(L"cmd line : Error loading initrd %d.\n", __LINE__);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		struct multiboot_tag_module *initrd_mod_tag = (struct multiboot_tag_module *) tmp;
		initrd_mod_tag->type = MULTIBOOT_TAG_TYPE_MODULE;
		initrd_mod_tag->size = sizeof (struct multiboot_tag_module)+ sizeof(NULL);
		initrd_mod_tag->mod_start = initrd_buf;
		initrd_mod_tag->mod_end = kernel_mod_tag->mod_start + initrd_sz;
		initrd_mod_tag->cmdline[0] = NULL;
		tmp += ALIGN_UP (initrd_mod_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* TODO - memory info */
		struct multiboot_tag_basic_meminfo *basic_meminfo_tag
		      = (struct multiboot_tag_basic_meminfo *) tmp;
		basic_meminfo_tag->type = MULTIBOOT_TAG_TYPE_BASIC_MEMINFO;
		basic_meminfo_tag->size = sizeof (struct multiboot_tag_basic_meminfo);
		tmp += ALIGN_UP (basic_meminfo_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* boot device - BIOS */

		/* TODO - ELF symbols */

		/* TODO - mmap */

		/* TODO - framebuffer info */

		/* EFI32 - WE ARE 64BIT*/

		/* EFI64 */
		struct multiboot_tag_efi64 *efi64_tag = (struct multiboot_tag_efi64 *) tmp;
		efi64_tag->type = MULTIBOOT_TAG_TYPE_EFI64;
		efi64_tag->size = sizeof (struct multiboot_tag_efi64);
		efi64_tag->pointer = ST;
		tmp += ALIGN_UP (efi64_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* TODO - ACPI old */

		/* TODO - ACPI new */

		/* TODO - Network */

		/* EFI mmap */
		struct multiboot_tag_efi_mmap *efi_mmap_tag = (struct multiboot_tag_efi_mmap *) tmp;
		efi_mmap_tag->type = MULTIBOOT_TAG_TYPE_EFI_MMAP;
		efi_mmap_tag->size = sizeof (struct multiboot_tag_efi_mmap) + efi_mmap.mmap_size;
		efi_mmap_tag->descr_size = efi_mmap.desc_size;
		efi_mmap_tag->descr_vers = efi_mmap.desc_ver;
		tmp += ALIGN_UP (efi_mmap_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* VBE - BIOS */

		/* APM - BIOS */

		/* END */
		struct multiboot_tag *end_tag = (struct multiboot_tag *) tmp;
		end_tag->type = MULTIBOOT_TAG_TYPE_END;
		end_tag->size = sizeof (struct multiboot_tag);
		tmp += ALIGN_UP (end_tag->size, MULTIBOOT_TAG_ALIGN);

		/* total_size */
		((UINT32 *) mbi2_buf)[0] = (char *) tmp - (char *) mbi2_buf;
	}

	return EFI_SUCCESS ;
}
