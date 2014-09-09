
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

		//TODO - remove debug messages
		if (hdr->magic == MULTIBOOT2_HEADER_MAGIC){
			Print(L"Found multiboot2 header!\n");
			uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
			if(!(hdr->magic + hdr->architecture+ hdr->header_length + hdr->checksum)){
				Print(L"Validated architecture!\n");
				uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);

				if(hdr->architecture == MULTIBOOT_ARCHITECTURE_I386)
					Print(L"Validated multiboot2 checksum!\n");

				uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
				break ;
			}
		}
	}

	//multiboot2 header not found or invalid checksum or arch
	if (hdr == 0)
		return EFI_LOAD_ERROR;

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
	efi_mmap_t efi_mmap ;

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

	/* boot device */
    + ALIGN_UP (sizeof (struct multiboot_tag_bootdev),
    	MULTIBOOT_TAG_ALIGN)

    /* TODO - ELF symbols */

    /* TODO - E820 mmap */

	/* framebuffer info */
	+ ALIGN_UP (sizeof (struct multiboot_tag_framebuffer),
		MULTIBOOT_TAG_ALIGN)

	/* EFI32 */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi32),
		MULTIBOOT_TAG_ALIGN)

	/* EFI64 */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi64),
		MULTIBOOT_TAG_ALIGN)

	/* TODO - ACPI old */

	/* TODO -ACPI new */

	/* TODO - Network */

	/* EFI mmap */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi_mmap)
				+ efi_mmap.mmap_size, MULTIBOOT_TAG_ALIGN)

	/* VBE */
    + sizeof (struct multiboot_tag_vbe) +
    	MULTIBOOT_TAG_ALIGN - 1

    /* APM */
    + sizeof (struct multiboot_tag_apm) +
    	MULTIBOOT_TAG_ALIGN - 1;

	Print(L"cmd line : cmd %s num %d.\n", entry->options,
			ALIGN_UP (StrLen(entry->options) * sizeof(CHAR16), MULTIBOOT_TAG_ALIGN));
			uefi_call_wrapper(BS->Stall, 1, 5 * 1000 * 1000);
  return mbi2_size ;
}

EFI_STATUS populate_mbi2(const ConfigEntry *entry){

	VOID *mbi2_buf = NULL, *tmp = NULL ;

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
		/******************** TAGS PART ********************/

		/* cmd line */

		tmp += 2 * sizeof(UINT32) ;
		struct multiboot_tag_string *tag = (struct multiboot_tag_string *) tmp;
		tag->type = MULTIBOOT_TAG_TYPE_CMDLINE;
		tag->size = sizeof (struct multiboot_tag_string) + (StrLen(entry->options) * sizeof(CHAR16));
		memcpy(tag->string, entry->options, (StrLen(entry->options) * sizeof(CHAR16))) ;
		tmp += ALIGN_UP (tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* TODO - bootloader name */

		/* TODO - modules - kernel + initrd */

		/* TODO - memory info */

		/* TODO - boot device */

		/* TODO - ELF symbols */

		/* TODO - E820 mmap */

		/* TODO - framebuffer info */

		/* TODO - EFI32 */

		/* TODO - EFI64 */

		/* TODO - ACPI old */

		/* TODO - ACPI new */

		/* TODO - Network */

		/* TODO - EFI mmap */

		/* TODO - VBE */

		/* TODO - APM */

		/* total_size */
		((UINT32 *) mbi2_buf)[0] = (char *) tmp - (char *) mbi2_buf; ;

	}

	return EFI_SUCCESS ;
}





