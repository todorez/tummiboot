#include <efi.h>
#include <efilib.h>
#include "acpi.h"
#include "multiboot2_util.h"

static acpi1_rsdp_t *acpi1_rsdp = NULL;
static acpi2_rsdp_t *acpi2_rsdp = NULL;
static efi_mmap_t efi_mmap ;
static INTN e820_map_overflow = 0;
static unsigned int e820_count = 0;
UINT8  g_e820_mmap[2560] ;
extern EFI_GUID GraphicsOutputProtocol;




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
		Print(L"multiboot2.c : %d Error getting a LoadedImageProtocol handle: %r ", __LINE__, err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
	}

	root_dir = LibOpenRoot(loaded_image->DeviceHandle);
	if (!root_dir) {
		Print(L"multiboot2.c : %d Unable to open root directory: %r ", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return EFI_LOAD_ERROR;
	}

	err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &file_handle, file, EFI_FILE_MODE_READ, 0ULL);
	if (EFI_ERROR(err)){
		Print(L"multiboot2.c : %d Unable to open file: %r ", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return err;
	}

	/*read the whole file*/
	if(*buf_len == 0){

		tmp_sz = SIZE_OF_EFI_FILE_INFO + (StrLen(file) * sizeof(CHAR16));
		err  = uefi_call_wrapper(file_handle->GetInfo, 4, file_handle, &GenericFileInfo, &tmp_sz , &tmp_buf);

		if (EFI_ERROR(err)){
			Print(L"multiboot2.c : %d Unable to get file size: err : %d\n", __LINE__, err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			uefi_call_wrapper(file_handle->Close, 1, file_handle);
			return EFI_LOAD_ERROR;
		}

		*buf_len = tmp_buf.FileSize ;
	}

	*buf = AllocateZeroPool(*buf_len);
	err = uefi_call_wrapper(file_handle->Read, 3, file_handle, buf_len, *buf);


	if (EFI_ERROR(err) || *buf_len < 32) {
		Print(L"Unable to read file: error : %r bytes read : %d\n", err, *buf_len);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		uefi_call_wrapper(file_handle->Close, 1, file_handle);
		return EFI_LOAD_ERROR;
	} else{
		Print(L"multiboot2.c : %d Read file : %s bytes read : %d\n", __LINE__, file, *buf_len);
//		uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
	}

	uefi_call_wrapper(file_handle->Close, 1, file_handle);
	return EFI_SUCCESS;
}

EFI_STATUS parse_header(CHAR8 *buf, UINTN len){
	bool has_entry_addr_tag = false ;

	mboot_hdr_p hdr ;
	mboot_hdr_tag_p tag;
	mboot_hdr_tag_addr_p addr_tag = NULL;

	/* these 4 are unused for the moment - IGNORE COMPILER WARNING
	bool console_required = false;
	bool keep_bs = false;
	uint32_t entry_addr_tag ;
	mboot_hdr_tag_fbuf_p fbtag = NULL; */

	int supported_consoles = MULTIBOOT_OS_CONSOLE_EGA_TEXT;

	/*look for the header magic in the buffer, validate the checksum and the arch*/
	for(hdr = (mboot_hdr_p)buf; ((char *) hdr <= (char *) buf + len - 16) || (hdr = 0);
			hdr = (mboot_hdr_p) ((uint32_t *) hdr + 2)){
		if (hdr->magic == MULTIBOOT2_HEADER_MAGIC){
			if(!(hdr->magic + hdr->architecture+ hdr->header_length + hdr->checksum)){
				if(hdr->architecture != MULTIBOOT_ARCHITECTURE_I386){
					Print(L"multiboot2.c : %d  Error: Invalid architecture.\n", __LINE__);
					uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
				}
				break ;
			}else{
				Print(L"multiboot2.c : %d  Error: Invalid checksum.\n", __LINE__);
				uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			}
		}
	}

	if (hdr == 0){
		Print(L"multiboot2.c : %d Error: Multiboot2 header not found.\n", __LINE__);
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
            Print(L"multiboot2.c : %d Unsupported information tag: 0x%x",
            __LINE__, req_tag->requests[i]);
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
				//entry_addr_tag = ((mboot_hdr_tag_entry_addr_p) tag)->entry_addr;
				break;

			case MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
				if (!(((mboot_hdr_tag_con_flags_p) tag)->console_flags
						& MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED))
					supported_consoles &= ~MULTIBOOT_OS_CONSOLE_EGA_TEXT;
				if (((struct multiboot_header_tag_console_flags *) tag)->console_flags
						& MULTIBOOT_CONSOLE_FLAGS_CONSOLE_REQUIRED)
					//console_required = true;

				break;

			case MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
				//fbtag = (mboot_hdr_tag_fbuf_p) tag;
				supported_consoles |= MULTIBOOT_CONSOLE_FRAMEBUFFER;
				break;

			case MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
				break;

			case MULTIBOOT_HEADER_TAG_EFI_BS:
				//keep_bs = true;
				break;

			default:
        if (! (tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)){
          Print(L"multiboot2.c : %d Unsupported tag: 0x%x",__LINE__, tag->type);
          uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
          return EFI_LOAD_ERROR;
        }
        break ;
		}
	}

	if (addr_tag && !has_entry_addr_tag){
		Print(L"multiboot2.c : %d ERROR: OS entry address not found!\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	if (addr_tag){
		Print(L"multiboot2.c : %d TODO - parse address tag. Feature not implemented yet.\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
	}else{
		Print(L"multiboot2.c : %d Loading as ELF binary \n", __LINE__);
		return EFI_LOAD_ELF ;
	}

	return EFI_SUCCESS;

}

/* Convert EFI memory map to E820 map for the operating system
 * This code is based on a Linux kernel patch submitted by Edgar Hucek
 */
static void add_memory_region (e820_entry_t *e820_map,
			       unsigned int *e820_count,
			       unsigned long long start,
			       unsigned long size,
			       unsigned int type)
{
	int x = *e820_count;
	static unsigned long long estart = 0ULL;
	static unsigned long esize = 0L;
	static unsigned int etype = -1;
	static int merge = 0;

	if (x == 0)
		Print(L"multiboot2.c : %d : %3s %4s %16s/%12s/%s\n",
			__LINE__, L"idx", L" ", L"start", L"size", L"type");

	/* merge adjacent regions of same type */
	if ((x > 0) && e820_map[x-1].start + e820_map[x-1].size == start
	    && e820_map[x-1].type == type) {
		e820_map[x-1].size += size;
		estart = e820_map[x-1].start;
		esize  = e820_map[x-1].size;
		etype  = e820_map[x-1].type;
		merge++;
		return;
	}
	/* fill up to E820_MAX_ENTRIES */
	if ( x < E820_MAX_ENTRIES ) {
		e820_map[x].start = start;
		e820_map[x].size = size;
		e820_map[x].type = type;
		(*e820_count)++;
		if (merge)
			Print(L"multiboot2.c : %d  %3d ==>  %016llx/%012lx/%d (%d)\n",
				__LINE__, x-1, estart, esize, etype, merge);
		merge=0;
		Print(L"multiboot2.c : %d %3d add  %016llx/%012lx/%d\n",
			__LINE__, x, start, size, type);
		return;
	}
	/* different type means another region didn't fit */
	/* or same type, but there's a hole */
	if (etype != type || (estart + esize) != start) {
		if (merge)
			Print(L"multiboot2.c : %d %3d ===> %016llx/%012lx/%d (%d)\n",
			__LINE__, e820_map_overflow, estart, esize, etype, merge);
		merge = 0;
		estart = start;
		esize = size;
		etype = type;
		e820_map_overflow++;
		Print(L"multiboot2.c : %d %3d OVER %016llx/%012lx/%d\n",
			 __LINE__, e820_map_overflow, start, size, type);
		return;
	}
	/* same type and no hole, merge it */
	estart += esize;
	esize += size;
	merge++;
}

void convert_mmap_efi_e820(efi_mmap_t *efi_mmap)
{
	int efi_count, i;
	UINT64 start, end, size;
	EFI_MEMORY_DESCRIPTOR	*desc, *p;
	e820_entry_t *e820_map;

	e820_count = 0 ;
	p = efi_mmap->mmap;
	efi_count = efi_mmap->mmap_size/efi_mmap->desc_size;
	e820_map = (e820_entry_t *)g_e820_mmap;

	for (i = 0; i < efi_count; i++)
	{
		desc = p;
		switch (desc->Type) {
		case EfiACPIReclaimMemory:
			add_memory_region(e820_map, &e820_count,
					desc->PhysicalStart,
					desc->NumberOfPages << EFI_PAGE_SHIFT,
					E820_ACPI);
			break;
		case EfiRuntimeServicesCode:
			add_memory_region(e820_map, &e820_count,
					desc->PhysicalStart,
					desc->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_EXEC_CODE);
			break;
		case EfiRuntimeServicesData:
		case EfiReservedMemoryType:
		case EfiMemoryMappedIO:
		case EfiMemoryMappedIOPortSpace:
		case EfiUnusableMemory:
		case EfiPalCode:
			add_memory_region(e820_map, &e820_count,
					desc->PhysicalStart,
					desc->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_RESERVED);
			break;
		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
		case EfiConventionalMemory:
			start = desc->PhysicalStart;
			size = desc->NumberOfPages << EFI_PAGE_SHIFT;
			end = start + size;
			/* Fix up for BIOS that claims RAM in 640K-1MB region */
			if (start < 0x100000ULL && end > 0xA0000ULL) {
				if (start < 0xA0000ULL) {
					/* start < 640K
					 * set memory map from start to 640K
					 */
					add_memory_region(e820_map,
							  &e820_count,
							  start,
							  0xA0000ULL-start,
							  E820_RAM);
				}
				if (end <= 0x100000ULL)
					continue;
				/* end > 1MB
				 * set memory map avoiding 640K to 1MB hole
				 */
				start = 0x100000ULL;
				size = end - start;
			}
			add_memory_region(e820_map, &e820_count,
					  start, size, E820_RAM);
			break;
		case EfiACPIMemoryNVS:
			add_memory_region(e820_map, &e820_count,
					desc->PhysicalStart,
					desc->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_NVS);
			break;
		default:
			Print(L"multiboot2.c : %d hit default!?", __LINE__);
			add_memory_region(e820_map, &e820_count,
					desc->PhysicalStart,
					desc->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_RESERVED);
			break;
		}
		p = NextMemoryDescriptor(p, efi_mmap->desc_size);
	}
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
		Print(L"multiboot2.c : %d ERROR: %d Unable to get efi memory map size\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	mmap = (EFI_MEMORY_DESCRIPTOR *) AllocateZeroPool(mmap_size) ;
	if (!mmap)
		Print(L"multiboot2.c : %d ERROR:%d Unable to allocate efi mmap memory\n", __LINE__, err);

	/* get the real memory map */
	err = uefi_call_wrapper(BS->GetMemoryMap,5,
				&mmap_size, mmap, &mapkey, &desc_size, &desc_ver);
	if (EFI_ERROR(err)) {
		Print(L"multiboot2.c : %d ERROR:%d Unable to get efi memory map\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return EFI_LOAD_ERROR;
	}

	efi_mmap.mmap_size = mmap_size ;
	efi_mmap.mmap = mmap ;
	efi_mmap.mapkey = mapkey ;
	efi_mmap.desc_size = desc_size ;
	efi_mmap.desc_ver = desc_ver ;

	Print(L"multiboot2.c : %d efi_mmap_size : %d desc_size : %d.\n", __LINE__, mmap_size, desc_size );
//	uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);

	/* convert EFI mmap to E820 mmap */
	convert_mmap_efi_e820(&efi_mmap) ;

	return EFI_SUCCESS ;

}

static int gop_get_bpp (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info){
	uint32_t total_mask;
	int i;
	switch (mode_info->PixelFormat){
		case PixelBlueGreenRedReserved8BitPerColor:
		case PixelRedGreenBlueReserved8BitPerColor:
			return 32;

		case PixelBitMask:
			if ((mode_info->PixelInformation.RedMask & mode_info->PixelInformation.GreenMask)
				|| (mode_info->PixelInformation.RedMask & mode_info->PixelInformation.BlueMask)
				|| (mode_info->PixelInformation.GreenMask & mode_info->PixelInformation.BlueMask)
				|| (mode_info->PixelInformation.RedMask & mode_info->PixelInformation.ReservedMask)
				|| (mode_info->PixelInformation.GreenMask & mode_info->PixelInformation.ReservedMask)
				|| (mode_info->PixelInformation.BlueMask & mode_info->PixelInformation.ReservedMask))
				return 0;

			total_mask = mode_info->PixelInformation.RedMask | mode_info->PixelInformation.GreenMask
				| mode_info->PixelInformation.BlueMask | mode_info->PixelInformation.ReservedMask;

			for(i = 31; i >= 0; i--)
				if (total_mask & (1 << i))
					return i + 1;

		default:
			return 0;
	}
}

static void gop_get_bitmask (uint32_t mask, unsigned int *mask_size, unsigned int *field_pos){
	int i;
	int last_p;

	for (i = 31; i >= 0; i--)
		if (mask & (1 << i))
			break;

	if (i == -1){
		*mask_size = *field_pos = 0;
		return;
	}

	last_p = i;

	for (; i >= 0; i--)
		if (!(mask & (1 << i)))
			break;

	*field_pos = i + 1;
	*mask_size = last_p - *field_pos + 1;
}

EFI_STATUS set_rgbr_mask_sz_fld_pos(EFI_GRAPHICS_PIXEL_FORMAT  PixelFormat, EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info,
		fb_rgbr_mask_field_t *mask_fld){

	switch (PixelFormat){
		case PixelRedGreenBlueReserved8BitPerColor:
			mask_fld->r_mask_sz = 8;
			mask_fld->r_fld_pos = 0;
			mask_fld->g_mask_sz = 8;
			mask_fld->g_fld_pos = 8;
			mask_fld->b_mask_sz = 8;
			mask_fld->b_fld_pos = 16;
			mask_fld->res_mask_sz = 8;
			mask_fld->res_fld_pos = 24;
			break;

		case PixelBlueGreenRedReserved8BitPerColor:
			mask_fld->r_mask_sz = 8;
			mask_fld->r_fld_pos = 16;
			mask_fld->g_mask_sz = 8;
			mask_fld->g_fld_pos = 8;
			mask_fld->b_mask_sz = 8;
			mask_fld->b_fld_pos = 0;
			mask_fld->res_mask_sz = 8;
			mask_fld->res_fld_pos = 24;
			break;

		case PixelBitMask:
			gop_get_bitmask (mode_info->PixelInformation.RedMask, &mask_fld->r_mask_sz,
				&mask_fld->r_fld_pos);
			gop_get_bitmask (mode_info->PixelInformation.GreenMask, &mask_fld->g_mask_sz,
				&mask_fld->g_fld_pos);
			gop_get_bitmask (mode_info->PixelInformation.BlueMask, &mask_fld->b_mask_sz,
				&mask_fld->b_fld_pos);
			gop_get_bitmask (mode_info->PixelInformation.ReservedMask, &mask_fld->res_mask_sz,
				&mask_fld->res_fld_pos);
			break;

		default:
			return EFI_LOAD_ERROR ;
	}
	return EFI_SUCCESS ;
}

EFI_STATUS mbi2_populate_framebuffer(void** mbi2_buf){

	EFI_STATUS err;
	EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	UINTN SizeOfInfo;
	fb_rgbr_mask_field_t rgbr_mask_sz_fld_pos ;

	err = LibLocateProtocol(&GraphicsOutputProtocol, (void **)&gop);

	if (EFI_ERROR(err)) {
		Print(L"multiboot2.c : %d Unable to find GOP\n", __LINE__ );
		uefi_call_wrapper(BS->Stall, 1, 2 * 1000 * 1000);
		return EFI_LOAD_ERROR ;
	}

	err = uefi_call_wrapper(gop->QueryMode, 4, gop, gop->Mode->Mode,&SizeOfInfo, &info);
	if (EFI_ERROR(err) && err == EFI_NOT_STARTED){
		err = uefi_call_wrapper(gop->SetMode, 2, gop, gop->Mode->Mode);

		if (!EFI_ERROR(err))
			err = uefi_call_wrapper(gop->QueryMode, 4, gop, gop->Mode->Mode,&SizeOfInfo, &info);
	}

	if (EFI_ERROR(err)) {
		CHAR16 Buffer[64];
		StatusToString(Buffer, err);
		Print(L"multiboot2.c : %d Bad response from QueryMode: %d: %s (%d)\n", __LINE__, gop->Mode->Mode, Buffer, err);
		return EFI_LOAD_ERROR ;
	}

	err=set_rgbr_mask_sz_fld_pos(info->PixelFormat, info, &rgbr_mask_sz_fld_pos) ;
	if (EFI_ERROR(err)) {
		CHAR16 Buffer[64];
		StatusToString(Buffer, err);
		Print(L"multiboot2.c : %d ERROR: GOP unsupported video mode : %s (%d)\n\n", __LINE__, Buffer, err);
		return EFI_LOAD_ERROR ;
	}

	struct multiboot_tag_framebuffer *fb_tag
	    = (struct multiboot_tag_framebuffer *) *mbi2_buf;

	fb_tag->common.type = MULTIBOOT_TAG_TYPE_FRAMEBUFFER;
	fb_tag->common.size = sizeof (struct multiboot_tag_framebuffer_common) + 6;
	fb_tag->common.framebuffer_addr = gop->Mode->FrameBufferBase;
	fb_tag->common.framebuffer_width = info->HorizontalResolution;
	fb_tag->common.framebuffer_height = info->VerticalResolution;
	fb_tag->common.framebuffer_bpp = gop_get_bpp(info) ;
	fb_tag->common.framebuffer_pitch = info->PixelsPerScanLine * (fb_tag->common.framebuffer_bpp >> 3);
	fb_tag->common.reserved = 0;


	fb_tag->common.framebuffer_type = MULTIBOOT_FRAMEBUFFER_TYPE_RGB;
	fb_tag->framebuffer_red_field_position = rgbr_mask_sz_fld_pos.r_fld_pos;
	fb_tag->framebuffer_red_mask_size = rgbr_mask_sz_fld_pos.r_mask_sz;
	fb_tag->framebuffer_green_field_position = rgbr_mask_sz_fld_pos.g_fld_pos;
	fb_tag->framebuffer_green_mask_size = rgbr_mask_sz_fld_pos.g_mask_sz;
	fb_tag->framebuffer_blue_field_position = rgbr_mask_sz_fld_pos.b_fld_pos;
	fb_tag->framebuffer_blue_mask_size = rgbr_mask_sz_fld_pos.b_mask_sz;

	/* TODO - DEBUG framebuffer tag*/
	Print(L"multiboot2.c : %d fb type %d \n", __LINE__, fb_tag->common.type) ;
	Print(L"multiboot2.c : %d fb size %d \n", __LINE__, fb_tag->common.size) ;
	Print(L"multiboot2.c : %d fb base %x \n", __LINE__, fb_tag->common.framebuffer_addr) ;
	Print(L"multiboot2.c : %d fb width %d \n", __LINE__, fb_tag->common.framebuffer_width) ;
	Print(L"multiboot2.c : %d fb height %d \n", __LINE__, fb_tag->common.framebuffer_height) ;
	Print(L"multiboot2.c : %d fb bpp %d \n", __LINE__, fb_tag->common.framebuffer_bpp) ;
	Print(L"multiboot2.c : %d fb pitch %d \n", __LINE__, fb_tag->common.framebuffer_pitch) ;
	Print(L"multiboot2.c : %d fb fb type%d \n", __LINE__, fb_tag->common.framebuffer_type) ;

	Print(L"multiboot2.c : %d fb r_fld_pos %d \n", __LINE__, fb_tag->framebuffer_red_field_position) ;
	Print(L"multiboot2.c : %d fb r_mask_sz %d \n", __LINE__, fb_tag->framebuffer_red_mask_size) ;
	Print(L"multiboot2.c : %d fb g_fld_pos %d \n", __LINE__, fb_tag->framebuffer_green_field_position) ;
	Print(L"multiboot2.c : %d fb g_mask_sz %d \n", __LINE__, fb_tag->framebuffer_green_mask_size) ;
	Print(L"multiboot2.c : %d fb b_fld_pos %d \n", __LINE__, fb_tag->framebuffer_blue_field_position) ;
	Print(L"multiboot2.c : %d fb b_mask_sz %d \n", __LINE__, fb_tag->framebuffer_blue_mask_size) ;

	*mbi2_buf += ALIGN_UP(fb_tag->common.size, MULTIBOOT_TAG_ALIGN) ;

	return EFI_SUCCESS ;
}


EFI_STATUS get_acpi1_rsdp(){

	unsigned int i ;
	EFI_GUID *tmp_vendor_guid, acpi1_tbl_guid;

	acpi1_tbl_guid = (EFI_GUID) EFI_ACPI_TABLE_GUID ;

	for (i = 0; i < ST->NumberOfTableEntries; i++){
		tmp_vendor_guid = &ST->ConfigurationTable[i].VendorGuid ;

		if (!memcmp (tmp_vendor_guid, &acpi1_tbl_guid, sizeof (EFI_GUID))){
			acpi1_rsdp = (acpi1_rsdp_t *) ST->ConfigurationTable[i].VendorTable ;
			return EFI_SUCCESS ;

		}
	}
	acpi1_rsdp = NULL ;
	return EFI_LOAD_ERROR ;
}

EFI_STATUS get_acpi2_rsdp(){

	unsigned int i ;
	EFI_GUID *tmp_vendor_guid, acpi2_tbl_guid;

	acpi2_tbl_guid = (EFI_GUID) EFI_ACPI_20_TABLE_GUID ;

	for (i = 0; i < ST->NumberOfTableEntries; i++){
		tmp_vendor_guid = &ST->ConfigurationTable[i].VendorGuid ;

		if (!memcmp (tmp_vendor_guid, &acpi2_tbl_guid, sizeof (EFI_GUID))){
			acpi2_rsdp = (acpi2_rsdp_t *) ST->ConfigurationTable[i].VendorTable ;
			return EFI_SUCCESS ;
		}
	}
	acpi2_rsdp = NULL ;
	return EFI_LOAD_ERROR ;
}


static UINT32 get_mbi2_size (const ConfigEntry *entry)
{
	UINT32 mbi2_size ;
	EFI_STATUS err ;

	err = get_efi_mmap() ;
	if (EFI_ERROR(err)) {
		Print(L"multiboot2.c : %d ERROR:%d Unable to get efi memory map\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return 0;
	}

	err = get_acpi1_rsdp() ;
	if (EFI_ERROR(err)) {
		Print(L"multiboot2.c : %d ERROR:%d Unable to get ACPIv1 RSDP\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return 0;
	}


	err = get_acpi2_rsdp() ;
	if (EFI_ERROR(err)) {
		Print(L"multiboot2.c : %d ERROR:%d Unable to get ACPIv2 RSDP\n", __LINE__, err);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
		return 0;
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

    /* modules - kernel + initrd + acm + 3 terminators*/
	+ ALIGN_UP (3 * (sizeof (struct multiboot_tag_module)) + 3,
			MULTIBOOT_TAG_ALIGN)

  /* memory info */
  + ALIGN_UP (sizeof (struct multiboot_tag_basic_meminfo),
  MULTIBOOT_TAG_ALIGN)

	/* boot device - BIOS */

	/* ELF symbols - not used by tboot */

	/* mmap */
	+ ALIGN_UP ((sizeof (struct multiboot_tag_mmap)
		+ e820_count * sizeof (struct multiboot_mmap_entry)),
		MULTIBOOT_TAG_ALIGN)

	/* framebuffer info */
	+ ALIGN_UP (sizeof (struct multiboot_tag_framebuffer),
  MULTIBOOT_TAG_ALIGN)

	/* EFI32 - WE ARE 64BIT*/

	/* EFI64 */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi64),
  MULTIBOOT_TAG_ALIGN)

	/* ACPI old */
	+ ALIGN_UP (sizeof (struct multiboot_tag_old_acpi)
			+ sizeof (acpi1_rsdp_t), MULTIBOOT_TAG_ALIGN)

	/* ACPI new */
	+ ALIGN_UP (sizeof (struct multiboot_tag_new_acpi)
					   + acpi2_rsdp->length, MULTIBOOT_TAG_ALIGN)

	/* TODO - Network */

	/* EFI mmap */
	+ ALIGN_UP (sizeof (struct multiboot_tag_efi_mmap)
				+ efi_mmap.mmap_size, MULTIBOOT_TAG_ALIGN)

	/* VBE - BIOS */

	/* APM - BIOS */

	/* END TAG */
	+ sizeof (struct multiboot_tag);

  return mbi2_size ;
}

multiboot_uint32_t get_e820_lower_mem(){
	unsigned int i ;
	e820_entry_t *e820_map = (e820_entry_t *)g_e820_mmap;
	multiboot_uint32_t lower_mem ;

	for(i=0; i < e820_count; i++){

		if (e820_map[i].type == E820_RAM){
			if (e820_map[i].start == 0){
				lower_mem = e820_map[i].size + e820_map[i].start;

				if (lower_mem > 0x100000)
					lower_mem =  0x100000;

				return lower_mem ;
			}
		}
	}

	return 0 ;

}

multiboot_uint32_t get_e820_upper_mem(){
	unsigned int i ;
	e820_entry_t *e820_map = (e820_entry_t *)g_e820_mmap;
	multiboot_uint32_t upper_mem ;

	for(i=0; i < e820_count; i++){

		if (e820_map[i].type == E820_RAM){
			if (e820_map[i].start <= 0x100000 && e820_map[i].start +
					e820_map[i].size > 0x100000){
				upper_mem = e820_map[i].start +
						e820_map[i].size - 0x100000;
				return upper_mem ;
			}
		}
	}

	return 0 ;

}

EFI_STATUS populate_mbi2(EFI_HANDLE parent_image, const ConfigEntry *entry, void** mbi2_buf){

	EFI_STATUS err ;
	VOID *tmp = NULL ;
	CHAR8 *kernel_buf= NULL, *initrd_buf = NULL, *acm_buf = NULL ;
	UINTN kern_sz = 0, initrd_sz = 0, acm_sz = 0, i ;

	*mbi2_buf = AllocateZeroPool(get_mbi2_size(entry)) ;
	if(!*mbi2_buf){
		Print(L"multiboot2.c : %d : Error allocating mbi2 buffer.\n", __LINE__);
		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

		return EFI_LOAD_ERROR ;
	}
	else{
		Print(L"multiboot2.c : %d Populating mbi2.\n", __LINE__);
//		uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);

		tmp = *mbi2_buf ;

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

		/* modules - kernel + initrd + acm*/
		err = copy_file_buf(parent_image, entry->loader, &kernel_buf, &kern_sz) ;
		if (EFI_ERROR(err) || !kernel_buf || !kern_sz){
			Print(L"multiboot2.c : %d Error loading kernel %d.\n", __LINE__, err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		struct multiboot_tag_module *kernel_mod_tag = (struct multiboot_tag_module *) tmp;
		kernel_mod_tag->type = MULTIBOOT_TAG_TYPE_MODULE;
		kernel_mod_tag->size = sizeof (struct multiboot_tag_module) + 1;
		kernel_mod_tag->mod_start = (uint64_t)kernel_buf;
		kernel_mod_tag->mod_end = kernel_mod_tag->mod_start + kern_sz;
		kernel_mod_tag->cmdline[0] = '\0';
		tmp += ALIGN_UP (kernel_mod_tag->size, MULTIBOOT_TAG_ALIGN) ;

		err = copy_file_buf(parent_image, entry->initrd, &initrd_buf, &initrd_sz) ;
		if (EFI_ERROR(err) || !initrd_buf || !initrd_sz){
			Print(L"multiboot2.c : %d Error loading initrd %d.\n", __LINE__, err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		struct multiboot_tag_module *initrd_mod_tag = (struct multiboot_tag_module *) tmp;
		initrd_mod_tag->type = MULTIBOOT_TAG_TYPE_MODULE;
		initrd_mod_tag->size = sizeof (struct multiboot_tag_module)+ 1;
		initrd_mod_tag->mod_start = (uint64_t)initrd_buf;
		initrd_mod_tag->mod_end = initrd_mod_tag->mod_start + initrd_sz;
		initrd_mod_tag->cmdline[0] = '\0' ;
		tmp += ALIGN_UP (initrd_mod_tag->size, MULTIBOOT_TAG_ALIGN) ;


		err = copy_file_buf(parent_image, entry->acm, &acm_buf, &acm_sz) ;
		if (EFI_ERROR(err) || !acm_buf || !acm_sz){
			Print(L"multiboot2.c : %d Error loading acm %d.\n", __LINE__, err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		Print(L"multiboot2.c : %d ACM : %s\n", __LINE__,entry->acm ) ;
		struct multiboot_tag_module *acm_mod_tag = (struct multiboot_tag_module *) tmp;
		acm_mod_tag->type = MULTIBOOT_TAG_TYPE_MODULE;
		acm_mod_tag->size = sizeof (struct multiboot_tag_module)+ 1;
		acm_mod_tag->mod_start = (uint64_t)acm_buf;
		acm_mod_tag->mod_end = initrd_mod_tag->mod_start + acm_sz;
		acm_mod_tag->cmdline[0] = '\0' ;
		tmp += ALIGN_UP (acm_mod_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* memory info */
		struct multiboot_tag_basic_meminfo *basic_meminfo_tag
		      = (struct multiboot_tag_basic_meminfo *) tmp;
		basic_meminfo_tag->type = MULTIBOOT_TAG_TYPE_BASIC_MEMINFO;
		basic_meminfo_tag->size = sizeof (struct multiboot_tag_basic_meminfo);
		basic_meminfo_tag->mem_lower = get_e820_lower_mem() /1024;
		basic_meminfo_tag->mem_upper = get_e820_upper_mem() / 1024 ;
		tmp += ALIGN_UP (basic_meminfo_tag->size, MULTIBOOT_TAG_ALIGN) ;

		Print(L"multiboot2.c : %d mem_lower : %d mem_upper : %d\n", __LINE__,
				basic_meminfo_tag->mem_lower, basic_meminfo_tag->mem_upper );

		/* boot device - BIOS */

		/* ELF symbols - not used by tboot */

		/* mmap */
		struct multiboot_tag_mmap *e820_mmap_tag = (struct multiboot_tag_mmap *) tmp;
		struct multiboot_mmap_entry *mmap_entry = e820_mmap_tag->entries;
		e820_mmap_tag->type = MULTIBOOT_TAG_TYPE_MMAP;
		e820_mmap_tag->size = sizeof (struct multiboot_tag_mmap)
		    + sizeof (struct multiboot_mmap_entry) * e820_count;
		e820_mmap_tag->entry_size = sizeof (struct multiboot_mmap_entry);
		e820_mmap_tag->entry_version = 0;

		e820_entry_t *e820_map = (e820_entry_t *)g_e820_mmap;

		Print(L"E820 memory map \n");
		for(i=0; i < e820_count; i++){
			mmap_entry[i].addr = e820_map[i].start;
			mmap_entry[i].len = e820_map[i].size;
			mmap_entry[i].type = e820_map[i].type;

			Print(L"addr : %x - len : %x - type : %d\n", mmap_entry[i].addr, mmap_entry[i].len, mmap_entry[i].type );
		}
//		uefi_call_wrapper(BS->Stall, 1, 1 * 1000 * 1000);
		tmp += ALIGN_UP (e820_mmap_tag->size, MULTIBOOT_TAG_ALIGN);


		/* framebuffer info */
		err = mbi2_populate_framebuffer(&tmp) ;
		if (EFI_ERROR(err)){
			Print(L"multiboot2.c : %d Error populating framebuffer %d.\n", __LINE__, err);
			uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
			return EFI_LOAD_ERROR ;
		}

		/* EFI32 - WE ARE 64BIT*/

		/* EFI64 */
		struct multiboot_tag_efi64 *efi64_tag = (struct multiboot_tag_efi64 *) tmp;
		efi64_tag->type = MULTIBOOT_TAG_TYPE_EFI64;
		efi64_tag->size = sizeof (struct multiboot_tag_efi64);
		efi64_tag->pointer = (uint64_t)ST;
		tmp += ALIGN_UP (efi64_tag->size, MULTIBOOT_TAG_ALIGN) ;

		/* ACPI old */
		if (acpi1_rsdp){
			struct multiboot_tag_old_acpi *acpiv1_tag =
					(struct multiboot_tag_old_acpi *)tmp;
			acpiv1_tag->type = MULTIBOOT_TAG_TYPE_ACPI_OLD;
			acpiv1_tag->size = sizeof (struct multiboot_tag_old_acpi)
					+ sizeof (acpi1_rsdp_t);
			memcpy (acpiv1_tag->rsdp, acpi1_rsdp, sizeof (acpi1_rsdp_t));
			tmp += ALIGN_UP (acpiv1_tag->size, MULTIBOOT_TAG_ALIGN);
		}

		/* ACPI new */
		if (acpi2_rsdp){
			struct multiboot_tag_new_acpi *acpiv2_tag =
					(struct multiboot_tag_new_acpi *)tmp;
			acpiv2_tag->type = MULTIBOOT_TAG_TYPE_ACPI_NEW;
			acpiv2_tag->size = sizeof (struct multiboot_tag_new_acpi)
					+ acpi2_rsdp->length;
			memcpy (acpiv2_tag->rsdp, acpiv2_tag, acpi2_rsdp->length);
			tmp += ALIGN_UP (acpiv2_tag->size, MULTIBOOT_TAG_ALIGN);
		}

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
		((UINT32 *) *mbi2_buf)[0] = (char *) tmp - (char *) *mbi2_buf;
	}

	return EFI_SUCCESS ;
}
