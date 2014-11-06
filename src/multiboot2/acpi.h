#define EFI_ACPI_TABLE_GUID  					\
	{ 0xeb9d2d30, 0x2d88, 0x11d3, 				\
	{ 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } 	\
	}

#define EFI_ACPI_20_TABLE_GUID 					\
	{ 0x8868e871, 0xe4f1, 0x11d3, 				\
	{ 0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81 }	\
	}

typedef struct {
  uint8_t signature[8];
  uint8_t checksum;
  uint8_t oemid[6];
  uint8_t revision;
  uint32_t rsdt_addr;
} __attribute__ ((packed)) acpi1_rsdp_t;


typedef struct {
  acpi1_rsdp_t rsdpv1;
  uint32_t length;
  uint64_t xsdt_addr;
  uint8_t checksum;
  uint8_t reserved[3];
} __attribute__ ((packed)) acpi2_rsdp_t;
