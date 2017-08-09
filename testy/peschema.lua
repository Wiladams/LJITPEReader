--[[
	Schema for Windows Portable Executable file format
	Revision 8.3 - February 6, 2013

	This file contains the schema lifted from the spec, and put into 
	a form which is machine maleable.

	A tool can be used to turn this schema into various forms which
	will be appropriate for different programming environments.
--]]

--[[
	
	References

	http://ivanlef0u.fr/repo/windoz/pe/CBM_1_2_2006_Goppit_PE_Format_Reverse_Engineer_View.pdf
	http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
--]]

local PETypes = {
-- DOS .EXE header
IMAGE_DOS_HEADER_Info = {
	name = "IMAGE_DOS_HEADER";
	fields = {
		{name = "e_magic", basetype="char", repeating=2},                     -- Magic number
		{name = "e_cblp", basetype="uint16_t"},                      -- Bytes on last page of file
		{name = "e_cp", basetype="uint16_t"},                        -- Pages in file
		{name = "e_crlc", basetype="uint16_t"},                      -- Relocations
		{name = "e_cparhdr", basetype="uint16_t"},                   -- Size of header in paragraphs
		{name = "e_minalloc", basetype="uint16_t"},                  -- Minimum extra paragraphs needed
		{name = "e_maxalloc", basetype="uint16_t"},                  -- Maximum extra paragraphs needed
		{name = "e_ss", basetype="uint16_t"},                        -- Initial (relative) SS value
		{name = "e_sp", basetype="uint16_t"},                        -- Initial SP value
		{name = "e_csum", basetype="uint16_t"},                      -- Checksum
		{name = "e_ip", basetype="uint16_t"},                        -- Initial IP value
		{name = "e_cs", basetype="uint16_t"},                        -- Initial (relative) CS value
		{name = "e_lfarlc", basetype="uint16_t"},                    -- File address of relocation table
		{name = "e_ovno", basetype="uint16_t"},                      -- Overlay number
		{name = "e_res", basetype="uint16_t", repeating=4},          -- Reserved s
		{name = "e_oemid", basetype="uint16_t"},                     -- OEM identifier (for e_oeminfo)
		{name = "e_oeminfo", basetype="uint16_t"},                   -- OEM information; e_oemid specific
		{name = "e_res2", basetype="uint16_t", repeating=10},        -- Reserved s
		{name = "e_lfanew", basetype="uint32_t"},                    -- File address of new exe header
  }
};

MAGIC_Info = {
	name = "MAGIC",
	fields = {
		{name = "Signature", basetype = "char", repeating = 2}
	};
};

MAGIC2_Info = {
	name = "MAGIC2",
	fields = {
		{name = "Signature", basetype = "char", repeating = 2}
	}
};

MAGIC4_Info = {
	name = "MAGIC4",
	fields = {
		{name = "Signature", basetype = "char", repeating = 4}
	}
};


COFF_Info = {
	name = "COFF";
	fields = {
		{name = "Machine", basetype = "uint16_t"};
		{name = "NumberOfSections", basetype = "uint16_t"};
		{name = "TimeDateStamp", basetype = "uint32_t"};
		{name = "PointerToSymbolTable", basetype = "uint32_t"};
		{name = "NumberOfSymbols", basetype = "uint32_t"};
		{name = "SizeOfOptionalHeader", basetype = "uint16_t"};
		{name = "Characteristics", basetype = "uint16_t"};
	};
};

-- Enums related to various fields within the PE32 headers
PEHeader = {
	enums = {
		-- COFF 'Machine' field
		MachineType = {
			{value = 0x0000, name = "IMAGE_FILE_MACHINE_UNKNOWN", description = "any"},
			{value = 0x01c0, name = "IMAGE_FILE_MACHINE_ARM", description = "ARM little endian"},
			{value = 0x01c4, name = "IMAGE_FILE_MACHINE_ARMN", description = "ARMv7 (or higher) Thumb mode only"},
			{value = 0x01d3, name = "IMAGE_FILE_MACHINE_AM33", description = "Matsushita AM33"},
			{value = 0x014c, name = "IMAGE_FILE_MACHINE_I386", description = "Intel 386 or later processors and compatible processors"},
			{value = 0x0166, name = "IMAGE_FILE_MACHINE_R4000", description = "MIPS little endian"},
			{value = 0x0169, name = "IMAGE_FILE_MACHINE_WCEMIPSV2", description = "MIPS little-endian WCE v2"},
			{value = 0x01a2, name = "IMAGE_FILE_MACHINE_SH3", description = "Hitachi SH3"},
			{value = 0x01a3, name = "IMAGE_FILE_MACHINE_SH3D", description = "Hitachi SH3 DSP"},
			{value = 0x01a6, name = "IMAGE_FILE_MACHINE_SH4", description = "Hitachi SH4"},
			{value = 0x01a8, name = "IMAGE_FILE_MACHINE_SH5", description = "Hitachi SH5"},
			{value = 0x01c2, name = "IMAGE_FILE_MACHINE_THUMB", description = "ARM or Thumb ('interworking')"},
			{value = 0x01f0, name = "IMAGE_FILE_MACHINE_POWERPC", description = "Power PC little endian"},
			{value = 0x01f1, name = "IMAGE_FILE_MACHINE_POWERPCFP", description = "Power PC with floating point support"},
			{value = 0x0200, name = "IMAGE_FILE_MACHINE_IA64", description = "Intel Itanium processor family"},
			{value = 0x0266, name = "IMAGE_FILE_MACHINE_MIPS1", description = "MIPS16"},
			{value = 0x0366, name = "IMAGE_FILE_MACHINE_MIPSF", description = "MIPS with FPU"},
			{value = 0x0466, name = "IMAGE_FILE_MACHINE_MIPSF", description = "MIPS16 with FPU"},
			{value = 0x0ebc, name = "IMAGE_FILE_MACHINE_EBC", description = "EFI byte code"},
			{value = 0x8664, name = "IMAGE_FILE_MACHINE_AMD64", description = "x64"},
			{value = 0x9041, name = "IMAGE_FILE_MACHINE_M32R", description = "Mitsubishi M32R little endian"},
			{value = 0xaa64, name = "IMAGE_FILE_MACHINE_ARM6", description = "ARMv8 in 64-bit mode"},
		},

		-- COFF Characteristics field
		Characteristics = {
			{value = 0x0001, name = "IMAGE_FILE_RELOCS_STRIPPED", description = "Image only, Windows CE, and Windows NT® and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files."},
			{value = 0x0002, name = "IMAGE_FILE_EXECUTABLE_IMAGE", description = "Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error."},
			{value = 0x0004, name = "IMAGE_FILE_LINE_NUMS_STRIPPED", description = "COFF line numbers have been removed. This flag is deprecated and should be zero."},
			{value = 0x0008, name = "IMAGE_FILE_LOCAL_SYMS_STRIPPED", description = "COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero."},
			{value = 0x0010, name = "IMAGE_FILE_AGGRESSIVE_WS_TRIM", description = "Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero."},
			{value = 0x0020, name = "IMAGE_FILE_LARGE_ADDRESS_AWARE", description = "Application can handle > 2‑GB addresses."},
			--{value = 0x0040, name = "IMAGE_FILE_RESERVED", description = "This flag is reserved for future use."},
			{value = 0x0080, name = "IMAGE_FILE_BYTES_REVERSED_LO", description = "Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero."},
			{value = 0x0100, name = "IMAGE_FILE_32BIT_MACHINE", description = "Machine is based on a 32-bit-word architecture."},
			{value = 0x0200, name = "IMAGE_FILE_DEBUG_STRIPPED", description = "Debugging information is removed from the image file."},
			{value = 0x0400, name = "IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP", description = "If the image is on removable media, fully load it and copy it to the swap file."},
			{value = 0x0800, name = "IMAGE_FILE_NET_RUN_FROM_SWAP", description = "If the image is on network media, fully load it and copy it to the swap file."},
			{value = 0x1000, name = "IMAGE_FILE_SYSTEM", description = "The image file is a system file, not a user program."},
			{value = 0x2000, name = "IMAGE_FILE_DLL", description = "The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run."},
			{value = 0x4000, name = "IMAGE_FILE_UP_SYSTEM_ONLY", description = "The file should be run only on a uniprocessor machine."},
			{value = 0x8000, name = "IMAGE_FILE_BYTES_REVERSED_HI", description = "Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero."},
		}

		OptHeaderMagic = {
			{value = 0x10b, name = "IMAGE_MAGIC_HEADER_PE32", description = "PE32"},
			{value = 0x20b, name = "IMAGE_MAGIC_HEADER_PE32_PLUS", description = "PE32+"},
		};

		Subsystem = {
			{value = 0x0000, name = "IMAGE_SUBSYSTEM_UNKNOWN", description = "An unknown subsystem"},
			{value = 0x0001, name = "IMAGE_SUBSYSTEM_NATIVE", description = "Device drivers and native Windows processes"},
			{value = 0x0002, name = "IMAGE_SUBSYSTEM_WINDOWS_GUI", description = "The Windows graphical user interface (GUI) subsystem"},
			{value = 0x0003, name = "IMAGE_SUBSYSTEM_WINDOWS_CUI", description = "The Windows character subsystem"},
			{value = 0x0007, name = "IMAGE_SUBSYSTEM_POSIX_CUI", description = "The Posix character subsystem"},
			{value = 0x0009, name = "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", description = "Windows CE"},
			{value = 0x00010, name = "IMAGE_SUBSYSTEM_EFI_APPLICATION", description = "An Extensible Firmware Interface (EFI) application"},
			{value = 0x00011, name = "IMAGE_SUBSYSTEM_EFI_BOOT_ SERVICE_DRIVER", description = "An EFI driver with boot services"},
			{value = 0x00012, name = "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", description = "An EFI driver with run-time services"},
			{value = 0x00013, name = "IMAGE_SUBSYSTEM_EFI_ROM", description = "An EFI ROM image"},
			{value = 0x00014, name = "IMAGE_SUBSYSTEM_XBOX", description = "XBOX"},

		};

		DllCharacteristics = {
			{value = 0x0001, name = "IMAGE_DLL_RESERVED1", description = "Reserved, must be zero."},
			{value = 0x0002, name = "IMAGE_DLL_RESERVED2", description = "Reserved, must be zero."},
			{value = 0x0004, name = "IMAGE_DLL_RESERVED3", description = "Reserved, must be zero."},
			{value = 0x0008, name = "IMAGE_DLL_RESERVED4", description = "Reserved, must be zero."},
			{value = 0x0040, name = "IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE", description = "DLL can be relocated at load time."},
			{value = 0x0080, name = "IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY", description = "Code Integrity checks are enforced."},
			{value = 0x0100, name = "IMAGE_DLL_CHARACTERISTICS_NX_COMPAT", description = "Image is NX compatible."},
			{value = 0x0200, name = "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", description = "Isolation aware, but do not isolate the image."},
			{value = 0x0400, name = "IMAGE_DLLCHARACTERISTICS_NO_SEH", description = "Does not use structured exception (SE) handling. No SE handler may be called in this image."},
			{value = 0x0800, name = "IMAGE_DLLCHARACTERISTICS_NO_BIND", description = "Do not bind the image."},
			{value = 0x1000, name = "IMAGE_DLL_RESERVED5", description = "Reserved, must be zero."},
			{value = 0x2000, name = "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", description = "A WDM driver."},
			{value = 0x8000, name = "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", description = "Terminal Server aware."},
		};

		-- Section flags of characteristics field of section header
		SectionCharacteristics = {
			{value = 0x00000000, name = "IMAGE_SCN_RESERVED1", description = "Reserved for future use."},
			{value = 0x00000001, name = "IMAGE_SCN_RESERVED2", description = "Reserved for future use."},
			{value = 0x00000002, name = "IMAGE_SCN_RESERVED3", description = "Reserved for future use."},
			{value = 0x00000004, name = "IMAGE_SCN_RESERVED4", description = "Reserved for future use."},
			{value = 0x00000008, name = "IMAGE_SCN_TYPE_NO_PAD", description = "The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files."},
			{value = 0x00000010, name = "IMAGE_SCN_RESERVED4", description = "Reserved for future use."},
			{value = 0x00000020, name = "IMAGE_SCN_CNT_CODE", description = "The section contains executable code."},
			{value = 0x00000040, name = "IMAGE_SCN_CNT_INITIALIZED_DATA", description = "The section contains initialized data."},
			{value = 0x00000080, name = "IMAGE_SCN_CNT_UNINITIALIZED_ DATA", description = "The section contains uninitialized data."},
			{value = 0x00000100, name = "IMAGE_SCN_LNK_OTHER", description = "Reserved for future use."},
			{value = 0x00000200, name = "IMAGE_SCN_LNK_INFO", description = "The section contains comments or other information. The .drectve section has this type. This is valid for object files only."},
			{value = 0x00000400, name = "RESERVED5", description = "Reserved for future use."},
			{value = 0x00000800, name = "IMAGE_SCN_LNK_REMOVE", description = "The section will not become part of the image. This is valid only for object files."},
			{value = 0x00001000, name = "IMAGE_SCN_LNK_COMDAT", description = "The section contains COMDAT data. For more information, see section 5.5.6, 'COMDAT Sections (Object Only).'' This is valid only for object files."},
			{value = 0x00008000, name = "IMAGE_SCN_GPREL", description = "The section contains data referenced through the global pointer (GP)."},
			{value = 0x00020000, name = "IMAGE_SCN_MEM_PURGEABLE", description = "Reserved for future use."},
		};
	}		
};

--[[
local IMAGE_DIRECTORY_ENTRY_EXPORT          = 0   -- Export Directory
local IMAGE_DIRECTORY_ENTRY_IMPORT          = 1   -- Import Directory
local IMAGE_DIRECTORY_ENTRY_RESOURCE        = 2   -- Resource Directory
local IMAGE_DIRECTORY_ENTRY_EXCEPTION       = 3   -- Exception Directory
local IMAGE_DIRECTORY_ENTRY_SECURITY        = 4   -- Security Directory
local IMAGE_DIRECTORY_ENTRY_BASERELOC       = 5   -- Base Relocation Table
local IMAGE_DIRECTORY_ENTRY_DEBUG           = 6   -- Debug Directory
--      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   -- (X86 usage)
local IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    = 7   -- Architecture Specific Data
local IMAGE_DIRECTORY_ENTRY_GLOBALPTR       = 8   -- RVA of GP
local IMAGE_DIRECTORY_ENTRY_TLS             = 9   -- TLS Directory
local IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10   -- Load Configuration Directory
local IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11   -- Bound Import Directory in headers
local IMAGE_DIRECTORY_ENTRY_IAT            = 12   -- Import Address Table
local IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13   -- Delay Load Import Descriptors
local IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14   -- COM Runtime descriptor
--]]

PE32Header_Info = {
	name = "PE32Header",
	fields = {
		-- Fields common to PE32 and PE+
		{name = "Magic", basetype="uint16_t"},	-- , default = 0x10b
		{name = "MajorLinkerVersion", basetype="uint8_t"},
		{name = "MinorLinkerVersion", basetype="uint8_t"},
		{name = "SizeOfCode", basetype="uint32_t"},
		{name = "SizeOfInitializedData", basetype="uint32_t"},
		{name = "SizeOfUninitializedData", basetype="uint32_t"},
		{name = "AddressOfEntryPoint", basetype="uint32_t"},
		{name = "BaseOfCode", basetype="uint32_t"},

		-- PE32 has BaseOfData, which is not in the PE32+ header
		{name = "BaseOfData", basetype="uint32_t"},

		-- The next 21 fields are Windows specific extensions to 
		-- the COFF format
		{name = "ImageBase", basetype="uint32_t"},
		{name = "SectionAlignment", basetype="uint32_t"},
		{name = "FileAlignment", basetype="uint32_t"},
		{name = "MajorOperatingSystemVersion", basetype="uint16_t"},
		{name = "MinorOperatingSystemVersion", basetype="uint16_t"},
		{name = "MajorImageVersion", basetype="uint16_t"},
		{name = "MinorImageVersion", basetype="uint16_t"},
		{name = "MajorSubsystemVersion", basetype="uint16_t"},
		{name = "MinorSubsystemVersion", basetype="uint16_t"},
		{name = "Win32VersionValue", basetype="uint32_t"},
		{name = "SizeOfImage", basetype="uint32_t"},
		{name = "SizeOfHeaders", basetype="uint32_t"},
		{name = "CheckSum", basetype="uint32_t"},
		{name = "Subsystem", basetype="uint16_t"},
		{name = "DllCharacteristics", basetype="uint16_t"},
		{name = "SizeOfStackReserve", basetype="uint32_t"},
		{name = "SizeOfStackCommit", basetype="uint32_t"},
		{name = "SizeOfHeapReserve", basetype="uint32_t"},
		{name = "SizeOfHeapCommit", basetype="uint32_t"},
		{name = "LoaderFlags", basetype="uint32_t"},
		{name = "NumberOfRvaAndSizes", basetype="uint32_t"},

		-- Data directories
		{name = "ExportTable", basetype="uint8_t", repeating=8},			-- .edata  exports
		{name = "ImportTable", basetype="uint8_t", repeating=8},			-- .idata  imports
		{name = "ResourceTable", basetype="uint8_t", repeating=8},			-- .rsrc   resource table
		{name = "ExceptionTable", basetype="uint8_t", repeating=8},			-- .pdata  exceptions table
		{name = "CertificateTable", basetype="uint8_t", repeating=8},		--         attribute certificate table
		{name = "BaseRelocationTable", basetype="uint8_t", repeating=8},	-- .reloc  base relocation table
		{name = "Debug", basetype="uint8_t", repeating=8},					-- .debug  debug data starting address
		{name = "Architecture", basetype="uint8_t", repeating=8},			-- architecture, reserved
		{name = "GlobalPtr", basetype="uint8_t", repeating=8},				-- global pointer
		{name = "TLSTable", basetype="uint8_t", repeating=8},				-- .tls    Thread local storage
		{name = "LoadConfigTable", basetype="uint8_t", repeating=8},		-- load configuration structure
		{name = "BoundImport", basetype="uint8_t", repeating=8},			-- bound import table
		{name = "IAT", basetype="uint8_t", repeating=8},					-- import address table
		{name = "DelayImportDescriptor", basetype="uint8_t", repeating=8},	-- delay import descriptor
		{name = "CLRRuntimeHeader", basetype="uint8_t", repeating=8},		-- .cormeta   CLR runtime header address
		{name = "Reserved", basetype="uint8_t", repeating=8},				-- Reserved, must be zero

	};

};

PE32PlusHeader_Info = {
	name = "PE32PlusHeader";
	fields = {
		-- Fields common with PE32
		{name = "Magic", basetype="uint16_t"},	-- , default = 0x20b
		{name = "MajorLinkerVersion", basetype="uint8_t"},
		{name = "MinorLinkerVersion", basetype="uint8_t"},
		{name = "SizeOfCode", basetype="uint32_t"},
		{name = "SizeOfInitializedData", basetype="uint32_t"},
		{name = "SizeOfUninitializedData", basetype="uint32_t"},
		{name = "AddressOfEntryPoint", basetype="uint32_t"},
		{name = "BaseOfCode", basetype="uint32_t"},

		-- The next 21 fields are Windows specific extensions to 
		-- the COFF format
		{name = "ImageBase", basetype="uint64_t"},						-- size difference
		{name = "SectionAlignment", basetype="uint32_t"},
		{name = "FileAlignment", basetype="uint32_t"},
		{name = "MajorOperatingSystemVersion", basetype="uint16_t"},
		{name = "MinorOperatingSystemVersion", basetype="uint16_t"},
		{name = "MajorImageVersion", basetype="uint16_t"},
		{name = "MinorImageVersion", basetype="uint16_t"},
		{name = "MajorSubsystemVersion", basetype="uint16_t"},
		{name = "MinorSubsystemVersion", basetype="uint16_t"},
		{name = "Win32VersionValue", basetype="uint32_t"},
		{name = "SizeOfImage", basetype="uint32_t"},
		{name = "SizeOfHeaders", basetype="uint32_t"},
		{name = "CheckSum", basetype="uint32_t"},
		{name = "Subsystem", basetype="uint16_t"},
		{name = "DllCharacteristics", basetype="uint16_t"},
		{name = "SizeOfStackReserve", basetype="uint64_t"},				-- size difference
		{name = "SizeOfStackCommit", basetype="uint64_t"},				-- size difference
		{name = "SizeOfHeapReserve", basetype="uint64_t"},				-- size difference
		{name = "SizeOfHeapCommit", basetype="uint64_t"},				-- size difference
		{name = "LoaderFlags", basetype="uint32_t"},
		{name = "NumberOfRvaAndSizes", basetype="uint32_t"},

		{name = "ExportTable", basetype="uint8_t", repeating=8},
		{name = "ImportTable", basetype="uint8_t", repeating=8},
		{name = "ResourceTable", basetype="uint8_t", repeating=8},
		{name = "ExceptionTable", basetype="uint8_t", repeating=8},
		{name = "CertificateTable", basetype="uint8_t", repeating=8},
		{name = "BaseRelocationTable", basetype="uint8_t", repeating=8},
		{name = "Debug", basetype="uint8_t", repeating=8},
		{name = "Architecture", basetype="uint8_t", repeating=8},
		{name = "GlobalPtr", basetype="uint8_t", repeating=8},
		{name = "TLSTable", basetype="uint8_t", repeating=8},
		{name = "LoadConfigTable", basetype="uint8_t", repeating=8},
		{name = "BoundImport", basetype="uint8_t", repeating=8},
		{name = "IAT", basetype="uint8_t", repeating=8},
		{name = "DelayImportDescriptor", basetype="uint8_t", repeating=8},
		{name = "CLRRuntimeHeader", basetype="uint8_t", repeating=8},
		{name = "Reserved", basetype="uint8_t", repeating=8},

	};

};

IMAGE_DATA_DIRECTORY_Info = {
	name = "IMAGE_DATA_DIRECTORY",
	fields = {
		{name = "VirtualAddress", basetype="uint32_t"},
		{name = "Size", basetype="uint32_t"},
	}
};

IMAGE_SECTION_HEADER_Info = {
	name = "IMAGE_SECTION_HEADER",
	fields = {
		{name = "Name", basetype="char", repeating=8},	-- has terminating 0 sometimes, otherwise, 8 bytes
		{name = "VirtualSize", basetype="uint32_t"},
		{name = "VirtualAddress", basetype="uint32_t"},
		{name = "SizeOfRawData", basetype="uint32_t"},
		{name = "PointerToRawData", basetype="uint32_t"},
		{name = "PointerToRelocations", basetype="uint32_t"},
		{name = "PointerToLinenumbers", basetype="uint32_t"},
		{name = "NumberOfRelocations", basetype="uint16_t"},
		{name = "NumberOfLinenumbers", basetype="uint16_t"},
		{name = "Characteristics", basetype="uint32_t"},
	}
};



IMAGE_EXPORT_DIRECTORY_Info = {
	name = "IMAGE_EXPORT_DIRECTORY",
	fields = {
		{name = "Characteristics", basetype = "uint32_t"};
		{name = "TimeDateStamp", basetype = "uint32_t"};
		{name = "MajorVersion", basetype = "uint16_t"};
		{name = "MinorVersion", basetype = "uint16_t"};
		{name = "Name", basetype = "uint32_t"};
		{name = "Base", basetype = "uint32_t"};
		{name = "NumberOfFunctions", basetype = "uint32_t"};
		{name = "NumberOfNames", basetype = "uint32_t"};
		{name = "AddressOfFunctions", basetype = "uint32_t"};
		{name = "AddressOfNames", basetype = "uint32_t"};
		{name = "AddressOfNameOrdinals", basetype = "uint32_t"};
	};
};


IMAGE_IMPORT_DESCRIPTOR_Info = {
	name = "IMAGE_IMPORT_DESCRIPTOR",
	fields = {
		{name = "OriginalFirstThunk", basetype = "uint32_t"};
		{name = "TimeDateStamp", basetype = "int32_t"};
		{name = "ForwarderChain", basetype="int32_t"};
		{name = "Name", basetype="uint32_t"};
		{name = "FirstThunk", basetype = "uint32_t"};
	};
};

IMAGE_IMPORT_BY_NAME_Info = {
    name = "IMAGE_IMPORT_BY_NAME";
	fields = {
		{name = "Hint", basetype="uint16_t"};
		{name = "Name", basetype="char", subtype="string", repeating=1};
	}
};

--[[
IMAGE_THUNK_DATA64_Info =  {
    union {
        ULONGLONG ForwarderString;  // PBYTE
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
};
--]]

IMAGE_THUNK_DATA_Info = {
	name = "IMAGE_THUNK_DATA";
	fields = {
		{name="Data", basetype="uint32_t"}
	};
--[[
    union {
        DWORD ForwarderString;      -- PBYTE
        DWORD Function;             -- PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        -- PIMAGE_IMPORT_BY_NAME
    } u1;
--]]
} ;


IMAGE_BOUND_IMPORT_DESCRIPTOR_Info = {
	name = "IMAGE_BOUND_IMPORT_DESCRIPTOR",
	fields = {
		{name = "TimeDateStamp", basetype = "int32_t"};
		{name = "OffsetModuleName", basetype="int16_t"};
		{name = "NumberOfModuleForwarderRefs", basetype="uint16_t"};
		-- Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
	};
};

IMAGE_BOUND_FORWARDER_REF_Info = {
	name = "IMAGE_BOUND_FORWARDER_REF",
	fields = {
		{name = "TimeDateStamp", basetype = "uint32_t"};
		{name = "OffsetModuleName", basetype="int16_t"};
		{name = "Reserved", basetype="uint16_t"};
	};
};

ImportHeader_Info = {
	name = "ImportHeader",
	fields = {
		{name = "Sig1", basetype="uint16_t"},
		{name = "Sig2", basetype="uint16_t"},
		{name = "Version", basetype="uint16_t"},
		{name = "Machine", basetype="uint16_t"},
		{name = "TimeDateStamp", basetype="uint32_t"},
		{name = "SizeOfData", basetype="uint32_t"},
		{name = "OrdinalHint", basetype="uint16_t"},
		{name = "Type", basetype="uint16_t", subtype="bit", repeating=2},
		{name = "NameType", basetype="uint16_t", subtype="bit", repeating=3},
		{name = "Reserved", basetype="uint16_t", subtype="bit", repeating=11},
	}
};

}

return PETypes
