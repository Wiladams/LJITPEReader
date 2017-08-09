

local ffi = require "ffi"

local pestructs = require("peluaclasses")
local peenums = require("peenums")
peenums();




--assuming machine is little endian
local IMAGE_DOS_SIGNATURE     =            0x5A4D   -- MZ
local IMAGE_OS2_SIGNATURE     =            0x454E   -- NE
local IMAGE_OS2_SIGNATURE_LE  =            0x454C   -- LE
local IMAGE_VXD_SIGNATURE     =            0x454C   -- LE
local IMAGE_NT_SIGNATURE      =            0x4550  	-- PE00

local IMAGE_NUMBEROF_DIRECTORY_ENTRIES    = 16

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



local function IsPEFormatImageFile(header)
local sig = header:get_Signature()
--print(string.char(sig[0]), string.char(sig[1]), sig[2], sig[3])
	return sig[0] == string.byte('P') and
		sig[1] == string.byte('E') and
		sig[2] == 0 and
		sig[3] == 0

end

local function IsPe32Header(header)
	local sig = header:get_Signature()
	return sig[0] == 0x0b and sig[1] == 0x01
end

local function IsPe32PlusHeader(header)
	local sig = header:get_Signature()
	return sig[0] == 0x0b and sig[1] == 0x02
end


local function GetSectionPtr(name, browser)
	local section = browser.Sections[name]

	if not section then return nil end

	return browser.Buffer + section:get_PointerToRawData()
end

local function GetPtrFromRVA(rva, browser)

	local delta;
	local pSectionHdr = GetEnclosingSectionHeader( rva, browser );

	if ( not pSectionHdr ) then
		return nil;
	end

	delta = (pSectionHdr:get_VirtualAddress() - pSectionHdr:get_PointerToRawData());
	return ( browser.Buffer + rva - delta );
end

--
-- Given an RVA, look up the section header that encloses it and return a
-- pointer to its IMAGE_SECTION_HEADER
--
local function GetEnclosingSectionHeader(rva, browser)
    for secname, section in pairs(browser.Sections) do
        -- Is the RVA within this section?
        if (rva >= section:get_VirtualAddress()) and
             (rva < (section:get_VirtualAddress() + section:get_VirtualSize())) then
            return section;
		end
    end

    return nil;
end

local function buildDirectories(peheader)
	local dirs = {}

	local tbl = IMAGE_DATA_DIRECTORY(peheader:get_ExportTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_EXPORT
	dirs.Export = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_ImportTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_IMPORT
	dirs.Import = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_ResourceTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_RESOURCE
	dirs.Resource = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_ExceptionTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_EXCEPTION
	dirs.Exception = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_CertificateTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_SECURITY
	dirs.Security = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_BaseRelocationTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_BASERELOC
	dirs.BaseRelocation = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_Debug())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_DEBUG
	dirs.Debug = tbl


	tbl = IMAGE_DATA_DIRECTORY(peheader:get_Architecture())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
	dirs.Architecture = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_GlobalPtr())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_GLOBALPTR
	dirs.GlobalPtr = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_TLSTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_TLS
	dirs.TLS = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_LoadConfigTable())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
	dirs.Config = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_BoundImport())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
	dirs.BoundImport = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_IAT())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_IAT
	dirs.IAT = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_DelayImportDescriptor())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
	dirs.DelayImport = tbl

	tbl = IMAGE_DATA_DIRECTORY(peheader:get_CLRRuntimeHeader())
	tbl.DIRID = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	dirs.COM = tbl

--	tbl = IMAGE_DATA_DIRECTORY(peheader:get_Reserved())
--	tbl.DIRID = -1
--	table.insert(dirs, tbl)


	return dirs;
end

local function stringFromBuff(buff, size)
	local truelen = size
	for i=size-1,0,-1 do
		if buff[i] == 0 then
		    truelen = truelen - 1
		end
	end
	return ffi.string(buff, truelen)
end

local function buildSectionHeaders(pefile)
	local sections = {}
	local nsections = pefile.FileHeader:get_NumberOfSections()

	local offset = pefile.PEHeader.Offset + pefile.PEHeader.ClassSize
	for i=1,nsections do
		local sec = IMAGE_SECTION_HEADER(pefile.PEHeader.Buffer, pefile.PEHeader.BufferSize, offset)
		local nameptr, len = sec:get_Name()
		local name = stringFromBuff(nameptr, len)
		sec.Name = name
		sections[name] = sec

		offset = offset + sec.ClassSize
	end

	return sections
end

local function copyFileToMemory(filename)
	local f = assert(io.open(filename, "rb"), "unable to open file")
	local str = f:read("*all")
	local slen = #str;
	f:close()

	-- allocate a chunk of memory
	--local arraystr = string.format("uint8_t[%d]", slen)
	local array = ffi.new("uint8_t[?]", slen);
	for offset=0, slen-1 do
		array[offset] = string.byte(str:sub(offset+1,offset+1))
	end


	return array, slen
end

local function CreatePEReader(filename)
	local buff, bufflen = copyFileToMemory(filename)

	local res = {}
	res.Buffer = buff
	res.BufferLength = bufflen


	local offset = 0
	res.DOSHeader = IMAGE_DOS_HEADER(buff, bufflen, offset)
	offset = offset + res.DOSHeader.ClassSize

	local ntheadertype = MAGIC4(buff, bufflen, res.DOSHeader:get_e_lfanew())
	print("Is PE Image File: ", IsPEFormatImageFile(ntheadertype))
	offset = ntheadertype.Offset + ntheadertype.ClassSize

	res.FileHeader = COFF(buff, bufflen, offset)
	offset = offset + res.FileHeader.ClassSize

	-- Read the 2 byte magic for the optional header
	local pemagic = MAGIC2(buff, bufflen, offset)

	local peheader=nil
	if IsPe32Header(pemagic) then
		res.PEHeader = PE32Header(buff, bufflen, offset)
	elseif IsPe32PlusHeader(pemagic) then
		res.PEHeader = PE32PlusHeader(buff, bufflen, offset)
	end

	offset = offset + res.PEHeader.ClassSize
	res.Directories = buildDirectories(res.PEHeader)

	-- Now offset should be positioned at the section table
	res.Sections = buildSectionHeaders(res)

	return res
end

local exports = {
	-- Table constants (enums)
	Characteristics 	= Characteristics,
	DllCharacteristics 	= DllCharacteristics,
	MachineType 		= MachineType,
	OptHeaderMagic 		= OptHeaderMagic,
	Subsystem 			= Subsystem,

	-- functions
	buildDirectories = buildDirectories;
	buildSectionHeaders = buildSectionHeaders;

	CreatePEReader = CreatePEReader;
	
	GetEnclosingSectionHeader = GetEnclosingSectionHeader;
	GetPtrFromRVA = GetPtrFromRVA;
	
	IsPe32Header = IsPe32Header;
	IsPe32PlusHeader = IsPe32PlusHeader;
	IsPEFormatImageFile = IsPEFormatImageFile;
}

setmetatable(exports, {
	__call = function(self, ...)
		for k,v in pairs(exports) do
			_G[k] = v;
		end
	end,
	})

return exports;