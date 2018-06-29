--[[
    Reference Material:
    https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
]]
local ffi = require("ffi")

local binstream = require("pereader.binstream")
local enums = require("pereader.peenums")


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



local peinfo = {}
setmetatable(peinfo, {
    __call = function(self, ...)
        return self:create(...)
    end;
})
local peinfo_mt = {
    __index = peinfo;
}

function peinfo.init(self, data, size)

    local obj = {
        _data = data;
        _size = size;
    }

    setmetatable(obj, peinfo_mt)
    
    local ms = binstream(data, size, 0, true);

    peinfo.parseData(obj, ms);

    return obj;
end

function peinfo.create(self, data, size)
    return self:init(data, size)
end

--[[
    Do the work of actually parsing the interesting
    data in the file.
]]
--[[
    PE\0\0 - PE header
    NE\0\0 - 16-bit Windows New Executable
    LE\0\0 - Windows 3.x virtual device driver (VxD)
    LX\0\0 - OS/2 2.0
]]
local function IsPEFormatImageFile(sig)
    return sig[0] == string.byte('P') and
        sig[1] == string.byte('E') and
        sig[2] == 0 and
        sig[3] == 0
end

local function IsPe32Header(sig)
return sig[0] == 0x0b and sig[1] == 0x01
end

local function IsPe32PlusHeader(sig)
return sig[0] == 0x0b and sig[1] == 0x02
end

--
-- Given an RVA, look up the section header that encloses it and return a
-- pointer to its IMAGE_SECTION_HEADER
--
function peinfo.GetEnclosingSectionHeader(self, rva)
    --print("==== EnclosingSection: ", rva)
    for secname, section in pairs(self.Sections) do
        -- Is the RVA within this section?
        --print(secname, section.VirtualAddress, section.VirtualAddress+section.VirtualSize)
        local pos = rva - section.VirtualAddress;
        if pos > 0 and pos < section.VirtualSize then
            -- return section, and the calculated fileoffset of the rva
            return section, pos 
        end
    end

    return false;
end

function peinfo.fileOffsetFromRVA(self, rva)
print("==== fileOffsetFromRVA: ", rva)
	local section, offset = self:GetEnclosingSectionHeader( rva);
print(section.name)
    return offset or false
end


--[[]
    Now for the actual parsing of the data stream
]]
function peinfo.readDOSHeader(self, ms)
    local res = {
        e_magic = ms:readBytes(2);                     -- Magic number
        e_cblp = ms:readUInt16();                      -- Bytes on last page of file
        e_cp = ms:readUInt16();                        -- Pages in file
        e_crlc = ms:readUInt16();                      -- Relocations
        e_cparhdr = ms:readUInt16();                   -- Size of header in paragraphs
        e_minalloc = ms:readUInt16();                  -- Minimum extra paragraphs needed
        e_maxalloc = ms:readUInt16();                  -- Maximum extra paragraphs needed
        e_ss = ms:readUInt16();                        -- Initial (relative) SS value
        e_sp = ms:readUInt16();                        -- Initial SP value
        e_csum = ms:readUInt16();                      -- Checksum
        e_ip = ms:readUInt16();                        -- Initial IP value
        e_cs = ms:readUInt16();                        -- Initial (relative) CS value
        e_lfarlc = ms:readUInt16();                    -- File address of relocation table
        e_ovno = ms:readUInt16();                      -- Overlay number
        ms:skip(4*2);
        --e_res, basetype="uint16_t", repeating=4},    -- Reserved s
        e_oemid = ms:readUInt16();                     -- OEM identifier (for e_oeminfo)
        e_oeminfo = ms:readUInt16();                   -- OEM information; e_oemid specific
        ms:skip(10*2);
        --e_res2, basetype="uint16_t", repeating=10},  -- Reserved s
        e_lfanew = ms:readUInt32();                    -- File address of new exe header
    }

    return res;
end



function peinfo.readCOFF(self, ms)
    local res = {
        Machine = ms:readUInt16();
        NumberOfSections = ms:readUInt16();
        TimeDateStamp = ms:readUInt32();
        PointerToSymbolTable = ms:readUInt32();
        NumberOfSymbols = ms:readUInt32();
        SizeOfOptionalHeader = ms:readUInt16();
        Characteristics = ms:readUInt16();
    }

    --print("readCOFF, SizeOfOptionalHeader: ", res.SizeOfOptionalHeader)

    return res;
end

--[[
    In the context of a PEHeader, a directory is a simple
    structure containing a virtual address, and a size
]]
local function readDirectory(ms, id)
    local res = {
        ID = id;
        VirtualAddress = ms:readUInt32();   -- RVA
        Size = ms:readUInt32();
    }

    return res;
end



function peinfo.readPE32Header(self, ms)
    self.PEHeader = {
		-- Fields common to PE32 and PE+
		Magic = ms:readUInt16();	-- , default = 0x10b
		MajorLinkerVersion = ms:readUInt8();
		MinorLinkerVersion = ms:readUInt8();
		SizeOfCode = ms:readUInt32();
		SizeOfInitializedData = ms:readUInt32();
		SizeOfUninitializedData = ms:readUInt32();
		AddressOfEntryPoint = ms:readUInt32();      -- RVA
		BaseOfCode = ms:readUInt32();               -- RVA

		-- PE32 has BaseOfData, which is not in the PE32+ header
		BaseOfData = ms:readUInt32();               -- RVA

		-- The next 21 fields are Windows specific extensions to 
		-- the COFF format
		ImageBase = ms:readUInt32();
		SectionAlignment = ms:readUInt32();             -- How are sections alinged in RAM
		FileAlignment = ms:readUInt32();                -- alignment of sections in file
		MajorOperatingSystemVersion = ms:readUInt16();
		MinorOperatingSystemVersion = ms:readUInt16();
		MajorImageVersion = ms:readUInt16();
		MinorImageVersion = ms:readUInt16();
		MajorSubsystemVersion = ms:readUInt16();
		MinorSubsystemVersion = ms:readUInt16();
		Win32VersionValue = ms:readUInt32();             -- reserved
		SizeOfImage = ms:readUInt32();
		SizeOfHeaders = ms:readUInt32();                    -- Essentially, offset to first sections
		CheckSum = ms:readUInt32();
		Subsystem = ms:readUInt16();
		DllCharacteristics = ms:readUInt16();
		SizeOfStackReserve = ms:readUInt32();
		SizeOfStackCommit = ms:readUInt32();
		SizeOfHeapReserve = ms:readUInt32();
		SizeOfHeapCommit = ms:readUInt32();
		LoaderFlags = ms:readUInt32();
		NumberOfRvaAndSizes = ms:readUInt32();



        -- Data directories
        Directories = {
		    ExportTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_EXPORT);			-- .edata  exports
		    ImportTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_IMPORT);			-- .idata  imports
		    ResourceTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_RESOURCE);			-- .rsrc   resource table
		    ExceptionTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_EXCEPTION);			-- .pdata  exceptions table
		    CertificateTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_SECURITY);		--         attribute certificate table, fileoffset, NOT RVA
            BaseRelocationTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_BASERELOC);	-- .reloc  base relocation table
        
		    Debug = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_DEBUG);					-- .debug  debug data starting address
		    Architecture = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);			-- architecture, reserved
		    GlobalPtr = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_GLOBALPTR);				-- global pointer
		    TLSTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_TLS);				-- .tls    Thread local storage
		    LoadConfigTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);		-- load configuration structure
		    BoundImport = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);			-- bound import table
		    IAT = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_IAT);					-- import address table
		    DelayImportDescriptor = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);	-- delay import descriptor
		    CLRRuntimeHeader = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);		-- .cormeta   CLR runtime header address
		    Reserved = readDirectory(ms);				-- Reserved, must be zero
        }

    }
    

    return self;
end

function peinfo.readPE32PlusHeader(self, ms)
    self.PEHeader = {
		-- Fields common with PE32
		Magic = ms:readUInt16();	-- , default = 0x20b
		MajorLinkerVersion = ms:readUInt8();
		MinorLinkerVersion = ms:readUInt8();
		SizeOfCode = ms:readUInt32();
		SizeOfInitializedData = ms:readUInt32();
		SizeOfUninitializedData = ms:readUInt32();
		AddressOfEntryPoint = ms:readUInt32();
		BaseOfCode = ms:readUInt32();

		-- The next 21 fields are Windows specific extensions to 
		-- the COFF format
		ImageBase = ms:readUInt64();						-- size difference
		SectionAlignment = ms:readUInt32();
		FileAlignment = ms:readUInt32();
		MajorOperatingSystemVersion = ms:readUInt16();
		MinorOperatingSystemVersion = ms:readUInt16();
		MajorImageVersion = ms:readUInt16();
		MinorImageVersion = ms:readUInt16();
		MajorSubsystemVersion = ms:readUInt16();
		MinorSubsystemVersion = ms:readUInt16();
		Win32VersionValue = ms:readUInt32();
		SizeOfImage = ms:readUInt32();
		SizeOfHeaders = ms:readUInt32();
		CheckSum = ms:readUInt32();
		Subsystem = ms:readUInt16();
		DllCharacteristics = ms:readUInt16();
		SizeOfStackReserve = ms:readUInt64();				-- size difference
		SizeOfStackCommit = ms:readUInt64();				-- size difference
		SizeOfHeapReserve = ms:readUInt64();				-- size difference
		SizeOfHeapCommit = ms:readUInt64();				-- size difference
		LoaderFlags = ms:readUInt32();
		NumberOfRvaAndSizes = ms:readUInt32();

        -- Data directories
        Directories = {
            ExportTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_EXPORT);			-- .edata  exports
            ImportTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_IMPORT);			-- .idata  imports
            ResourceTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_RESOURCE);			-- .rsrc   resource table
            ExceptionTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_EXCEPTION);			-- .pdata  exceptions table
            CertificateTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_SECURITY);		--         attribute certificate table, fileoffset, NOT RVA
            BaseRelocationTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_BASERELOC);	-- .reloc  base relocation table
                
            Debug = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_DEBUG);					-- .debug  debug data starting address
            Architecture = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);			-- architecture, reserved
            GlobalPtr = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_GLOBALPTR);				-- global pointer
            TLSTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_TLS);				-- .tls    Thread local storage
            LoadConfigTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);		-- load configuration structure
            BoundImport = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);			-- bound import table
            IAT = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_IAT);					-- import address table
            DelayImportDescriptor = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);	-- delay import descriptor
            CLRRuntimeHeader = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);		-- .cormeta   CLR runtime header address
            Reserved = readDirectory(ms);				-- Reserved, must be zero
        };

    }
    
    return self;
end


function peinfo.readDirectory_Export(self)
    print("==== readDirectory_Export ====")
    local dirTable = self.PEHeader.Directories.ExportTable
    if not dirTable then 
        print("NO EXPORT TABLE")
        return false 
    end

    -- If the virtual address is zero, then we don't actually
    -- have any exports
    if dirTable.VirtualAddress == 0 then
        return false;
    end

    -- We use the directory entry to lookup the actual export table.
    -- We need to turn the VirtualAddress into an actual file offset
    print(string.format("  dirTable.VirtualAddress: 0x%x", dirTable.VirtualAddress))
    local fileOffset = tonumber(self:fileOffsetFromRVA(dirTable.VirtualAddress))
    print(string.format("  fileOffset: 0x%x", fileOffset))

    -- We now know where the actual export table exists, so 
    -- create a binary stream, and position it at the offset
    print("   binstream: ", self._data, self._size)
    local ms = binstream(self._data, tonumber(self._size))
    ms:seek(fileOffset);

    -- We are now in position to read the actual export table data
    -- The data consists of various bits and pieces of information, including
    -- pointers to the actual export information.
    local res = {
        Characteristics = ms:readUInt32();
        TimeDateStamp = ms:readUInt32();
        MajorVersion = ms:readUInt16();
        MinorVersion = ms:readUInt16();
        nName = ms:readUInt32();                -- Relative to image base
        nBase = ms:readUInt32();
        NumberOfFunctions = ms:readUInt32();
        NumberOfNames = ms:readUInt32();
        AddressOfFunctions = ms:readUInt32();
        AddressOfNames = ms:readUInt32();
        AddressOfNameOrdinals = ms:readUInt32();
    }

    print("        Export Flags: ", res.Characteristics)
    print("        Ordinal Base: ", res.nBase)
    print("   NumberOfFunctions: ", res.NumberOfFunctions);
    print("       NumberOfNames: ", res.NumberOfNames);
    print("  AddressOfFunctions: ", res.AddressOfFunctions);
    print("      AddressOfNames: ", res.AddressOfNames);
    return res;
end

function peinfo.readDirectory_Import(self)
    print("==== readDirectory_Import ====")
    local dirTable = self.PEHeader.Directories.ImportTable
    if not dirTable then return false end

    -- turn the RVA Virtual address into a file address
print("  dirTable.VirtualAddress: ", dirTable.VirtualAddress)
    local fileOffset = self:fileOffsetFromRVA(dirTable.VirtualAddress)
print("               fileOffset: ", fileOffset)
    -- Setup a binstream and start reading
    local ms = binstream(self._data, self._size)
    ms:seek(fileOffset);

    local res = {
        OriginalFirstThunk  = ms:readUInt32();   -- RVA to IMAGE_THUNK_DATA array
        TimeDateStamp       = ms:readUInt32();
        ForwarderChain      = ms:readUInt32();
        Name1               = ms:readUInt32();   -- RVA, Name of the .dll or .exe
        FirstThunk          = ms:readUInt32();
    }

    -- turn the name into an actual name
    print("                res.Name1: ", res.Name1)
    local Name1Offset = self:fileOffsetFromRVA(res.Name1)
    if Name1Offset then
    ms:seek(Name1Offset);
    res.DllName = ms:readString();
    print("DllName: ", res.DllName)
    end 

    return res;
end


function peinfo.readDirectories(self)
    self.Directories = self.Directories or {}
    
    self.Directories.Export = self:readDirectory_Export();
    self.Directories.Import = self:readDirectory_Import();

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

function peinfo.readSectionHeaders(self, ms)
	local nsections = self.FileHeader.NumberOfSections;
	self.Sections = {}

    for i=1,nsections do
        local sec = {
            Name = ms:readBytes(8);
            VirtualSize = ms:readNumber(4);
            VirtualAddress = ms:readNumber(4);
            SizeOfRawData = ms:readNumber(4);
            PointerToRawData = ms:readNumber(4);
            PointerToRelocations = ms:readNumber(4);
            PointerToLinenumbers = ms:readNumber(4);
            NumberOfRelocations = ms:readNumber(2);
            NumberOfLinenumbers = ms:readNumber(2);
            Characteristics = ms:readUInt32();
        }

		--local sec = IMAGE_SECTION_HEADER(pefile.PEHeader.Buffer, pefile.PEHeader.BufferSize, offset)
		--local nameptr, len = sec:get_Name()
		sec.Name = stringFromBuff(sec.Name, 8)

		self.Sections[sec.Name] = sec
	end

	return sections
end

function peinfo.parseData(self, ms)
    self.DOSHeader = self:readDOSHeader(ms);

 
    -- get nt header type, 
    -- seek to where the header
    -- is supposed to start
    ms:seek(self.DOSHeader.e_lfanew)
    local sentinel = ms:tell();
    
    local ntheadertype = ms:readBytes(4);
    print("Is PE Image File: ", IsPEFormatImageFile(ntheadertype))

    self.PEHeader = {
        signature = ntheadertype;
    }
    self.FileHeader = self:readCOFF(ms);

    -- Read the 2 byte magic for the optional header
    local pemagic = ms:readBytes(2);
    print(string.format("PEMAGIC: 0x%x 0x%x", pemagic[0], pemagic[1]))

    -- unwind reading the magic so we can read it again
    -- as part of reading the whole 'optional' header
    ms:seek(ms:tell()-2);

    -- we know from the file header what size the
    -- optional header is supposed to be, so we can 
    -- create a sub-stream for reading that section alone
    if IsPe32Header(pemagic) then
        self:readPE32Header(ms);
    elseif IsPe32PlusHeader(pemagic) then
        self:readPE32PlusHeader(ms);
    end

    -- Now offset should be positioned at the section table
    self:readSectionHeaders(ms)

    -- Now that we have section information, we should
    -- be able to read detailed directory information
    self:readDirectories()

    return self
end


return peinfo