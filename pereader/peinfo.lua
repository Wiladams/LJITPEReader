local binstream = require("pereader.binstream")



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

function peinfo.init(self, data, len)

    local obj = {}

    setmetatable(obj, peinfo_mt)
    
    local ms = binstream(data, len, 0, true);

    peinfo.parseData(obj, ms);

    return obj;
end

function peinfo.create(self, data, len)
    return self:init(data, len)
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
        --e_res, basetype="uint16_t", repeating=4},          -- Reserved s
        e_oemid = ms:readUInt16();                     -- OEM identifier (for e_oeminfo)
        e_oeminfo = ms:readUInt16();                   -- OEM information; e_oemid specific
        ms:skip(10*2);
        --e_res2, basetype="uint16_t", repeating=10},        -- Reserved s
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

local function readDirectory(ms, id)
    local res = {
        ID = id;
        VirtualAddress = ms:readUInt32();
        Size = ms:readUInt32();
    }
end

function peinfo.readPE32Header(self, ms)
    local res = {
		-- Fields common to PE32 and PE+
		Magic = ms:readUInt16();	-- , default = 0x10b
		MajorLinkerVersion = ms:readUInt8();
		MinorLinkerVersion = ms:readUInt8();
		SizeOfCode = ms:readUInt32();
		SizeOfInitializedData = ms:readUInt32();
		SizeOfUninitializedData = ms:readUInt32();
		AddressOfEntryPoint = ms:readUInt32();
		BaseOfCode = ms:readUInt32();

		-- PE32 has BaseOfData, which is not in the PE32+ header
		BaseOfData = ms:readUInt32();

		-- The next 21 fields are Windows specific extensions to 
		-- the COFF format
		ImageBase = ms:readUInt32();
		SectionAlignment = ms:readUInt32();
		FileAlignment = ms:readUInt32();
		MajorOperatingSystemVersion = ms:readUInt16();
		MinorOperatingSystemVersion = ms:readUInt16();
		MajorImageVersion = ms:readUInt16();
		MinorImageVersion = ms:readUInt16();
		MajorSubsystemVersion = ms:readUInt16();
		MinorSubsystemVersion = ms:readUInt16();
		Win32VersionValue = ms:readUInt32();             -- reserved
		SizeOfImage = ms:readUInt32();
		SizeOfHeaders = ms:readUInt32();
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
		    CertificateTable = readDirectory(ms, IMAGE_DIRECTORY_ENTRY_SECURITY);		--         attribute certificate table
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

    print("readPE32Header, OSVersion: ", res.MajorOperatingSystemVersion, res.MinorOperatingSystemVersion)
    return res;
end

function peinfo.readPE32PlusHeader(self, ms)
    local res = {

    }
    return res;
end

function peinfo.parseData(self, ms)
    self.DOSHeader = self:readDOSHeader(ms);

 
    -- get nt header type, seek to where the header
    -- is supposed to start
    ms:seek(self.DOSHeader.e_lfanew)
    local sentinel = ms:tell();
    
    local ntheadertype = ms:readBytes(4);
    print("Is PE Image File: ", IsPEFormatImageFile(ntheadertype))

    self.PEHeader = {
        signature = ntheadertype;
    }
    self.fileHeader = self:readCOFF(ms);

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
        self.PEHeader = self:readPE32Header(ms);
    elseif IsPe32PlusHeader(pemagic) then
        self.PEHeader = self:readPE32PlusHeader(ms);
    end

--[[
res.Directories = buildDirectories(res.PEHeader)

-- Now offset should be positioned at the section table
res.Sections = buildSectionHeaders(res)
--]]
    return self
end


return peinfo