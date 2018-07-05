--[[
    PE file format reader.
    This reader will essentially 'decompress' all the information
    in the PE file, and make all relevant content available
    through a standard Lua table.

    Typical usage on a Windows platform would be:

    local mfile = mmap(filename);
	local data = ffi.cast("uint8_t *", mfile:getPointer());

	local peinfo = peinfo(data, mfile.size);

    Once the peinfo object has been constructed, it will already 
    contain the contents in an easily navigable form.
]]
local ffi = require("ffi")
local bit = require("bit")
local band = bit.band;

local binstream = require("pereader.binstream")
local enums = require("pereader.peenums")


local peinfo = {}
setmetatable(peinfo, {
    __call = function(self, ...)
        return self:create(...)
    end;
})
local peinfo_mt = {
    __index = peinfo;
}

function peinfo.init(self, obj)
    obj = obj or {}

    setmetatable(obj, peinfo_mt)

    return obj;
end

function peinfo.create(self, obj)
    return self:init(obj)
end

function peinfo.fromData(self, data, size)
    local ms = binstream(data, size, 0, true);
    local obj = self:create()

    return obj:parse(ms)
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
        if pos >= 0 and pos < section.VirtualSize then
            -- return section, and the calculated fileoffset of the rva
            return section, pos 
        end
    end

    return false;
end

-- There are many values within the file which are 'RVA' (Relative Virtual Address)
-- In order to translate this RVA into a file offset, we use the following
-- function.
function peinfo.fileOffsetFromRVA(self, rva)
--print("==== fileOffsetFromRVA: ", rva)
    local section = self:GetEnclosingSectionHeader( rva);
    if not section then return false; end

    local fileOffset = rva - section.VirtualAddress + section.PointerToRawData;

    return fileOffset
end


--[[]
    Now for the actual parsing of the data stream
]]


function peinfo.readDOSHeader(self)
    local ms = self.SourceStream;
    local e_magic = ms:readBytes(2);    -- Magic number, must be 'MZ'
    
    local function isValidDOS(bytes)
        return bytes[0] == string.byte('M') and
            bytes[1] == string.byte('Z')
    end
    
    if not isValidDOS(e_magic) then
        return false, "'MZ' signature not found", e_magic
    end

    local res = {
        e_magic = e_magic;                      -- Magic number
        e_cblp = ms:readUInt16();               -- Bytes on last page of file
        e_cp = ms:readUInt16();                 -- Pages in file
        e_crlc = ms:readUInt16();               -- Relocations
        e_cparhdr = ms:readUInt16();            -- Size of header in paragraphs
        e_minalloc = ms:readUInt16();           -- Minimum extra paragraphs needed
        e_maxalloc = ms:readUInt16();           -- Maximum extra paragraphs needed
        e_ss = ms:readUInt16();                 -- Initial (relative) SS value
        e_sp = ms:readUInt16();                 -- Initial SP value
        e_csum = ms:readUInt16();               -- Checksum
        e_ip = ms:readUInt16();                 -- Initial IP value
        e_cs = ms:readUInt16();                 -- Initial (relative) CS value
        e_lfarlc = ms:readUInt16();             -- File address of relocation table
        e_ovno = ms:readUInt16();               -- Overlay number
        ms:skip(4*2);                           -- e_res, basetype="uint16_t", repeating=4},    -- Reserved s
        e_oemid = ms:readUInt16();              -- OEM identifier (for e_oeminfo)
        e_oeminfo = ms:readUInt16();            -- OEM information; e_oemid specific
        ms:skip(10*2);                          -- e_res2, basetype="uint16_t", repeating=10},  -- Reserved s
        e_lfanew = ms:readUInt32();             -- File address of new exe header
    }

    return res;
end



function peinfo.readCOFF(self)
    local ms = self.SourceStream;

    local res = {
        Machine = ms:readUInt16();
        NumberOfSections = ms:readUInt16();     -- Windows loader limits to 96
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

-- List of directories in the order
-- they show up in the file
local dirNames = {
    "ExportTable",
    "ImportTable",
    "ResourceTable",
    "ExceptionTable",
    "CertificateTable",
    "BaseRelocationTable",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLSTable",
    "LoadConfigTable",
    "BoundImport",
    "IAT",
    "DelayImportDescriptor",
    "CLRRuntimeHeader",
    "Reserved"
}

function peinfo.readDirectoryTable(self)
    local ms = self.SourceStream;
    
    -- Read directory index entries
    self.PEHeader.Directories = {}
    for i, name in ipairs(dirNames) do
        local dir = readDirectory(ms, i-1);
        if dir.Size ~= 0 then
            self.PEHeader.Directories[name] = dir;
        end
    end
end

function peinfo.readPE32Header(self, ms)
    print("==== readPE32Header ====")
    local startOff = ms:tell();

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
    }

    -- Read directory index entries
    -- Only save the ones that actually
    -- have data in them
    self:readDirectoryTable();
--[[
        self.PEHeader.Directories = {}
    --print("  READ DIRECTORIES ")
    for i, name in ipairs(dirNames) do
        --print("dir offset: ", name, ms:tell()-startOff)
        local dir = readDirectory(ms,i-1);
        if dir.Size ~= 0 then
            self.PEHeader.Directories[name] = dir;
        end
    end
--]]

    return self;
end

function peinfo.readPE32PlusHeader(self, ms)
    self.isPE32Plus = true;

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
    }

    self:readDirectoryTable();

    return self;
end


function peinfo.readDirectory_Export(self)
    print("==== readDirectory_Export ====")
    local dirTable = self.PEHeader.Directories.ExportTable
    if not dirTable then 
        print("NO EXPORT TABLE")
        return false 
    end

    self.Exports = {}

    -- If the virtual address is zero, then we don't actually
    -- have any exports
    if dirTable.VirtualAddress == 0 then
        print("  No Virtual Address")
        return false;
    end

    -- We use the directory entry to lookup the actual export table.
    -- We need to turn the VirtualAddress into an actual file offset
    --print(string.format("  dirTable.VirtualAddress: 0x%x", dirTable.VirtualAddress))
    local fileOffset = self:fileOffsetFromRVA(dirTable.VirtualAddress)
    --print(string.format("  fileOffset: 0x%x", fileOffset))

    -- We now know where the actual export table exists, so 
    -- create a binary stream, and position it at the offset
    --print("   binstream: ", self._data, self._size)
    local ms = binstream(self._data, self._size, fileOffset, true)


    -- We are now in position to read the actual export table data
    -- The data consists of various bits and pieces of information, including
    -- pointers to the actual export information.
    local res = dirTable;
        dirTable.Characteristics = ms:readUInt32();
        dirTable.TimeDateStamp = ms:readUInt32();
        dirTable.MajorVersion = ms:readUInt16();
        dirTable.MinorVersion = ms:readUInt16();
        dirTable.nName = ms:readUInt32();                -- Relative to image base
        dirTable.nBase = ms:readUInt32();
        dirTable.NumberOfFunctions = ms:readUInt32();
        dirTable.NumberOfNames = ms:readUInt32();
        dirTable.AddressOfFunctions = ms:readUInt32();
        dirTable.AddressOfNames = ms:readUInt32();
        dirTable.AddressOfNameOrdinals = ms:readUInt32();


    -- Get the internal name of the module
    local nNameOffset = self:fileOffsetFromRVA(res.nName)
    if nNameOffset then
        -- use a separate stream to read the string so we don't
        -- upset the positioning on the one that's reading
        -- the import descriptors
        local ns = binstream(self._data, self._size, nNameOffset, true)
        self.ModuleName = ns:readString();
        --print("Module Name: ", res.ModuleName)
    end 

--[[
    print("        Export Flags: ", res.Characteristics)
    print("               nName: ", string.format("0x%X",res.nName))
    print("         Module Name: ", self.ModuleName)
    print("        Ordinal Base: ", res.nBase)
    print("   NumberOfFunctions: ", res.NumberOfFunctions);
    print("       NumberOfNames: ", res.NumberOfNames);
    print("  AddressOfFunctions: ", res.AddressOfFunctions);
    print("      AddressOfNames: ", res.AddressOfNames);
    print("AddressOfNameOrdinals: ", string.format("0x%X", res.AddressOfNameOrdinals));
--]]

    -- Get the function pointers
    local EATable = {}; -- ffi.new("uint32_t[?]", res.NumberOfFunctions)
    if res.NumberOfFunctions > 0 then
        local EATOffset = self:fileOffsetFromRVA(res.AddressOfFunctions);
        local EATStream = binstream(self._data, self._size, EATOffset, true);

        for i=1, res.NumberOfFunctions do 
            local AddressRVA = EATStream:readUInt32()
            local section = self:GetEnclosingSectionHeader(AddressRVA)
            --print("Export Function: ", string.format("0x%08X", AddressRVA), section, section.Name)
            local ExportOffset = self:fileOffsetFromRVA(AddressRVA)

            -- If it's an internal function then store the RVA
            -- functions are not always going to be in the .text
            -- section, but mostly are.
            -- Need to come up with a reliable way to determine when
            -- an RVA is pointing to a forward reference
            if section and section.Name == '.text' then
                --table.insert(EATable, ExportOffset);
                table.insert(EATable, AddressRVA);
            else
                local ForwardStream = binstream(self._data, self._size, ExportOffset, true)
                local forwardName = ForwardStream:readString();
                table.insert(EATable, forwardName)
            end
        end
    end

    -- Get the names if the Names array exists
    if res.NumberOfNames > 0 then
        local NamesArrayOffset = self:fileOffsetFromRVA(res.AddressOfNames)
        local NamesArrayStream = binstream(self._data, self._size, NamesArrayOffset, true);
        --NamesArrayStream:seek(NamesArrayOffset);

        -- Setup a stream for the AddressOfNameOrdinals (EOT) table
        local EOTOffset = self:fileOffsetFromRVA(res.AddressOfNameOrdinals);
        local EOTStream = binstream(self._data, self._size, EOTOffset, true);
        --EOTStream:seek(EOTOffset);


        for i=1, res.NumberOfNames do
            -- create a stream pointing at the specific name
            local nameRVA = NamesArrayStream:readUInt32();
            local nameOffset = self:fileOffsetFromRVA(nameRVA)
            local nameStream = binstream(self._data, self._size, nameOffset, true);
--nameStream:seek(nameOffset);

            local name = nameStream:readString();
            local hint = EOTStream:readUInt16();
            local ordinal = hint + dirTable.nBase;
            local funcptr = EATable[ordinal];

            --print("  name: ", ordinal, name)
            table.insert(self.Exports, {name = name, hint=hint, ordinal = ordinal , funcptr=funcptr})
            --self.Exports[name] = true;    -- put extended info in here, like ordinal, and func ptr
        end
    end


    return self.Exports;
end

local IMAGE_ORDINAL_FLAG32 = 0x80000000

function peinfo.readDirectory_Import(self)
    --print("==== readDirectory_Import ====")
    self.Imports = {}
    local dirTable = self.PEHeader.Directories.ImportTable
    if not dirTable then return false end

    -- Get section import directory is in
    local importsStartRVA = dirTable.VirtualAddress
	local importsSize = dirTable.Size
	local importdescripptr = self:fileOffsetFromRVA(dirTable.VirtualAddress)

	if not importdescripptr then
		print("No section found for import directory")
		return
    end
    

	--print("file offset: ", string.format("0x%x",importdescripptr));

     -- Setup a binstream and start reading
    local ImageImportDescriptorStream = binstream(self._data, self._size, 0, true)
    ImageImportDescriptorStream:seek(importdescripptr);
	while true do
        local res = {
            OriginalFirstThunk  = ImageImportDescriptorStream:readUInt32();   -- RVA to IMAGE_THUNK_DATA array
            TimeDateStamp       = ImageImportDescriptorStream:readUInt32();
            ForwarderChain      = ImageImportDescriptorStream:readUInt32();
            Name1               = ImageImportDescriptorStream:readUInt32();   -- RVA, Name of the .dll or .exe
            FirstThunk          = ImageImportDescriptorStream:readUInt32();
        }

        if (res.Name1 == 0 and res.OriginalFirstThunk == 0 and res.FirstThunk == 0) then 
            break;
        end

--[[
        print("== IMPORT ==")
        print(string.format("OriginalFirstThunk: 0x%08x (0x%08x)", res.OriginalFirstThunk, self:fileOffsetFromRVA(res.OriginalFirstThunk)))
        print(string.format("     TimeDateStamp: 0x%08x", res.TimeDateStamp))
        print(string.format("    ForwarderChain: 0x%08x", res.ForwarderChain))
        print(string.format("             Name1: 0x%08x (0x%08x)", res.Name1, self:fileOffsetFromRVA(res.Name1)))
        print(string.format("        FirstThunk: 0x%08x", res.FirstThunk))
--]]
        -- The .Name1 field contains an RVA which points to
        -- the actual string name of the .dll
        -- So, get the file offset, and read the string
        local Name1Offset = self:fileOffsetFromRVA(res.Name1)
        if Name1Offset then
            -- use a separate stream to read the string so we don't
            -- upset the positioning on the one that's reading
            -- the import descriptors
            local ns = binstream(self._data, self._size, 0, true)
            ns:seek(Name1Offset)
            res.DllName = ns:readString();
            --print("DllName: ", res.DllName)
            self.Imports[res.DllName] = {};
        end 

        -- Iterate over the invividual import entries
        -- The thunk points to an array of IMAGE_THUNK_DATA structures
        -- which is comprised of a single uint32_t
		local thunkRVA = res.OriginalFirstThunk
		local thunkIATRVA = res.FirstThunk
        if thunkRVA == 0 then
            thunkRVA = thunkIATRVA
        end


		if (thunkRVA ~= 0) then
            local ThunkArrayOffset = self:fileOffsetFromRVA(thunkRVA);
--print(string.format("ThunkRVA: 0x%08X (0x%08X)", thunkRVA, ThunkArrayOffset))

            -- this will point to an array of IMAGE_THUNK_DATA objects
            -- so create a separate stream to read them
            local ThunkArrayStream = binstream(self._data, self._size, 0, true)
            ThunkArrayStream:seek(ThunkArrayOffset)

            --local thunkIATOffset = self:fileOffsetFromRVA(thunkIATRVA);
            --ms:seek(thunkIATOffset)
            --local thunkIATData = ms:readUInt32();

            -- Read individual Import names or ordinals
            while (true) do
                -- the thunkPtr is an RVA pointing to the beginning
                -- of an array of 
                local ThunkDataRVA = false;
                local pos = ThunkArrayStream:tell();
                if self.isPE32Plus then
                        --print("PE32Plus")
                        ThunkDataRVA = ThunkArrayStream:readUInt64();
                else
                        ThunkDataRVA = ThunkArrayStream:readUInt32();
                end
                --print("ThunkDataRVA: ", string.format("x%08X", pos), ThunkDataRVA)
                --print(string.format("ThunkDataRVA: 0x%08X (0x%08X)", ThunkDataRVA, self:fileOffsetFromRVA(ThunkDataRVA)))
                if ThunkDataRVA == 0 then
                    break;
                end

                local ThunkDataOffset = self:fileOffsetFromRVA(ThunkDataRVA)

                --if band(ThunkDataRVA, IMAGE_ORDINAL_FLAG32) > 0 then
                -- Check for Ordinal only import
                -- must be mindful of 32/64-bit
                if (false) then
                        print("** IMPORT ORDINAL!! **")
                else
                    -- Read the entries in the nametable
                    local HintNameStream = binstream(self._data, self._size, 0, true);
                    HintNameStream:seek(ThunkDataOffset)

                    local hint = HintNameStream:readUInt16();
                    local actualName = HintNameStream:readString();

                    --print(string.format("\t0x%04x %s", hint, actualName))
                    table.insert(self.Imports[res.DllName], actualName);
                end
            end
        end
    end

    return res;
end


function peinfo.readDirectories(self)
    self.Directories = self.Directories or {}
    
    self:readDirectory_Export();
    self:readDirectory_Import();

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
	local nsections = self.COFF.NumberOfSections;
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

		sec.Name = stringFromBuff(sec.Name, 8)

		self.Sections[sec.Name] = sec
	end

	return self
end

--[[
    DOS Header
    COFF Header
]]
function peinfo.readPESignature(self)
    local ntheadertype = self.SourceStream:readBytes(4);
    if not IsPEFormatImageFile(ntheadertype) then
        return false, "not PE Format Image File"
    end

    self.PEHeader = {
        signature = ntheadertype;
    }

    return ntheadertype;
end

function peinfo.parse(self, ms)
    self.SourceStream = ms;
    self._data = ms.data;
    self._size = ms.size;

    local DOSHeader, err, sig = self:readDOSHeader();
    if not DOSHeader then 
        return false, err, sig;
    end

    local DOSBodySize = DOSHeader.e_lfanew - ms:tell();
    self.DOS = {
        Header = DOSHeader;
        StubSize = DOSBodySize;
        Stub = ms:readBytes(DOSBodySize);   -- Valid DOS stub program
    }

--[[
    print("---- parseData ----")
    print("  DOS Header Ends: ", ms:tell());
    print(" PE Header Begins: ", string.format("0x%x", DOSHeader.e_lfanew))
    print("    DOS Body size: ", DOSBodySize)
--]]
 

    -- seek to where the PE header
    -- is supposed to start
    ms:seek(DOSHeader.e_lfanew)

    -- we assume we can only read PE, and PE+ files
    -- anything else is an error
    local pesig, err = self:readPESignature()

    if not pesig then
        return false, err;
    end

    self.COFF = self:readCOFF(ms);

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