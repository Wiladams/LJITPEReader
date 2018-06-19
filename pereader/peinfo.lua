local binstream = require("pereader.binstream")

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
        TimeDateStamp = ms:readUInt32();;
        PointerToSymbolTable = ms:readUInt32();
        NumberOfSymbols = ms:readUInt32();
        SizeOfOptionalHeader = ms:readUInt16();
        Characteristics = ms:readUInt16();
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
    -- unwind reading the magic so we can read it again
    -- as part of reading the whole 'optional' header
    ms:seek(ms:tell()-2);

    -- we know from the file header what size the
    -- optional header is supposed to be, so we can 
    -- create a sub-stream for reading that section alone
    if IsPe32Header(pemagic) then
        res.PEHeader = PE32Header(buff, bufflen, offset)
    elseif IsPe32PlusHeader(pemagic) then
        res.PEHeader = PE32PlusHeader(buff, bufflen, offset)
    end

--[[
res.Directories = buildDirectories(res.PEHeader)

-- Now offset should be positioned at the section table
res.Sections = buildSectionHeaders(res)
--]]
    return self
end


return peinfo