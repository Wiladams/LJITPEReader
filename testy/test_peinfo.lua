package.path = package.path..";../?.lua"

local ffi = require("ffi")

local peinfo = require("pereader.peinfo")
local mmap = require("pereader.mmap_win32")
local filename = arg[1];

if not filename then
    return
end

local function printDOSInfo(info)
	print(string.format("Magic: %c%c", info.e_magic[0], info.e_magic[1]))
	print(string.format("PE Offset: 0x%x", info.e_lfanew));
end


local mfile = mmap(filename);
--print("MFILE: ", mfile)
local data = ffi.cast("uint8_t *", mfile:getPointer());

local peinfo = peinfo(data, mfile.size);


printDOSInfo(peinfo.DOSHeader)


