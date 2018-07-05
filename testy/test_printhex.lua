package.path = package.path..";../?.lua"

local ffi = require("ffi")
local putils = require("print_utils")

local mmap = require("pereader.mmap_win32")
local binstream = require("pereader.binstream")


local filename = arg[1];

if not filename then
	print("NO FILE SPECIFIED")
    return
end

local mfile = mmap(filename);

if not mfile then 
    print("Error trying to map: ", filename)
end

local data = ffi.cast("uint8_t *", mfile:getPointer());
local ms = binstream(data, mfile.size)


putils.printHex(ms, 256)

