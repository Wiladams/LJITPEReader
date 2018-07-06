# LJITPEReader
Various routines related to reading Windows PE format files.

On the Windows OS, there are inbuilt routines for reading information from PE files (the executabl file format for Windows).
The routines in this project replicate that inbuilt capability, but using Lua.  This allows you to read PE format files from
any platform where Lua is supported.

**Basic Usage**

```lua
local function main()
	local mfile = mmap(filename);
	if not mfile then 
		print("Error trying to map: ", filename)
	end

	local data = ffi.cast("uint8_t *", mfile:getPointer());

	local info, err = peinfo:fromData(data, mfile.size);
	if not info then
		print("ERROR: fromData - ", err)
		return
    end

    -- Once you have the info object, it is already filled with 
    -- all the PE Information parsed out, and ready to traverse
    -- look at the 'testy/test_peinfo.lua'  file as an example
    printDOSInfo(info.DOS)
	printCOFF(info)
	printOptionalHeader(info)
	printDataDirectory(info)
	printSectionHeaders(info)
	printImports(info)
	printExports(info)
end
```

**Chronology**
6 July 2018
- Cleanup and refactoring in peinfo
- Improve error handling in binstream
- Add print_utils, with printHex() function
- Improve detection of Export forward reference by checking section characteristics

1 July 2018
- Correctly parse imports for 32 and 64-bit images
- Correctly parse export names only, no ordinal or address tables
- Put internal module name into parser 'ModuleName' field

**References**
* [Microsoft Documentation]https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
* [Tutorial]http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
