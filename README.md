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
The point of the peinfo object is to give you relatively easy access to the bits and 
pieces of a Portable Executable (PE) file.  There's quite a bit of esoterica, misunderstanding
and plain wrongness about parsing PE files.  This object tries to get things right, 
pulling from examples, documentation, confirming with tools such as dumpbin, and the like.

The result is you can do things like access headers, sections, directories and the like with ease.
For example, if you want to print out a list of all the functions that are exported by a PE file;

```lua
local function printExports(reader)
	print("===== EXPORTS =====")
	if (not reader.Exports) then
		print("  NO EXPORTS")
		return ;
	end

	print("Module Name: ", reader.ModuleName)
	for i, entry in ipairs(reader.Exports) do
		if type(entry.funcptr) == "string" then
			print(string.format("%4d %4d %50s %s",entry.ordinal, entry.hint, entry.name, entry.funcptr))
		else 
			print(string.format("%4d %4d %50s %s",entry.ordinal, entry.hint, entry.name, string.format("0x%08X", entry.funcptr or 0)))
		end
	end
end
```

This will also take care of those cases where you have forward exports, which means the function pointer isn't actually a pointer to a function within the .dll you're examining, but rather a pointer to a string which represents the actual
function within a different library.

You can find various bits and bobs in the 'testy' directory.  Of most note is the 'test_penifo.lua' file.  This acts 
essentially like the 'dumpbin' program that is found on Windows.  It will dump all the interesting information found in the PE file, like the various headers, directories, sections, imports, exports.  It dumps in a human readable form, similar to what dumpbin does.  If you'd prefer dumping into another machine readable form such as Lua, or JSON, you
can probably construct such a program using this one as a starting point.

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
