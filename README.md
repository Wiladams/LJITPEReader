# LJITPEReader
Various routines related to reading Windows PE format files.

On the Windows OS, there are inbuilt routines for reading information from PE files (the executabl file format for Windows). The routines in this project replicate that inbuilt capability, but using Lua.  This allows you to read PE format files from any platform where Lua is supported.

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

**General Methodology**
The most fundamental idea here is to start with treating the .dll, or .exe as a stream of bytes.  We don't do a LibraryLoad(), because that would actually load the file into memory as if it were going to be executed.  That's not what we want.  We want to treat the file as a raw chunk of memory, and throw a binary stream atop that.

The peinfo object has a factory method: peinfo:fromData(data, size)

this function takes a pointer to some data, and a size, and will return an object that represents the parsed form of the data.  This chuck of memory can be delivered in any way you like.  In the test_peinfo.lua program, a memory map is established for the file, because this is the easiest thing to do on Windows.  But, the peinfo object does not require memory mapping, it just requires a pointer to some data.

One you have a pointer to the binary data, the 'binstream' object is used to retrieve various integer, string, and byte range values.  This stream object makes life really convenient.  A simple usage might be like this:

```lua
local bs = binstream(data, size, 0, true);  -- data, size, offset, littleendian
bs:readUInt32()     -- read DWORD
bs:readUInt32()     -- read DWORD
bs:readUInt16()     -- read WORD
bs:skip(2*10)       -- skip some 'reserved' data
local bytes = bs:readBytes(8)
```

Using this stream processing approach is in comparison to using a data structure mapping approach.  That is, you could define a bunch of 'C' structs, and just overlay the file atop those.  This was the first approach used in this project.  There are a couple of drawbacks to that approach.  First, it will only work as long as you're reading the files on a machine with the same endianness as the one the files were generated for.  Second, there is enough processing and variance that you need to make adjustments along the way.  Therefore, it was deemed that an approach that relies on code rather than data structures, would be a more explicit and efficient approach.

Another bit of magic that happens behind the scenes is dealing with RVA (Relative Virtual Address).  This is probably the biggest paid of dealing with the PE file format.  The RVA is essentially a way for the 'loader' or any other tool, to determine where something is located within the file without using a fixed offset.  The RVA points to a place with a particular section, and that section's actual location within the file, or within memory after loaded, could change.

The peinfo object has the convenient `peinfo.fileOffsetFromRVA(self, rva)` which will give you back a value which is an offset within the file.  This offset can be used with the binstream to 'seek' to a particular position.  This is done behind the scenes, for example to get the export names within the file.  You can further use this function to locate the actual body of a function within the file, and do what you will with that information.

As a convenience, there is the 'testy/print_utils.lua' file.  This contains functions that make printing hex dumps prettier.  The one function: `printHex(ms, buffer, offsetbits, iterations)' will take a stream 'ms', and print it out as a pretty printed 'hex' display.  The 'buffer' parameter is a convenience you can pass in so that one is not allocated within the function itself.  'offsetbits' tells the routine whether to print 32-bit or 64-bit offsets.  The 'iterations' parameter tells how many lines to print.  If left out, all lines will be printed.

```
Offset (h)  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  Decoded text
0x00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
0x00000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......
0x00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0x00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  ................
0x00000040: 0E 1F BA 0E 00 B4 09 CD  21 B8 01 4C CD 21 54 68  ........!..L.!Th
0x00000050: 69 73 20 70 72 6F 67 72  61 6D 20 63 61 6E 6E 6F  is program canno
0x00000060: 74 20 62 65 20 72 75 6E  20 69 6E 20 44 4F 53 20  t be run in DOS 
0x00000070: 6D 6F 64 65 2E 0D 0D 0A  24 00 00 00 00 00 00 00  mode....$.......
0x00000080: 28 58 09 94 6C 39 67 C7  6C 39 67 C7 6C 39 67 C7  (X..l9g.l9g.l9g.
0x00000090: 65 41 F4 C7 7E 39 67 C7  BE 5D 66 C6 6E 39 67 C7  eA..~9g..]f.n9g.
0x000000A0: 1F 5B 66 C6 6F 39 67 C7  6C 39 66 C7 E7 39 67 C7  .[f.o9g.l9f..9g.
0x000000B0: BE 5D 64 C6 6F 39 67 C7  BE 5D 62 C6 67 39 67 C7  .]d.o9g..]b.g9g.
0x000000C0: BE 5D 63 C6 66 39 67 C7  6C 39 67 C7 6D 39 67 C7  .]c.f9g.l9g.m9g.
0x000000D0: 87 5D 63 C6 2D 39 67 C7  87 5D 67 C6 6D 39 67 C7  .]c.-9g..]g.m9g.
0x000000E0: 87 5D 65 C6 6D 39 67 C7  52 69 63 68 6C 39 67 C7  .]e.m9g.Richl9g.
0x000000F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
0x00000100: 50 45 00 00 64 86 05 00  98 E3 29 5B 00 00 00 00  PE..d.....)[....
```

This is very convenient when you don't already have a favored hex editor.  You can quickly dump the contents of some file, load it into a reasonable text editor, and poke around at various addresses to see what you can see.

You can position the binstream at the location you desire, and go from there as well.


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
Parsing Portable Executable (PE) file formats is pretty esoteric stuff.  The documentation is usually in the form of code, rather than voluminous documentation.  PE file format actually has documentation from Microsoft, and has at least a couple of decades of actual usage.  Even so, there is plenty of documentation that is out of date, wrong, incomplete, etc.  The links provided below form part of the picture, and are still accessible as of July 2018.  Be aware that some documentation was written before 64-bit systems were a thing.  That's the biggest gotcha when reading through the various documents.  When it comes to the PE 'magic', if you don't see mention of 'PE 32 Plus", you know you're dealing with 32-bit documentation, and you'll want to consider that, and make sure you reference the current Microsoft documentation.

Microsoft Documentation

* https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
* https://msdn.microsoft.com/en-us/library/ms809762.aspx

Other Stuff

* http://net.pku.edu.cn/~course/cs201/2003/mirrorWebster.cs.ucr.edu/Page_TechDocs/pe.txt
* http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
* http://www.osdever.net/documents/PECOFF.pdf
* http://www.pelib.com/resources/kath.txt
* https://resources.infosecinstitute.com/complete-tour-of-pe-and-elf-part-1/#article

Pretty Pictures

http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf


