package.path = package.path..";../?.lua"

local ffi = require("ffi")

local enum = require("pereader.enum")
local peinfo = require("pereader.peinfo")
local peenums = require("pereader.peenums")
local mmap = require("pereader.mmap_win32")
local binstream = require("pereader.binstream")


local filename = arg[1];

if not filename then
	print("NO FILE SPECIFIED")
    return
end


local function printDOSInfo(info)
	print(string.format("    Magic: %c%c", info.e_magic[0], info.e_magic[1]))
	print(string.format("PE Offset: 0x%x", info.e_lfanew));
end

local function printCOFF(reader)
	local info = reader.COFF;

	print("==== COFF ====")
	print("                Machine: ", string.format("0x%X", info.Machine), peenums.MachineType[info.Machine]);
	print("     Number Of Sections: ", info.NumberOfSections);
	print("        Time Date Stamp: ", string.format("0x%X", info.TimeDateStamp));
	print("Pointer To Symbol Table: ", info.PointerToSymbolTable);
	print("      Number of Symbols: ", info.NumberOfSymbols);
	print("Size of Optional Header: ", info.SizeOfOptionalHeader);
	print(string.format("        Characteristics: 0x%04x  (%s)", info.Characteristics,
		enum.bitValues(peenums.Characteristics, info.Characteristics, 32)));
	print("---------------------")
end

--[[
    print("==== readPE32PlusHeader ====")


    print("      Size of Image: ", self.PEHeader.SizeOfImage)
    print("    Size of Headers: ", self.PEHeader.SizeOfHeaders)
    print("       Loader Flags: ", self.PEHeader.LoaderFlags)

--]]

local function printOptionalHeader(browser)
	local info = browser.PEHeader
	print("==== Optional Header ====")
	
	if not info then
		print(" **   NONE  **")
		return 
	end


	print("                   Magic: ", string.format("0x%04X",info.Magic))
    print("          Linker Version: ", string.format("%d.%d",info.MajorLinkerVersion, info.MinorLinkerVersion));
	print("            Size Of Code: ", string.format("0x%08x", info.SizeOfCode))
    print("              Image Base: ", info.ImageBase)
    print("       Section Alignment: ", info.SectionAlignment)
	print("          File Alignment: ", info.FileAlignment)
	print("  Address of Entry Point: ", string.format("0x%08X",info.AddressOfEntryPoint))
	print(string.format("            Base of Code: 0x%08X", info.BaseOfCode))
	-- BaseOfData only exists for 32-bit, not 64-bit
	if info.BaseOfData then
		print(string.format("            Base of Data: 0x%08X", info.BaseOfData))
	end

	print(string.format("Number of Rvas and Sizes: 0x%08X (%d)", info.NumberOfRvaAndSizes, info.NumberOfRvaAndSizes))
	print("---------------------")
end




local function printDataDirectory(reader, dirs)
	local dirs = reader.PEHeader.Directories
	print("==== Directory Entries ====")
	print(string.format("%20s   %10s    %12s  %s",
		"name", "location", "size (bytes)", "section"))
	for name,dir in pairs(dirs) do
		--print(name, dir)
		local vaddr = dir.VirtualAddress
		local sectionName = "UNKNOWN"
		if vaddr > 0 then
			local sec = reader:GetEnclosingSectionHeader(vaddr)
			if sec then
				sectionName = sec.Name
			end
		end
		print(string.format("%20s   0x%08X    %12s   %s", 
			name, vaddr, string.format("0x%x (%d)", dir.Size, dir.Size), sectionName))
	end
	print("---------------------")
end

local function printSectionHeaders(reader)
	print("===== SECTIONS =====")
	for name,section in pairs(reader.Sections) do
		print("Name: ", name)
		print(string.format("            Virtual Size: %d", section.VirtualSize))
		print(string.format("         Virtual Address: 0x%08X", section.VirtualAddress))
		print(string.format("        Size of Raw Data: %d", section.SizeOfRawData))
		print(string.format("     Pointer to Raw Data: 0x%08X", section.PointerToRawData))
		print(string.format("  Pointer to Relocations: 0x%08X", section.PointerToRelocations))
		print(string.format("  Pointer To Linenumbers: 0x%08X", section.PointerToLinenumbers))
		print(string.format("   Number of Relocations: %d", section.NumberOfRelocations))
		print(string.format("  Number of Line Numbers: %d", section.NumberOfLinenumbers))
		print(string.format("         Characteristics: 0x%08X  (%s)", section.Characteristics, 
			enum.bitValues(peenums.SectionCharacteristics, section.Characteristics)))
	end
	print("---------------------")
end

local function printImports(reader)
	print("===== IMPORTS =====")
	if not reader.Imports then return ; end

	for k,v in pairs(reader.Imports) do
		print(k)
		for i, name in ipairs(v) do
			print(string.format("    %s",name))
		end
	end
	print("---------------------")
end

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
	print("---------------------")
end


local function main()
	local mfile = mmap(filename);
	if not mfile then 
		print("Error trying to map: ", filename)
	end

	local data = ffi.cast("uint8_t *", mfile:getPointer());

	local peinfo = peinfo(data, mfile.size);


	printDOSInfo(peinfo.DOSHeader)
	printCOFF(peinfo)
	printOptionalHeader(peinfo)
	printDataDirectory(peinfo)
	printSectionHeaders(peinfo)
	printImports(peinfo)
	printExports(peinfo)
end

main()