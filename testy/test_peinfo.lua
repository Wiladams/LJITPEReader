package.path = package.path..";../?.lua"

local ffi = require("ffi")

local peinfo = require("pereader.peinfo")
local enums = require("pereader.peenums")
local mmap = require("pereader.mmap_win32")

local filename = arg[1];

if not filename then
	print("NO FILE SPECIFIED")
    return
end

local function printDOSInfo(info)
	print(string.format("Magic: %c%c", info.e_magic[0], info.e_magic[1]))
	print(string.format("PE Offset: 0x%x", info.e_lfanew));
end

local function printCOFF(reader)
	local info = reader.FileHeader;

	print("==== COFF ====")
	print(string.format("Machine: %s (0x%x)", enums.MachineType[info.Machine], info.Machine));
	print("Number Of Sections: ", info.NumberOfSections);
	print("Pointer To Symbol Table: ", info.PointerToSymbolTable);
	print("Number of Symbols: ", info.NumberOfSymbols);
	print("Size of Optional Header: ", info.SizeOfOptionalHeader);
	print(string.format("Characteristics: 0x%04x", info.Characteristics));
end

local function printPEHeader(browser)
	local info = browser.PEHeader

	print("==== PE Header ====")
	print(string.format("Magic: 0x%04X", info.Magic))
	print(string.format("Major Linker Version: 0x%02x", info.MajorLinkerVersion))
	print(string.format("Minor Linker Version: 0x%02x", info.MinorLinkerVersion))
	print(string.format("Size Of Code: 0x%08x", info.SizeOfCode))

	print(string.format("Address of Entry Point: 0x%08X", info.AddressOfEntryPoint))
	print(string.format("Base of Code: 0x%08X", info.BaseOfCode))
	if info.BaseOfData then
		print(string.format("Base of Data: 0x%08X", info.BaseOfData))
	end
	print(string.format("Image Base: 0x%08X", info.ImageBase))

	print(string.format("Number of Rvas and Sizes: 0x%08X", info.NumberOfRvaAndSizes))
end




local function printDirectoryEntries(reader, dirs)
	local dirs = reader.PEHeader.Directories
	print("==== printDirectoryEntries ====")
	for name,dir in pairs(dirs) do
		--print(name, dir)
		local vaddr = dir.VirtualAddress
		print(string.format("Name: %s  Address: 0x%08X  Size: 0x%08X", name, vaddr, dir.Size));
		if vaddr > 0 then
			local sec = reader:GetEnclosingSectionHeader(vaddr)
			if sec then
			    print("  Section: ", sec.Name)
			end
		end
	end
end

local function printSectionHeaders(reader)
	print("===== SECTIONS =====")
	for name,section in pairs(reader.Sections) do
		print("Name: ", name)
		print(string.format("\tVirtual Size: 0x%08X", section.VirtualSize))
		print(string.format("\tVirtual Address: 0x%08X", section.VirtualAddress))
		print(string.format("\tSize of Raw Data: 0x%08X", section.SizeOfRawData))
		print(string.format("\tPointer to Raw Data: 0x%08X", section.PointerToRawData))
		print(string.format("\tPointer to Relocations: 0x%08X", section.PointerToRelocations))
		print(string.format("\tPointer To Linenumbers: 0x%08X", section.PointerToLinenumbers))
		print(string.format("\tNumber of Relocations: %d", section.NumberOfRelocations))
		print(string.format("\tNumber of Line Numbers: %d", section.NumberOfLinenumbers))
		print(string.format("\tCharacteristics: 0x%08X", section.Characteristics))
	end
end

local function printImports(reader)
	print("===== IMPORTS =====")

	local importdirref = reader.PEHeader.Directories.Import

	if not importdirref then 
		print("   NO Imports")
		return 
	end

	-- Get the section the import directory is in
	local importsStartRVA = importdirref.VirtualAddress
	local importsSize = importdirref.Size
	local section = reader:GetEnclosingSectionHeader(importsStartRVA)
	if not section then
		print("No section found for import directory")
		return
	end

	print("Import Section: ", section.Name);

	-- Get the actual address of the import descriptor
	local importdescripptr = reader:GetPtrFromRVA(importsStartRVA)
	local importdescrip = IMAGE_IMPORT_DESCRIPTOR(importdescripptr, importsSize)


	-- Iterate over import descriptors
	while true do

		if importdescrip.TimeDateStamp == 0 and importdescrip.Name == 0 then
			break
		end

		local nameptr = reader:GetPtrFromRVA(importdescrip.Name)
		local importname = ffi.string(nameptr)
		print("Import Name: ", importname);

		--print(string.format("Original First Thunk: 0x08%X", importdescrip:get_OriginalFirstThunk()))
		--print(string.format("TimeStamp: 0x08%X", importdescrip:get_TimeDateStamp()))
		--print(string.format("Forwarder Chain: 0x08%X", importdescrip:get_ForwarderChain()))
		--print(string.format("Name: 0x08%X", importdescrip:get_Name()))
		--print(string.format("First Thunk: 0x08%X", importdescrip:get_FirstThunk()))

		-- Iterate over the invividual import entries
		local thunk = importdescrip.OriginalFirstThunk
		local thunkIAT = importdescrip.FirstThunk

		if thunk == 0 then
			-- Yes!  Must have a non-zero FirstThunk field then
			thunk = thunkIAT;

			if (thunk == 0) then
				return ;
			end
		end

		thunk = reader:GetPtrFromRVA(thunk);
		if not thunk then
			return
		end

		thunkIAT = reader:GetPtrFromRVA(thunkIAT);

		thunk = IMAGE_THUNK_DATA(thunk, importdescrip.ClassSize);
		thunkIAT = IMAGE_THUNK_DATA(thunkIAT, importdescrip.ClassSize);

		while (true) do
			local thunkPtr = thunk.Data
			if thunkPtr == 0 then
				break;
			end

			if (false) then -- band(thunk.Data, IMAGE_ORDINAL_FLAG) then
			else
				local pOrdinalName = thunkPtr;
				pOrdinalName = reader:GetPtrFromRVA(pOrdinalName);
				pOrdinalName = IMAGE_IMPORT_BY_NAME(pOrdinalName, importdescrip.ClassSize)
				local actualName = pOrdinalName.Name
				actualName = ffi.string(actualName)
				print(string.format("\t%s", actualName))
			end

			thunk.DataPtr = thunk.DataPtr + thunk.ClassSize;
			thunkIAT.DataPtr = thunkIAT.DataPtr + thunkIAT.ClassSize;
		end


		importdescrip.DataPtr = importdescrip.DataPtr + importdescrip.ClassSize
	end
end


local function main()
	local mfile = mmap(filename);
--print("MFILE: ", mfile)
	local data = ffi.cast("uint8_t *", mfile:getPointer());

	local peinfo = peinfo(data, mfile.size);


	printDOSInfo(peinfo.DOSHeader)
	printCOFF(peinfo)
	printPEHeader(peinfo)
	printDirectoryEntries(peinfo)
	printSectionHeaders(peinfo)
	--printImports(peinfo)
end

main()