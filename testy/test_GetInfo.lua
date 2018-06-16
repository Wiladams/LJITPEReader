package.path = package.path..";../?.lua"

local ffi = require "ffi"

local PEReader = require ("PEReader")
PEReader();
local enums = require("peenums")


local function printDOSInfo(info)
	local magic = info:get_e_magic();
	local lfanew = info:get_e_lfanew();

	print(string.format("Magic: %c %c", magic[0], magic[1]))
	print(string.format("PE Offset: 0x%x", lfanew));

end

local function printCOFF(info)
	print("==== COFF ====")
	print(string.format("Machine: %s (0x%x)", enums.MachineType[info:get_Machine()], info:get_Machine()));
	print("Number Of Sections: ", info:get_NumberOfSections());
	print("Pointer To Symbol Table: ", info:get_PointerToSymbolTable());
	print("Number of Symbols: ", info:get_NumberOfSymbols());
	print("Size of Optional Header: ", info:get_SizeOfOptionalHeader());
	print(string.format("Characteristics: 0x%4x", info:get_Characteristics()));
end

local function printPEHeader(browser)
	local info = browser.PEHeader

	print("==== PE Header ====")
	print(string.format("Magic: 0x%04X", info:get_Magic()))
	print(string.format("Major Linker Version: 0x%02x", info:get_MajorLinkerVersion()))
	print(string.format("Minor Linker Version: 0x%02x", info:get_MinorLinkerVersion()))
	print(string.format("Size Of Code: 0x%08x", info:get_SizeOfCode()))

	print(string.format("Address of Entry Point: 0x%08X", info:get_AddressOfEntryPoint()))
	print(string.format("Base of Code: 0x%08X", info:get_BaseOfCode()))
	if info.get_BaseOfData then
		print(string.format("Base of Data: 0x%08X", info:get_BaseOfData()))
	end
	print(string.format("Image Base: 0x%08X", info:get_ImageBase()))

	print(string.format("Number of Rvas and Sizes: 0x%08X", info:get_NumberOfRvaAndSizes()))
end

local function printDirectoryEntries(browser)
	local dirs = browser.Directories

	for name,dir in pairs(dirs) do
		local vaddr = dir:get_VirtualAddress()
		print(string.format("Name: %s  Address: 0x%08X  Size: 0x%08X", name, vaddr, dir:get_Size()));
		if vaddr > 0 then
			local sec = GetEnclosingSectionHeader(vaddr, browser)
			if sec then
			    print("  Section: ", sec.Name)
			end
		end
	end
end



local function printImports(browser)
	local importdirref = browser.Directories.Import

	if not importdirref then return end

	print("===== IMPORTS =====")
	-- Get the section the import directory is in
	local importsStartRVA = importdirref:get_VirtualAddress()
	local importsSize = importdirref:get_Size()
	local section = GetEnclosingSectionHeader(importsStartRVA, browser)
	if not section then
		print("No section found for import directory")
		return
	end

	print("Import Section: ", section.Name);

	-- Get the actual address of the import descriptor
	local importdescripptr = GetPtrFromRVA(importsStartRVA, browser)
	local importdescrip = IMAGE_IMPORT_DESCRIPTOR(importdescripptr, importsSize)


	-- Iterate over import descriptors
	while true do

		if importdescrip:get_TimeDateStamp() == 0 and importdescrip:get_Name() == 0 then
			break
		end

		local nameptr = GetPtrFromRVA(importdescrip:get_Name(), browser)
		local importname = ffi.string(nameptr)
		print("Import Name: ", importname);

		--print(string.format("Original First Thunk: 0x08%X", importdescrip:get_OriginalFirstThunk()))
		--print(string.format("TimeStamp: 0x08%X", importdescrip:get_TimeDateStamp()))
		--print(string.format("Forwarder Chain: 0x08%X", importdescrip:get_ForwarderChain()))
		--print(string.format("Name: 0x08%X", importdescrip:get_Name()))
		--print(string.format("First Thunk: 0x08%X", importdescrip:get_FirstThunk()))

		-- Iterate over the invividual import entries
		local thunk = importdescrip:get_OriginalFirstThunk()
		local thunkIAT = importdescrip:get_FirstThunk()

		if thunk == 0 then
			-- Yes!  Must have a non-zero FirstThunk field then
			thunk = thunkIAT;

			if (thunk == 0) then
				return ;
			end
		end

		thunk = GetPtrFromRVA(thunk, browser);
		if not thunk then
			return
		end

		thunkIAT = GetPtrFromRVA(thunkIAT, browser);

		thunk = IMAGE_THUNK_DATA(thunk, importdescrip.ClassSize);
		thunkIAT = IMAGE_THUNK_DATA(thunkIAT, importdescrip.ClassSize);

		while (true) do
			local thunkPtr = thunk:get_Data()
			if thunkPtr == 0 then
				break;
			end

			if (false) then -- band(thunk.Data, IMAGE_ORDINAL_FLAG) then
			else
				local pOrdinalName = thunkPtr;
				pOrdinalName = GetPtrFromRVA(pOrdinalName, browser);
				pOrdinalName = IMAGE_IMPORT_BY_NAME(pOrdinalName, importdescrip.ClassSize)
				local actualName = pOrdinalName:get_Name()
				actualName = ffi.string(actualName)
				print(string.format("\t%s", actualName))
			end

			thunk.DataPtr = thunk.DataPtr + thunk.ClassSize;
			thunkIAT.DataPtr = thunkIAT.DataPtr + thunkIAT.ClassSize;
		end


		importdescrip.DataPtr = importdescrip.DataPtr + importdescrip.ClassSize
	end
end


local function printSectionHeaders(browser)
	print("===== SECTIONS =====")
	for name,section in pairs(browser.Sections) do
		print("Name: ", name)
		print(string.format("\tVirtual Size: 0x%08X", section:get_VirtualSize()))
		print(string.format("\tVirtual Address: 0x%08X", section:get_VirtualAddress()))
		print(string.format("\tSize of Raw Data: 0x%08X", section:get_SizeOfRawData()))
		print(string.format("\tPointer to Raw Data: 0x%08X", section:get_PointerToRawData()))
		print(string.format("\tPointer to Relocations: 0x%08X", section:get_PointerToRelocations()))
		print(string.format("\tPointer To Linenumbers: 0x%08X", section:get_PointerToLinenumbers()))
		print(string.format("\tNumber of Relocations: %d", section:get_NumberOfRelocations()))
		print(string.format("\tNumber of Line Numbers: %d", section:get_NumberOfLinenumbers()))
		print(string.format("\tCharacteristics: 0x%08X", section:get_Characteristics()))
	end
end







--local browser = CreatePEBrowser("HeadsUp.exe")
--local browser = CreatePEBrowser("HexEdit.exe")
--local browser = PEReader.CreatePEReader("c:/tools/openssl/openssl.exe")
local filename = arg[1];

if not filename then
return
end

local browser = PEReader.CreatePEReader(filename)

printDOSInfo(browser.DOSHeader)
printCOFF(browser.FileHeader)
printPEHeader(browser);
printDirectoryEntries(browser);
printSectionHeaders(browser)
printImports(browser)
