local ffi = require('ffi')
local class = require('class')
local bitbang = require('bitbang')
bitbang();


class.IMAGE_BOUND_FORWARDER_REF()

IMAGE_BOUND_FORWARDER_REF.Fields = {}

function IMAGE_BOUND_FORWARDER_REF:_init(...)
	local args={...}

    self.ClassSize = 8

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[8]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_BOUND_FORWARDER_REF:SetFieldValue(fieldname, value)
    local field = IMAGE_BOUND_FORWARDER_REF.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_BOUND_FORWARDER_REF:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_BOUND_FORWARDER_REF:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_BOUND_FORWARDER_REF.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="uint32_t", bitoffset= 0, sizeinbits = 32}

function IMAGE_BOUND_FORWARDER_REF:set_OffsetModuleName(value)
	setbitstobytes(self.DataPtr, 32, 16, value);
	return self
end

function IMAGE_BOUND_FORWARDER_REF:get_OffsetModuleName()
	return getbitsfrombytes(self.DataPtr, 32, 16);
end

IMAGE_BOUND_FORWARDER_REF.Fields.OffsetModuleName = {name="OffsetModuleName", basetype="int16_t", bitoffset= 32, sizeinbits = 16}

function IMAGE_BOUND_FORWARDER_REF:set_Reserved(value)
	setbitstobytes(self.DataPtr, 48, 16, value);
	return self
end

function IMAGE_BOUND_FORWARDER_REF:get_Reserved()
	return getbitsfrombytes(self.DataPtr, 48, 16);
end

IMAGE_BOUND_FORWARDER_REF.Fields.Reserved = {name="Reserved", basetype="uint16_t", bitoffset= 48, sizeinbits = 16}


class.IMAGE_SECTION_HEADER()

IMAGE_SECTION_HEADER.Fields = {}

function IMAGE_SECTION_HEADER:_init(...)
	local args={...}

    self.ClassSize = 40

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[40]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_SECTION_HEADER:SetFieldValue(fieldname, value)
    local field = IMAGE_SECTION_HEADER.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_SECTION_HEADER:set_Name(value)
	setbitstobytes(self.DataPtr, 0, 64, value);
	return self
end

function IMAGE_SECTION_HEADER:get_Name()
	local byteoffset = 0/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)
	return ptr, 8;
end

IMAGE_SECTION_HEADER.Fields.Name = {name="Name", basetype="char", bitoffset= 0, sizeinbits = 64}

function IMAGE_SECTION_HEADER:set_VirtualSize(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_VirtualSize()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

IMAGE_SECTION_HEADER.Fields.VirtualSize = {name="VirtualSize", basetype="uint32_t", bitoffset= 64, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_VirtualAddress(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_VirtualAddress()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

IMAGE_SECTION_HEADER.Fields.VirtualAddress = {name="VirtualAddress", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_SizeOfRawData(value)
	setbitstobytes(self.DataPtr, 128, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_SizeOfRawData()
	return getbitsfrombytes(self.DataPtr, 128, 32);
end

IMAGE_SECTION_HEADER.Fields.SizeOfRawData = {name="SizeOfRawData", basetype="uint32_t", bitoffset= 128, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_PointerToRawData(value)
	setbitstobytes(self.DataPtr, 160, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_PointerToRawData()
	return getbitsfrombytes(self.DataPtr, 160, 32);
end

IMAGE_SECTION_HEADER.Fields.PointerToRawData = {name="PointerToRawData", basetype="uint32_t", bitoffset= 160, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_PointerToRelocations(value)
	setbitstobytes(self.DataPtr, 192, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_PointerToRelocations()
	return getbitsfrombytes(self.DataPtr, 192, 32);
end

IMAGE_SECTION_HEADER.Fields.PointerToRelocations = {name="PointerToRelocations", basetype="uint32_t", bitoffset= 192, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_PointerToLinenumbers(value)
	setbitstobytes(self.DataPtr, 224, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_PointerToLinenumbers()
	return getbitsfrombytes(self.DataPtr, 224, 32);
end

IMAGE_SECTION_HEADER.Fields.PointerToLinenumbers = {name="PointerToLinenumbers", basetype="uint32_t", bitoffset= 224, sizeinbits = 32}

function IMAGE_SECTION_HEADER:set_NumberOfRelocations(value)
	setbitstobytes(self.DataPtr, 256, 16, value);
	return self
end

function IMAGE_SECTION_HEADER:get_NumberOfRelocations()
	return getbitsfrombytes(self.DataPtr, 256, 16);
end

IMAGE_SECTION_HEADER.Fields.NumberOfRelocations = {name="NumberOfRelocations", basetype="uint16_t", bitoffset= 256, sizeinbits = 16}

function IMAGE_SECTION_HEADER:set_NumberOfLinenumbers(value)
	setbitstobytes(self.DataPtr, 272, 16, value);
	return self
end

function IMAGE_SECTION_HEADER:get_NumberOfLinenumbers()
	return getbitsfrombytes(self.DataPtr, 272, 16);
end

IMAGE_SECTION_HEADER.Fields.NumberOfLinenumbers = {name="NumberOfLinenumbers", basetype="uint16_t", bitoffset= 272, sizeinbits = 16}

function IMAGE_SECTION_HEADER:set_Characteristics(value)
	setbitstobytes(self.DataPtr, 288, 32, value);
	return self
end

function IMAGE_SECTION_HEADER:get_Characteristics()
	return getbitsfrombytes(self.DataPtr, 288, 32);
end

IMAGE_SECTION_HEADER.Fields.Characteristics = {name="Characteristics", basetype="uint32_t", bitoffset= 288, sizeinbits = 32}


class.ImportHeader()

ImportHeader.Fields = {}

function ImportHeader:_init(...)
	local args={...}

    self.ClassSize = 20

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[20]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function ImportHeader:SetFieldValue(fieldname, value)
    local field = ImportHeader.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function ImportHeader:set_Sig1(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function ImportHeader:get_Sig1()
	return getbitsfrombytes(self.DataPtr, 0, 16);
end

ImportHeader.Fields.Sig1 = {name="Sig1", basetype="uint16_t", bitoffset= 0, sizeinbits = 16}

function ImportHeader:set_Sig2(value)
	setbitstobytes(self.DataPtr, 16, 16, value);
	return self
end

function ImportHeader:get_Sig2()
	return getbitsfrombytes(self.DataPtr, 16, 16);
end

ImportHeader.Fields.Sig2 = {name="Sig2", basetype="uint16_t", bitoffset= 16, sizeinbits = 16}

function ImportHeader:set_Version(value)
	setbitstobytes(self.DataPtr, 32, 16, value);
	return self
end

function ImportHeader:get_Version()
	return getbitsfrombytes(self.DataPtr, 32, 16);
end

ImportHeader.Fields.Version = {name="Version", basetype="uint16_t", bitoffset= 32, sizeinbits = 16}

function ImportHeader:set_Machine(value)
	setbitstobytes(self.DataPtr, 48, 16, value);
	return self
end

function ImportHeader:get_Machine()
	return getbitsfrombytes(self.DataPtr, 48, 16);
end

ImportHeader.Fields.Machine = {name="Machine", basetype="uint16_t", bitoffset= 48, sizeinbits = 16}

function ImportHeader:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function ImportHeader:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

ImportHeader.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="uint32_t", bitoffset= 64, sizeinbits = 32}

function ImportHeader:set_SizeOfData(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function ImportHeader:get_SizeOfData()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

ImportHeader.Fields.SizeOfData = {name="SizeOfData", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function ImportHeader:set_OrdinalHint(value)
	setbitstobytes(self.DataPtr, 128, 16, value);
	return self
end

function ImportHeader:get_OrdinalHint()
	return getbitsfrombytes(self.DataPtr, 128, 16);
end

ImportHeader.Fields.OrdinalHint = {name="OrdinalHint", basetype="uint16_t", bitoffset= 128, sizeinbits = 16}

function ImportHeader:set_Type(value)
	setbitstobytes(self.DataPtr, 144, 2, value);
	return self
end

function ImportHeader:get_Type()
	return getbitsfrombytes(self.DataPtr, 144, 2);
end

ImportHeader.Fields.Type = {name="Type", basetype="uint16_t", bitoffset= 144, sizeinbits = 2}

function ImportHeader:set_NameType(value)
	setbitstobytes(self.DataPtr, 146, 3, value);
	return self
end

function ImportHeader:get_NameType()
	return getbitsfrombytes(self.DataPtr, 146, 3);
end

ImportHeader.Fields.NameType = {name="NameType", basetype="uint16_t", bitoffset= 146, sizeinbits = 3}

function ImportHeader:set_Reserved(value)
	setbitstobytes(self.DataPtr, 149, 11, value);
	return self
end

function ImportHeader:get_Reserved()
	return getbitsfrombytes(self.DataPtr, 149, 11);
end

ImportHeader.Fields.Reserved = {name="Reserved", basetype="uint16_t", bitoffset= 149, sizeinbits = 11}


class.PE32Header()

PE32Header.Fields = {}

function PE32Header:_init(...)
	local args={...}

    self.ClassSize = 224

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[224]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function PE32Header:SetFieldValue(fieldname, value)
    local field = PE32Header.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function PE32Header:set_Magic(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function PE32Header:get_Magic()
	return getbitsfrombytes(self.DataPtr, 0, 16);
end

PE32Header.Fields.Magic = {name="Magic", basetype="uint16_t", bitoffset= 0, sizeinbits = 16}

function PE32Header:set_MajorLinkerVersion(value)
	setbitstobytes(self.DataPtr, 16, 8, value);
	return self
end

function PE32Header:get_MajorLinkerVersion()
	return getbitsfrombytes(self.DataPtr, 16, 8);
end

PE32Header.Fields.MajorLinkerVersion = {name="MajorLinkerVersion", basetype="uint8_t", bitoffset= 16, sizeinbits = 8}

function PE32Header:set_MinorLinkerVersion(value)
	setbitstobytes(self.DataPtr, 24, 8, value);
	return self
end

function PE32Header:get_MinorLinkerVersion()
	return getbitsfrombytes(self.DataPtr, 24, 8);
end

PE32Header.Fields.MinorLinkerVersion = {name="MinorLinkerVersion", basetype="uint8_t", bitoffset= 24, sizeinbits = 8}

function PE32Header:set_SizeOfCode(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function PE32Header:get_SizeOfCode()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

PE32Header.Fields.SizeOfCode = {name="SizeOfCode", basetype="uint32_t", bitoffset= 32, sizeinbits = 32}

function PE32Header:set_SizeOfInitializedData(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function PE32Header:get_SizeOfInitializedData()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

PE32Header.Fields.SizeOfInitializedData = {name="SizeOfInitializedData", basetype="uint32_t", bitoffset= 64, sizeinbits = 32}

function PE32Header:set_SizeOfUninitializedData(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function PE32Header:get_SizeOfUninitializedData()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

PE32Header.Fields.SizeOfUninitializedData = {name="SizeOfUninitializedData", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function PE32Header:set_AddressOfEntryPoint(value)
	setbitstobytes(self.DataPtr, 128, 32, value);
	return self
end

function PE32Header:get_AddressOfEntryPoint()
	return getbitsfrombytes(self.DataPtr, 128, 32);
end

PE32Header.Fields.AddressOfEntryPoint = {name="AddressOfEntryPoint", basetype="uint32_t", bitoffset= 128, sizeinbits = 32}

function PE32Header:set_BaseOfCode(value)
	setbitstobytes(self.DataPtr, 160, 32, value);
	return self
end

function PE32Header:get_BaseOfCode()
	return getbitsfrombytes(self.DataPtr, 160, 32);
end

PE32Header.Fields.BaseOfCode = {name="BaseOfCode", basetype="uint32_t", bitoffset= 160, sizeinbits = 32}

function PE32Header:set_BaseOfData(value)
	setbitstobytes(self.DataPtr, 192, 32, value);
	return self
end

function PE32Header:get_BaseOfData()
	return getbitsfrombytes(self.DataPtr, 192, 32);
end

PE32Header.Fields.BaseOfData = {name="BaseOfData", basetype="uint32_t", bitoffset= 192, sizeinbits = 32}

function PE32Header:set_ImageBase(value)
	setbitstobytes(self.DataPtr, 224, 32, value);
	return self
end

function PE32Header:get_ImageBase()
	return getbitsfrombytes(self.DataPtr, 224, 32);
end

PE32Header.Fields.ImageBase = {name="ImageBase", basetype="uint32_t", bitoffset= 224, sizeinbits = 32}

function PE32Header:set_SectionAlignment(value)
	setbitstobytes(self.DataPtr, 256, 32, value);
	return self
end

function PE32Header:get_SectionAlignment()
	return getbitsfrombytes(self.DataPtr, 256, 32);
end

PE32Header.Fields.SectionAlignment = {name="SectionAlignment", basetype="uint32_t", bitoffset= 256, sizeinbits = 32}

function PE32Header:set_FileAlignment(value)
	setbitstobytes(self.DataPtr, 288, 32, value);
	return self
end

function PE32Header:get_FileAlignment()
	return getbitsfrombytes(self.DataPtr, 288, 32);
end

PE32Header.Fields.FileAlignment = {name="FileAlignment", basetype="uint32_t", bitoffset= 288, sizeinbits = 32}

function PE32Header:set_MajorOperatingSystemVersion(value)
	setbitstobytes(self.DataPtr, 320, 16, value);
	return self
end

function PE32Header:get_MajorOperatingSystemVersion()
	return getbitsfrombytes(self.DataPtr, 320, 16);
end

PE32Header.Fields.MajorOperatingSystemVersion = {name="MajorOperatingSystemVersion", basetype="uint16_t", bitoffset= 320, sizeinbits = 16}

function PE32Header:set_MinorOperatingSystemVersion(value)
	setbitstobytes(self.DataPtr, 336, 16, value);
	return self
end

function PE32Header:get_MinorOperatingSystemVersion()
	return getbitsfrombytes(self.DataPtr, 336, 16);
end

PE32Header.Fields.MinorOperatingSystemVersion = {name="MinorOperatingSystemVersion", basetype="uint16_t", bitoffset= 336, sizeinbits = 16}

function PE32Header:set_MajorImageVersion(value)
	setbitstobytes(self.DataPtr, 352, 16, value);
	return self
end

function PE32Header:get_MajorImageVersion()
	return getbitsfrombytes(self.DataPtr, 352, 16);
end

PE32Header.Fields.MajorImageVersion = {name="MajorImageVersion", basetype="uint16_t", bitoffset= 352, sizeinbits = 16}

function PE32Header:set_MinorImageVersion(value)
	setbitstobytes(self.DataPtr, 368, 16, value);
	return self
end

function PE32Header:get_MinorImageVersion()
	return getbitsfrombytes(self.DataPtr, 368, 16);
end

PE32Header.Fields.MinorImageVersion = {name="MinorImageVersion", basetype="uint16_t", bitoffset= 368, sizeinbits = 16}

function PE32Header:set_MajorSubsystemVersion(value)
	setbitstobytes(self.DataPtr, 384, 16, value);
	return self
end

function PE32Header:get_MajorSubsystemVersion()
	return getbitsfrombytes(self.DataPtr, 384, 16);
end

PE32Header.Fields.MajorSubsystemVersion = {name="MajorSubsystemVersion", basetype="uint16_t", bitoffset= 384, sizeinbits = 16}

function PE32Header:set_MinorSubsystemVersion(value)
	setbitstobytes(self.DataPtr, 400, 16, value);
	return self
end

function PE32Header:get_MinorSubsystemVersion()
	return getbitsfrombytes(self.DataPtr, 400, 16);
end

PE32Header.Fields.MinorSubsystemVersion = {name="MinorSubsystemVersion", basetype="uint16_t", bitoffset= 400, sizeinbits = 16}

function PE32Header:set_Win32VersionValue(value)
	setbitstobytes(self.DataPtr, 416, 32, value);
	return self
end

function PE32Header:get_Win32VersionValue()
	return getbitsfrombytes(self.DataPtr, 416, 32);
end

PE32Header.Fields.Win32VersionValue = {name="Win32VersionValue", basetype="uint32_t", bitoffset= 416, sizeinbits = 32}

function PE32Header:set_SizeOfImage(value)
	setbitstobytes(self.DataPtr, 448, 32, value);
	return self
end

function PE32Header:get_SizeOfImage()
	return getbitsfrombytes(self.DataPtr, 448, 32);
end

PE32Header.Fields.SizeOfImage = {name="SizeOfImage", basetype="uint32_t", bitoffset= 448, sizeinbits = 32}

function PE32Header:set_SizeOfHeaders(value)
	setbitstobytes(self.DataPtr, 480, 32, value);
	return self
end

function PE32Header:get_SizeOfHeaders()
	return getbitsfrombytes(self.DataPtr, 480, 32);
end

PE32Header.Fields.SizeOfHeaders = {name="SizeOfHeaders", basetype="uint32_t", bitoffset= 480, sizeinbits = 32}

function PE32Header:set_CheckSum(value)
	setbitstobytes(self.DataPtr, 512, 32, value);
	return self
end

function PE32Header:get_CheckSum()
	return getbitsfrombytes(self.DataPtr, 512, 32);
end

PE32Header.Fields.CheckSum = {name="CheckSum", basetype="uint32_t", bitoffset= 512, sizeinbits = 32}

function PE32Header:set_Subsystem(value)
	setbitstobytes(self.DataPtr, 544, 16, value);
	return self
end

function PE32Header:get_Subsystem()
	return getbitsfrombytes(self.DataPtr, 544, 16);
end

PE32Header.Fields.Subsystem = {name="Subsystem", basetype="uint16_t", bitoffset= 544, sizeinbits = 16}

function PE32Header:set_DllCharacteristics(value)
	setbitstobytes(self.DataPtr, 560, 16, value);
	return self
end

function PE32Header:get_DllCharacteristics()
	return getbitsfrombytes(self.DataPtr, 560, 16);
end

PE32Header.Fields.DllCharacteristics = {name="DllCharacteristics", basetype="uint16_t", bitoffset= 560, sizeinbits = 16}

function PE32Header:set_SizeOfStackReserve(value)
	setbitstobytes(self.DataPtr, 576, 32, value);
	return self
end

function PE32Header:get_SizeOfStackReserve()
	return getbitsfrombytes(self.DataPtr, 576, 32);
end

PE32Header.Fields.SizeOfStackReserve = {name="SizeOfStackReserve", basetype="uint32_t", bitoffset= 576, sizeinbits = 32}

function PE32Header:set_SizeOfStackCommit(value)
	setbitstobytes(self.DataPtr, 608, 32, value);
	return self
end

function PE32Header:get_SizeOfStackCommit()
	return getbitsfrombytes(self.DataPtr, 608, 32);
end

PE32Header.Fields.SizeOfStackCommit = {name="SizeOfStackCommit", basetype="uint32_t", bitoffset= 608, sizeinbits = 32}

function PE32Header:set_SizeOfHeapReserve(value)
	setbitstobytes(self.DataPtr, 640, 32, value);
	return self
end

function PE32Header:get_SizeOfHeapReserve()
	return getbitsfrombytes(self.DataPtr, 640, 32);
end

PE32Header.Fields.SizeOfHeapReserve = {name="SizeOfHeapReserve", basetype="uint32_t", bitoffset= 640, sizeinbits = 32}

function PE32Header:set_SizeOfHeapCommit(value)
	setbitstobytes(self.DataPtr, 672, 32, value);
	return self
end

function PE32Header:get_SizeOfHeapCommit()
	return getbitsfrombytes(self.DataPtr, 672, 32);
end

PE32Header.Fields.SizeOfHeapCommit = {name="SizeOfHeapCommit", basetype="uint32_t", bitoffset= 672, sizeinbits = 32}

function PE32Header:set_LoaderFlags(value)
	setbitstobytes(self.DataPtr, 704, 32, value);
	return self
end

function PE32Header:get_LoaderFlags()
	return getbitsfrombytes(self.DataPtr, 704, 32);
end

PE32Header.Fields.LoaderFlags = {name="LoaderFlags", basetype="uint32_t", bitoffset= 704, sizeinbits = 32}

function PE32Header:set_NumberOfRvaAndSizes(value)
	setbitstobytes(self.DataPtr, 736, 32, value);
	return self
end

function PE32Header:get_NumberOfRvaAndSizes()
	return getbitsfrombytes(self.DataPtr, 736, 32);
end

PE32Header.Fields.NumberOfRvaAndSizes = {name="NumberOfRvaAndSizes", basetype="uint32_t", bitoffset= 736, sizeinbits = 32}

function PE32Header:set_ExportTable(value)
	setbitstobytes(self.DataPtr, 768, 64, value);
	return self
end

function PE32Header:get_ExportTable()
	local byteoffset = 768/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.ExportTable = {name="ExportTable", basetype="uint8_t", bitoffset= 768, sizeinbits = 64}

function PE32Header:set_ImportTable(value)
	setbitstobytes(self.DataPtr, 832, 64, value);
	return self
end

function PE32Header:get_ImportTable()
	local byteoffset = 832/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.ImportTable = {name="ImportTable", basetype="uint8_t", bitoffset= 832, sizeinbits = 64}

function PE32Header:set_ResourceTable(value)
	setbitstobytes(self.DataPtr, 896, 64, value);
	return self
end

function PE32Header:get_ResourceTable()
	local byteoffset = 896/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.ResourceTable = {name="ResourceTable", basetype="uint8_t", bitoffset= 896, sizeinbits = 64}

function PE32Header:set_ExceptionTable(value)
	setbitstobytes(self.DataPtr, 960, 64, value);
	return self
end

function PE32Header:get_ExceptionTable()
	local byteoffset = 960/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.ExceptionTable = {name="ExceptionTable", basetype="uint8_t", bitoffset= 960, sizeinbits = 64}

function PE32Header:set_CertificateTable(value)
	setbitstobytes(self.DataPtr, 1024, 64, value);
	return self
end

function PE32Header:get_CertificateTable()
	local byteoffset = 1024/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.CertificateTable = {name="CertificateTable", basetype="uint8_t", bitoffset= 1024, sizeinbits = 64}

function PE32Header:set_BaseRelocationTable(value)
	setbitstobytes(self.DataPtr, 1088, 64, value);
	return self
end

function PE32Header:get_BaseRelocationTable()
	local byteoffset = 1088/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.BaseRelocationTable = {name="BaseRelocationTable", basetype="uint8_t", bitoffset= 1088, sizeinbits = 64}

function PE32Header:set_Debug(value)
	setbitstobytes(self.DataPtr, 1152, 64, value);
	return self
end

function PE32Header:get_Debug()
	local byteoffset = 1152/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.Debug = {name="Debug", basetype="uint8_t", bitoffset= 1152, sizeinbits = 64}

function PE32Header:set_Architecture(value)
	setbitstobytes(self.DataPtr, 1216, 64, value);
	return self
end

function PE32Header:get_Architecture()
	local byteoffset = 1216/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.Architecture = {name="Architecture", basetype="uint8_t", bitoffset= 1216, sizeinbits = 64}

function PE32Header:set_GlobalPtr(value)
	setbitstobytes(self.DataPtr, 1280, 64, value);
	return self
end

function PE32Header:get_GlobalPtr()
	local byteoffset = 1280/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.GlobalPtr = {name="GlobalPtr", basetype="uint8_t", bitoffset= 1280, sizeinbits = 64}

function PE32Header:set_TLSTable(value)
	setbitstobytes(self.DataPtr, 1344, 64, value);
	return self
end

function PE32Header:get_TLSTable()
	local byteoffset = 1344/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.TLSTable = {name="TLSTable", basetype="uint8_t", bitoffset= 1344, sizeinbits = 64}

function PE32Header:set_LoadConfigTable(value)
	setbitstobytes(self.DataPtr, 1408, 64, value);
	return self
end

function PE32Header:get_LoadConfigTable()
	local byteoffset = 1408/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.LoadConfigTable = {name="LoadConfigTable", basetype="uint8_t", bitoffset= 1408, sizeinbits = 64}

function PE32Header:set_BoundImport(value)
	setbitstobytes(self.DataPtr, 1472, 64, value);
	return self
end

function PE32Header:get_BoundImport()
	local byteoffset = 1472/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.BoundImport = {name="BoundImport", basetype="uint8_t", bitoffset= 1472, sizeinbits = 64}

function PE32Header:set_IAT(value)
	setbitstobytes(self.DataPtr, 1536, 64, value);
	return self
end

function PE32Header:get_IAT()
	local byteoffset = 1536/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.IAT = {name="IAT", basetype="uint8_t", bitoffset= 1536, sizeinbits = 64}

function PE32Header:set_DelayImportDescriptor(value)
	setbitstobytes(self.DataPtr, 1600, 64, value);
	return self
end

function PE32Header:get_DelayImportDescriptor()
	local byteoffset = 1600/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.DelayImportDescriptor = {name="DelayImportDescriptor", basetype="uint8_t", bitoffset= 1600, sizeinbits = 64}

function PE32Header:set_CLRRuntimeHeader(value)
	setbitstobytes(self.DataPtr, 1664, 64, value);
	return self
end

function PE32Header:get_CLRRuntimeHeader()
	local byteoffset = 1664/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.CLRRuntimeHeader = {name="CLRRuntimeHeader", basetype="uint8_t", bitoffset= 1664, sizeinbits = 64}

function PE32Header:set_Reserved(value)
	setbitstobytes(self.DataPtr, 1728, 64, value);
	return self
end

function PE32Header:get_Reserved()
	local byteoffset = 1728/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32Header.Fields.Reserved = {name="Reserved", basetype="uint8_t", bitoffset= 1728, sizeinbits = 64}


class.IMAGE_DATA_DIRECTORY()

IMAGE_DATA_DIRECTORY.Fields = {}

function IMAGE_DATA_DIRECTORY:_init(...)
	local args={...}

    self.ClassSize = 8

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[8]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_DATA_DIRECTORY:SetFieldValue(fieldname, value)
    local field = IMAGE_DATA_DIRECTORY.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_DATA_DIRECTORY:set_VirtualAddress(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_DATA_DIRECTORY:get_VirtualAddress()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_DATA_DIRECTORY.Fields.VirtualAddress = {name="VirtualAddress", basetype="uint32_t", bitoffset= 0, sizeinbits = 32}

function IMAGE_DATA_DIRECTORY:set_Size(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function IMAGE_DATA_DIRECTORY:get_Size()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

IMAGE_DATA_DIRECTORY.Fields.Size = {name="Size", basetype="uint32_t", bitoffset= 32, sizeinbits = 32}


class.IMAGE_BOUND_IMPORT_DESCRIPTOR()

IMAGE_BOUND_IMPORT_DESCRIPTOR.Fields = {}

function IMAGE_BOUND_IMPORT_DESCRIPTOR:_init(...)
	local args={...}

    self.ClassSize = 8

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[8]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_BOUND_IMPORT_DESCRIPTOR:SetFieldValue(fieldname, value)
    local field = IMAGE_BOUND_IMPORT_DESCRIPTOR.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_BOUND_IMPORT_DESCRIPTOR:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_BOUND_IMPORT_DESCRIPTOR:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_BOUND_IMPORT_DESCRIPTOR.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="int32_t", bitoffset= 0, sizeinbits = 32}

function IMAGE_BOUND_IMPORT_DESCRIPTOR:set_OffsetModuleName(value)
	setbitstobytes(self.DataPtr, 32, 16, value);
	return self
end

function IMAGE_BOUND_IMPORT_DESCRIPTOR:get_OffsetModuleName()
	return getbitsfrombytes(self.DataPtr, 32, 16);
end

IMAGE_BOUND_IMPORT_DESCRIPTOR.Fields.OffsetModuleName = {name="OffsetModuleName", basetype="int16_t", bitoffset= 32, sizeinbits = 16}

function IMAGE_BOUND_IMPORT_DESCRIPTOR:set_NumberOfModuleForwarderRefs(value)
	setbitstobytes(self.DataPtr, 48, 16, value);
	return self
end

function IMAGE_BOUND_IMPORT_DESCRIPTOR:get_NumberOfModuleForwarderRefs()
	return getbitsfrombytes(self.DataPtr, 48, 16);
end

IMAGE_BOUND_IMPORT_DESCRIPTOR.Fields.NumberOfModuleForwarderRefs = {name="NumberOfModuleForwarderRefs", basetype="uint16_t", bitoffset= 48, sizeinbits = 16}


class.PE32PlusHeader()

PE32PlusHeader.Fields = {}

function PE32PlusHeader:_init(...)
	local args={...}

    self.ClassSize = 240

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[240]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function PE32PlusHeader:SetFieldValue(fieldname, value)
    local field = PE32PlusHeader.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function PE32PlusHeader:set_Magic(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function PE32PlusHeader:get_Magic()
	return getbitsfrombytes(self.DataPtr, 0, 16);
end

PE32PlusHeader.Fields.Magic = {name="Magic", basetype="uint16_t", bitoffset= 0, sizeinbits = 16}

function PE32PlusHeader:set_MajorLinkerVersion(value)
	setbitstobytes(self.DataPtr, 16, 8, value);
	return self
end

function PE32PlusHeader:get_MajorLinkerVersion()
	return getbitsfrombytes(self.DataPtr, 16, 8);
end

PE32PlusHeader.Fields.MajorLinkerVersion = {name="MajorLinkerVersion", basetype="uint8_t", bitoffset= 16, sizeinbits = 8}

function PE32PlusHeader:set_MinorLinkerVersion(value)
	setbitstobytes(self.DataPtr, 24, 8, value);
	return self
end

function PE32PlusHeader:get_MinorLinkerVersion()
	return getbitsfrombytes(self.DataPtr, 24, 8);
end

PE32PlusHeader.Fields.MinorLinkerVersion = {name="MinorLinkerVersion", basetype="uint8_t", bitoffset= 24, sizeinbits = 8}

function PE32PlusHeader:set_SizeOfCode(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function PE32PlusHeader:get_SizeOfCode()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

PE32PlusHeader.Fields.SizeOfCode = {name="SizeOfCode", basetype="uint32_t", bitoffset= 32, sizeinbits = 32}

function PE32PlusHeader:set_SizeOfInitializedData(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function PE32PlusHeader:get_SizeOfInitializedData()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

PE32PlusHeader.Fields.SizeOfInitializedData = {name="SizeOfInitializedData", basetype="uint32_t", bitoffset= 64, sizeinbits = 32}

function PE32PlusHeader:set_SizeOfUninitializedData(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function PE32PlusHeader:get_SizeOfUninitializedData()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

PE32PlusHeader.Fields.SizeOfUninitializedData = {name="SizeOfUninitializedData", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function PE32PlusHeader:set_AddressOfEntryPoint(value)
	setbitstobytes(self.DataPtr, 128, 32, value);
	return self
end

function PE32PlusHeader:get_AddressOfEntryPoint()
	return getbitsfrombytes(self.DataPtr, 128, 32);
end

PE32PlusHeader.Fields.AddressOfEntryPoint = {name="AddressOfEntryPoint", basetype="uint32_t", bitoffset= 128, sizeinbits = 32}

function PE32PlusHeader:set_BaseOfCode(value)
	setbitstobytes(self.DataPtr, 160, 32, value);
	return self
end

function PE32PlusHeader:get_BaseOfCode()
	return getbitsfrombytes(self.DataPtr, 160, 32);
end

PE32PlusHeader.Fields.BaseOfCode = {name="BaseOfCode", basetype="uint32_t", bitoffset= 160, sizeinbits = 32}

function PE32PlusHeader:set_ImageBase(value)
	setbitstobytes(self.DataPtr, 192, 64, value);
	return self
end

function PE32PlusHeader:get_ImageBase()
	return getbitsfrombytes(self.DataPtr, 192, 64);
end

PE32PlusHeader.Fields.ImageBase = {name="ImageBase", basetype="uint64_t", bitoffset= 192, sizeinbits = 64}

function PE32PlusHeader:set_SectionAlignment(value)
	setbitstobytes(self.DataPtr, 256, 32, value);
	return self
end

function PE32PlusHeader:get_SectionAlignment()
	return getbitsfrombytes(self.DataPtr, 256, 32);
end

PE32PlusHeader.Fields.SectionAlignment = {name="SectionAlignment", basetype="uint32_t", bitoffset= 256, sizeinbits = 32}

function PE32PlusHeader:set_FileAlignment(value)
	setbitstobytes(self.DataPtr, 288, 32, value);
	return self
end

function PE32PlusHeader:get_FileAlignment()
	return getbitsfrombytes(self.DataPtr, 288, 32);
end

PE32PlusHeader.Fields.FileAlignment = {name="FileAlignment", basetype="uint32_t", bitoffset= 288, sizeinbits = 32}

function PE32PlusHeader:set_MajorOperatingSystemVersion(value)
	setbitstobytes(self.DataPtr, 320, 16, value);
	return self
end

function PE32PlusHeader:get_MajorOperatingSystemVersion()
	return getbitsfrombytes(self.DataPtr, 320, 16);
end

PE32PlusHeader.Fields.MajorOperatingSystemVersion = {name="MajorOperatingSystemVersion", basetype="uint16_t", bitoffset= 320, sizeinbits = 16}

function PE32PlusHeader:set_MinorOperatingSystemVersion(value)
	setbitstobytes(self.DataPtr, 336, 16, value);
	return self
end

function PE32PlusHeader:get_MinorOperatingSystemVersion()
	return getbitsfrombytes(self.DataPtr, 336, 16);
end

PE32PlusHeader.Fields.MinorOperatingSystemVersion = {name="MinorOperatingSystemVersion", basetype="uint16_t", bitoffset= 336, sizeinbits = 16}

function PE32PlusHeader:set_MajorImageVersion(value)
	setbitstobytes(self.DataPtr, 352, 16, value);
	return self
end

function PE32PlusHeader:get_MajorImageVersion()
	return getbitsfrombytes(self.DataPtr, 352, 16);
end

PE32PlusHeader.Fields.MajorImageVersion = {name="MajorImageVersion", basetype="uint16_t", bitoffset= 352, sizeinbits = 16}

function PE32PlusHeader:set_MinorImageVersion(value)
	setbitstobytes(self.DataPtr, 368, 16, value);
	return self
end

function PE32PlusHeader:get_MinorImageVersion()
	return getbitsfrombytes(self.DataPtr, 368, 16);
end

PE32PlusHeader.Fields.MinorImageVersion = {name="MinorImageVersion", basetype="uint16_t", bitoffset= 368, sizeinbits = 16}

function PE32PlusHeader:set_MajorSubsystemVersion(value)
	setbitstobytes(self.DataPtr, 384, 16, value);
	return self
end

function PE32PlusHeader:get_MajorSubsystemVersion()
	return getbitsfrombytes(self.DataPtr, 384, 16);
end

PE32PlusHeader.Fields.MajorSubsystemVersion = {name="MajorSubsystemVersion", basetype="uint16_t", bitoffset= 384, sizeinbits = 16}

function PE32PlusHeader:set_MinorSubsystemVersion(value)
	setbitstobytes(self.DataPtr, 400, 16, value);
	return self
end

function PE32PlusHeader:get_MinorSubsystemVersion()
	return getbitsfrombytes(self.DataPtr, 400, 16);
end

PE32PlusHeader.Fields.MinorSubsystemVersion = {name="MinorSubsystemVersion", basetype="uint16_t", bitoffset= 400, sizeinbits = 16}

function PE32PlusHeader:set_Win32VersionValue(value)
	setbitstobytes(self.DataPtr, 416, 32, value);
	return self
end

function PE32PlusHeader:get_Win32VersionValue()
	return getbitsfrombytes(self.DataPtr, 416, 32);
end

PE32PlusHeader.Fields.Win32VersionValue = {name="Win32VersionValue", basetype="uint32_t", bitoffset= 416, sizeinbits = 32}

function PE32PlusHeader:set_SizeOfImage(value)
	setbitstobytes(self.DataPtr, 448, 32, value);
	return self
end

function PE32PlusHeader:get_SizeOfImage()
	return getbitsfrombytes(self.DataPtr, 448, 32);
end

PE32PlusHeader.Fields.SizeOfImage = {name="SizeOfImage", basetype="uint32_t", bitoffset= 448, sizeinbits = 32}

function PE32PlusHeader:set_SizeOfHeaders(value)
	setbitstobytes(self.DataPtr, 480, 32, value);
	return self
end

function PE32PlusHeader:get_SizeOfHeaders()
	return getbitsfrombytes(self.DataPtr, 480, 32);
end

PE32PlusHeader.Fields.SizeOfHeaders = {name="SizeOfHeaders", basetype="uint32_t", bitoffset= 480, sizeinbits = 32}

function PE32PlusHeader:set_CheckSum(value)
	setbitstobytes(self.DataPtr, 512, 32, value);
	return self
end

function PE32PlusHeader:get_CheckSum()
	return getbitsfrombytes(self.DataPtr, 512, 32);
end

PE32PlusHeader.Fields.CheckSum = {name="CheckSum", basetype="uint32_t", bitoffset= 512, sizeinbits = 32}

function PE32PlusHeader:set_Subsystem(value)
	setbitstobytes(self.DataPtr, 544, 16, value);
	return self
end

function PE32PlusHeader:get_Subsystem()
	return getbitsfrombytes(self.DataPtr, 544, 16);
end

PE32PlusHeader.Fields.Subsystem = {name="Subsystem", basetype="uint16_t", bitoffset= 544, sizeinbits = 16}

function PE32PlusHeader:set_DllCharacteristics(value)
	setbitstobytes(self.DataPtr, 560, 16, value);
	return self
end

function PE32PlusHeader:get_DllCharacteristics()
	return getbitsfrombytes(self.DataPtr, 560, 16);
end

PE32PlusHeader.Fields.DllCharacteristics = {name="DllCharacteristics", basetype="uint16_t", bitoffset= 560, sizeinbits = 16}

function PE32PlusHeader:set_SizeOfStackReserve(value)
	setbitstobytes(self.DataPtr, 576, 64, value);
	return self
end

function PE32PlusHeader:get_SizeOfStackReserve()
	return getbitsfrombytes(self.DataPtr, 576, 64);
end

PE32PlusHeader.Fields.SizeOfStackReserve = {name="SizeOfStackReserve", basetype="uint64_t", bitoffset= 576, sizeinbits = 64}

function PE32PlusHeader:set_SizeOfStackCommit(value)
	setbitstobytes(self.DataPtr, 640, 64, value);
	return self
end

function PE32PlusHeader:get_SizeOfStackCommit()
	return getbitsfrombytes(self.DataPtr, 640, 64);
end

PE32PlusHeader.Fields.SizeOfStackCommit = {name="SizeOfStackCommit", basetype="uint64_t", bitoffset= 640, sizeinbits = 64}

function PE32PlusHeader:set_SizeOfHeapReserve(value)
	setbitstobytes(self.DataPtr, 704, 64, value);
	return self
end

function PE32PlusHeader:get_SizeOfHeapReserve()
	return getbitsfrombytes(self.DataPtr, 704, 64);
end

PE32PlusHeader.Fields.SizeOfHeapReserve = {name="SizeOfHeapReserve", basetype="uint64_t", bitoffset= 704, sizeinbits = 64}

function PE32PlusHeader:set_SizeOfHeapCommit(value)
	setbitstobytes(self.DataPtr, 768, 64, value);
	return self
end

function PE32PlusHeader:get_SizeOfHeapCommit()
	return getbitsfrombytes(self.DataPtr, 768, 64);
end

PE32PlusHeader.Fields.SizeOfHeapCommit = {name="SizeOfHeapCommit", basetype="uint64_t", bitoffset= 768, sizeinbits = 64}

function PE32PlusHeader:set_LoaderFlags(value)
	setbitstobytes(self.DataPtr, 832, 32, value);
	return self
end

function PE32PlusHeader:get_LoaderFlags()
	return getbitsfrombytes(self.DataPtr, 832, 32);
end

PE32PlusHeader.Fields.LoaderFlags = {name="LoaderFlags", basetype="uint32_t", bitoffset= 832, sizeinbits = 32}

function PE32PlusHeader:set_NumberOfRvaAndSizes(value)
	setbitstobytes(self.DataPtr, 864, 32, value);
	return self
end

function PE32PlusHeader:get_NumberOfRvaAndSizes()
	return getbitsfrombytes(self.DataPtr, 864, 32);
end

PE32PlusHeader.Fields.NumberOfRvaAndSizes = {name="NumberOfRvaAndSizes", basetype="uint32_t", bitoffset= 864, sizeinbits = 32}

function PE32PlusHeader:set_ExportTable(value)
	setbitstobytes(self.DataPtr, 896, 64, value);
	return self
end

function PE32PlusHeader:get_ExportTable()
	local byteoffset = 896/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.ExportTable = {name="ExportTable", basetype="uint8_t", bitoffset= 896, sizeinbits = 64}

function PE32PlusHeader:set_ImportTable(value)
	setbitstobytes(self.DataPtr, 960, 64, value);
	return self
end

function PE32PlusHeader:get_ImportTable()
	local byteoffset = 960/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.ImportTable = {name="ImportTable", basetype="uint8_t", bitoffset= 960, sizeinbits = 64}

function PE32PlusHeader:set_ResourceTable(value)
	setbitstobytes(self.DataPtr, 1024, 64, value);
	return self
end

function PE32PlusHeader:get_ResourceTable()
	local byteoffset = 1024/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.ResourceTable = {name="ResourceTable", basetype="uint8_t", bitoffset= 1024, sizeinbits = 64}

function PE32PlusHeader:set_ExceptionTable(value)
	setbitstobytes(self.DataPtr, 1088, 64, value);
	return self
end

function PE32PlusHeader:get_ExceptionTable()
	local byteoffset = 1088/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.ExceptionTable = {name="ExceptionTable", basetype="uint8_t", bitoffset= 1088, sizeinbits = 64}

function PE32PlusHeader:set_CertificateTable(value)
	setbitstobytes(self.DataPtr, 1152, 64, value);
	return self
end

function PE32PlusHeader:get_CertificateTable()
	local byteoffset = 1152/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.CertificateTable = {name="CertificateTable", basetype="uint8_t", bitoffset= 1152, sizeinbits = 64}

function PE32PlusHeader:set_BaseRelocationTable(value)
	setbitstobytes(self.DataPtr, 1216, 64, value);
	return self
end

function PE32PlusHeader:get_BaseRelocationTable()
	local byteoffset = 1216/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.BaseRelocationTable = {name="BaseRelocationTable", basetype="uint8_t", bitoffset= 1216, sizeinbits = 64}

function PE32PlusHeader:set_Debug(value)
	setbitstobytes(self.DataPtr, 1280, 64, value);
	return self
end

function PE32PlusHeader:get_Debug()
	local byteoffset = 1280/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.Debug = {name="Debug", basetype="uint8_t", bitoffset= 1280, sizeinbits = 64}

function PE32PlusHeader:set_Architecture(value)
	setbitstobytes(self.DataPtr, 1344, 64, value);
	return self
end

function PE32PlusHeader:get_Architecture()
	local byteoffset = 1344/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.Architecture = {name="Architecture", basetype="uint8_t", bitoffset= 1344, sizeinbits = 64}

function PE32PlusHeader:set_GlobalPtr(value)
	setbitstobytes(self.DataPtr, 1408, 64, value);
	return self
end

function PE32PlusHeader:get_GlobalPtr()
	local byteoffset = 1408/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.GlobalPtr = {name="GlobalPtr", basetype="uint8_t", bitoffset= 1408, sizeinbits = 64}

function PE32PlusHeader:set_TLSTable(value)
	setbitstobytes(self.DataPtr, 1472, 64, value);
	return self
end

function PE32PlusHeader:get_TLSTable()
	local byteoffset = 1472/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.TLSTable = {name="TLSTable", basetype="uint8_t", bitoffset= 1472, sizeinbits = 64}

function PE32PlusHeader:set_LoadConfigTable(value)
	setbitstobytes(self.DataPtr, 1536, 64, value);
	return self
end

function PE32PlusHeader:get_LoadConfigTable()
	local byteoffset = 1536/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.LoadConfigTable = {name="LoadConfigTable", basetype="uint8_t", bitoffset= 1536, sizeinbits = 64}

function PE32PlusHeader:set_BoundImport(value)
	setbitstobytes(self.DataPtr, 1600, 64, value);
	return self
end

function PE32PlusHeader:get_BoundImport()
	local byteoffset = 1600/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.BoundImport = {name="BoundImport", basetype="uint8_t", bitoffset= 1600, sizeinbits = 64}

function PE32PlusHeader:set_IAT(value)
	setbitstobytes(self.DataPtr, 1664, 64, value);
	return self
end

function PE32PlusHeader:get_IAT()
	local byteoffset = 1664/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.IAT = {name="IAT", basetype="uint8_t", bitoffset= 1664, sizeinbits = 64}

function PE32PlusHeader:set_DelayImportDescriptor(value)
	setbitstobytes(self.DataPtr, 1728, 64, value);
	return self
end

function PE32PlusHeader:get_DelayImportDescriptor()
	local byteoffset = 1728/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.DelayImportDescriptor = {name="DelayImportDescriptor", basetype="uint8_t", bitoffset= 1728, sizeinbits = 64}

function PE32PlusHeader:set_CLRRuntimeHeader(value)
	setbitstobytes(self.DataPtr, 1792, 64, value);
	return self
end

function PE32PlusHeader:get_CLRRuntimeHeader()
	local byteoffset = 1792/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.CLRRuntimeHeader = {name="CLRRuntimeHeader", basetype="uint8_t", bitoffset= 1792, sizeinbits = 64}

function PE32PlusHeader:set_Reserved(value)
	setbitstobytes(self.DataPtr, 1856, 64, value);
	return self
end

function PE32PlusHeader:get_Reserved()
	local byteoffset = 1856/8
	local ptr = ffi.cast("uint8_t *",self.DataPtr + byteoffset)
	return ptr, 8;
end

PE32PlusHeader.Fields.Reserved = {name="Reserved", basetype="uint8_t", bitoffset= 1856, sizeinbits = 64}


class.COFF()

COFF.Fields = {}

function COFF:_init(...)
	local args={...}

    self.ClassSize = 20

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[20]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function COFF:SetFieldValue(fieldname, value)
    local field = COFF.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function COFF:set_Machine(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function COFF:get_Machine()
	return getbitsfrombytes(self.DataPtr, 0, 16);
end

COFF.Fields.Machine = {name="Machine", basetype="uint16_t", bitoffset= 0, sizeinbits = 16}

function COFF:set_NumberOfSections(value)
	setbitstobytes(self.DataPtr, 16, 16, value);
	return self
end

function COFF:get_NumberOfSections()
	return getbitsfrombytes(self.DataPtr, 16, 16);
end

COFF.Fields.NumberOfSections = {name="NumberOfSections", basetype="uint16_t", bitoffset= 16, sizeinbits = 16}

function COFF:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function COFF:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

COFF.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="uint32_t", bitoffset= 32, sizeinbits = 32}

function COFF:set_PointerToSymbolTable(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function COFF:get_PointerToSymbolTable()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

COFF.Fields.PointerToSymbolTable = {name="PointerToSymbolTable", basetype="uint32_t", bitoffset= 64, sizeinbits = 32}

function COFF:set_NumberOfSymbols(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function COFF:get_NumberOfSymbols()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

COFF.Fields.NumberOfSymbols = {name="NumberOfSymbols", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function COFF:set_SizeOfOptionalHeader(value)
	setbitstobytes(self.DataPtr, 128, 16, value);
	return self
end

function COFF:get_SizeOfOptionalHeader()
	return getbitsfrombytes(self.DataPtr, 128, 16);
end

COFF.Fields.SizeOfOptionalHeader = {name="SizeOfOptionalHeader", basetype="uint16_t", bitoffset= 128, sizeinbits = 16}

function COFF:set_Characteristics(value)
	setbitstobytes(self.DataPtr, 144, 16, value);
	return self
end

function COFF:get_Characteristics()
	return getbitsfrombytes(self.DataPtr, 144, 16);
end

COFF.Fields.Characteristics = {name="Characteristics", basetype="uint16_t", bitoffset= 144, sizeinbits = 16}


class.IMAGE_DOS_HEADER()

IMAGE_DOS_HEADER.Fields = {}

function IMAGE_DOS_HEADER:_init(...)
	local args={...}

    self.ClassSize = 64

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[64]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_DOS_HEADER:SetFieldValue(fieldname, value)
    local field = IMAGE_DOS_HEADER.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_DOS_HEADER:set_e_magic(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_magic()
	local byteoffset = 0/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)
	return ptr, 2;
end

IMAGE_DOS_HEADER.Fields.e_magic = {name="e_magic", basetype="char", bitoffset= 0, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_cblp(value)
	setbitstobytes(self.DataPtr, 16, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_cblp()
	return getbitsfrombytes(self.DataPtr, 16, 16);
end

IMAGE_DOS_HEADER.Fields.e_cblp = {name="e_cblp", basetype="uint16_t", bitoffset= 16, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_cp(value)
	setbitstobytes(self.DataPtr, 32, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_cp()
	return getbitsfrombytes(self.DataPtr, 32, 16);
end

IMAGE_DOS_HEADER.Fields.e_cp = {name="e_cp", basetype="uint16_t", bitoffset= 32, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_crlc(value)
	setbitstobytes(self.DataPtr, 48, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_crlc()
	return getbitsfrombytes(self.DataPtr, 48, 16);
end

IMAGE_DOS_HEADER.Fields.e_crlc = {name="e_crlc", basetype="uint16_t", bitoffset= 48, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_cparhdr(value)
	setbitstobytes(self.DataPtr, 64, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_cparhdr()
	return getbitsfrombytes(self.DataPtr, 64, 16);
end

IMAGE_DOS_HEADER.Fields.e_cparhdr = {name="e_cparhdr", basetype="uint16_t", bitoffset= 64, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_minalloc(value)
	setbitstobytes(self.DataPtr, 80, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_minalloc()
	return getbitsfrombytes(self.DataPtr, 80, 16);
end

IMAGE_DOS_HEADER.Fields.e_minalloc = {name="e_minalloc", basetype="uint16_t", bitoffset= 80, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_maxalloc(value)
	setbitstobytes(self.DataPtr, 96, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_maxalloc()
	return getbitsfrombytes(self.DataPtr, 96, 16);
end

IMAGE_DOS_HEADER.Fields.e_maxalloc = {name="e_maxalloc", basetype="uint16_t", bitoffset= 96, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_ss(value)
	setbitstobytes(self.DataPtr, 112, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_ss()
	return getbitsfrombytes(self.DataPtr, 112, 16);
end

IMAGE_DOS_HEADER.Fields.e_ss = {name="e_ss", basetype="uint16_t", bitoffset= 112, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_sp(value)
	setbitstobytes(self.DataPtr, 128, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_sp()
	return getbitsfrombytes(self.DataPtr, 128, 16);
end

IMAGE_DOS_HEADER.Fields.e_sp = {name="e_sp", basetype="uint16_t", bitoffset= 128, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_csum(value)
	setbitstobytes(self.DataPtr, 144, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_csum()
	return getbitsfrombytes(self.DataPtr, 144, 16);
end

IMAGE_DOS_HEADER.Fields.e_csum = {name="e_csum", basetype="uint16_t", bitoffset= 144, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_ip(value)
	setbitstobytes(self.DataPtr, 160, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_ip()
	return getbitsfrombytes(self.DataPtr, 160, 16);
end

IMAGE_DOS_HEADER.Fields.e_ip = {name="e_ip", basetype="uint16_t", bitoffset= 160, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_cs(value)
	setbitstobytes(self.DataPtr, 176, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_cs()
	return getbitsfrombytes(self.DataPtr, 176, 16);
end

IMAGE_DOS_HEADER.Fields.e_cs = {name="e_cs", basetype="uint16_t", bitoffset= 176, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_lfarlc(value)
	setbitstobytes(self.DataPtr, 192, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_lfarlc()
	return getbitsfrombytes(self.DataPtr, 192, 16);
end

IMAGE_DOS_HEADER.Fields.e_lfarlc = {name="e_lfarlc", basetype="uint16_t", bitoffset= 192, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_ovno(value)
	setbitstobytes(self.DataPtr, 208, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_ovno()
	return getbitsfrombytes(self.DataPtr, 208, 16);
end

IMAGE_DOS_HEADER.Fields.e_ovno = {name="e_ovno", basetype="uint16_t", bitoffset= 208, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_res(value)
	setbitstobytes(self.DataPtr, 224, 64, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_res()
	local byteoffset = 224/8
	local ptr = ffi.cast("uint16_t *",self.DataPtr + byteoffset)
	return ptr, 4;
end

IMAGE_DOS_HEADER.Fields.e_res = {name="e_res", basetype="uint16_t", bitoffset= 224, sizeinbits = 64}

function IMAGE_DOS_HEADER:set_e_oemid(value)
	setbitstobytes(self.DataPtr, 288, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_oemid()
	return getbitsfrombytes(self.DataPtr, 288, 16);
end

IMAGE_DOS_HEADER.Fields.e_oemid = {name="e_oemid", basetype="uint16_t", bitoffset= 288, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_oeminfo(value)
	setbitstobytes(self.DataPtr, 304, 16, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_oeminfo()
	return getbitsfrombytes(self.DataPtr, 304, 16);
end

IMAGE_DOS_HEADER.Fields.e_oeminfo = {name="e_oeminfo", basetype="uint16_t", bitoffset= 304, sizeinbits = 16}

function IMAGE_DOS_HEADER:set_e_res2(value)
	setbitstobytes(self.DataPtr, 320, 160, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_res2()
	local byteoffset = 320/8
	local ptr = ffi.cast("uint16_t *",self.DataPtr + byteoffset)
	return ptr, 10;
end

IMAGE_DOS_HEADER.Fields.e_res2 = {name="e_res2", basetype="uint16_t", bitoffset= 320, sizeinbits = 160}

function IMAGE_DOS_HEADER:set_e_lfanew(value)
	setbitstobytes(self.DataPtr, 480, 32, value);
	return self
end

function IMAGE_DOS_HEADER:get_e_lfanew()
	return getbitsfrombytes(self.DataPtr, 480, 32);
end

IMAGE_DOS_HEADER.Fields.e_lfanew = {name="e_lfanew", basetype="uint32_t", bitoffset= 480, sizeinbits = 32}


class.IMAGE_IMPORT_BY_NAME()

IMAGE_IMPORT_BY_NAME.Fields = {}

function IMAGE_IMPORT_BY_NAME:_init(...)
	local args={...}

    self.ClassSize = 3

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[3]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_IMPORT_BY_NAME:SetFieldValue(fieldname, value)
    local field = IMAGE_IMPORT_BY_NAME.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_IMPORT_BY_NAME:set_Hint(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function IMAGE_IMPORT_BY_NAME:get_Hint()
	return getbitsfrombytes(self.DataPtr, 0, 16);
end

IMAGE_IMPORT_BY_NAME.Fields.Hint = {name="Hint", basetype="uint16_t", bitoffset= 0, sizeinbits = 16}

function IMAGE_IMPORT_BY_NAME:set_Name(value)
	local maxbytes = math.min(1-1, string.len(value))
	local byteoffset = 16/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)

	for i=0,maxbytes-1 do
		ptr[i] = string.byte(value:sub(i+1,i+1))
	end
	ptr[maxbytes+1]= 0
	return self
end

function IMAGE_IMPORT_BY_NAME:get_Name()
	local byteoffset = 16/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)
	return ffi.string(ptr);
end

IMAGE_IMPORT_BY_NAME.Fields.Name = {name="Name", basetype="char", bitoffset= 16, sizeinbits = 8}


class.MAGIC2()

MAGIC2.Fields = {}

function MAGIC2:_init(...)
	local args={...}

    self.ClassSize = 2

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[2]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function MAGIC2:SetFieldValue(fieldname, value)
    local field = MAGIC2.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function MAGIC2:set_Signature(value)
	setbitstobytes(self.DataPtr, 0, 16, value);
	return self
end

function MAGIC2:get_Signature()
	local byteoffset = 0/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)
	return ptr, 2;
end

MAGIC2.Fields.Signature = {name="Signature", basetype="char", bitoffset= 0, sizeinbits = 16}


class.IMAGE_THUNK_DATA()

IMAGE_THUNK_DATA.Fields = {}

function IMAGE_THUNK_DATA:_init(...)
	local args={...}

    self.ClassSize = 4

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[4]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_THUNK_DATA:SetFieldValue(fieldname, value)
    local field = IMAGE_THUNK_DATA.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_THUNK_DATA:set_Data(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_THUNK_DATA:get_Data()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_THUNK_DATA.Fields.Data = {name="Data", basetype="uint32_t", bitoffset= 0, sizeinbits = 32}


class.IMAGE_IMPORT_DESCRIPTOR()

IMAGE_IMPORT_DESCRIPTOR.Fields = {}

function IMAGE_IMPORT_DESCRIPTOR:_init(...)
	local args={...}

    self.ClassSize = 20

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[20]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_IMPORT_DESCRIPTOR:SetFieldValue(fieldname, value)
    local field = IMAGE_IMPORT_DESCRIPTOR.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_IMPORT_DESCRIPTOR:set_OriginalFirstThunk(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_IMPORT_DESCRIPTOR:get_OriginalFirstThunk()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_IMPORT_DESCRIPTOR.Fields.OriginalFirstThunk = {name="OriginalFirstThunk", basetype="uint32_t", bitoffset= 0, sizeinbits = 32}

function IMAGE_IMPORT_DESCRIPTOR:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function IMAGE_IMPORT_DESCRIPTOR:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

IMAGE_IMPORT_DESCRIPTOR.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="int32_t", bitoffset= 32, sizeinbits = 32}

function IMAGE_IMPORT_DESCRIPTOR:set_ForwarderChain(value)
	setbitstobytes(self.DataPtr, 64, 32, value);
	return self
end

function IMAGE_IMPORT_DESCRIPTOR:get_ForwarderChain()
	return getbitsfrombytes(self.DataPtr, 64, 32);
end

IMAGE_IMPORT_DESCRIPTOR.Fields.ForwarderChain = {name="ForwarderChain", basetype="int32_t", bitoffset= 64, sizeinbits = 32}

function IMAGE_IMPORT_DESCRIPTOR:set_Name(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function IMAGE_IMPORT_DESCRIPTOR:get_Name()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

IMAGE_IMPORT_DESCRIPTOR.Fields.Name = {name="Name", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function IMAGE_IMPORT_DESCRIPTOR:set_FirstThunk(value)
	setbitstobytes(self.DataPtr, 128, 32, value);
	return self
end

function IMAGE_IMPORT_DESCRIPTOR:get_FirstThunk()
	return getbitsfrombytes(self.DataPtr, 128, 32);
end

IMAGE_IMPORT_DESCRIPTOR.Fields.FirstThunk = {name="FirstThunk", basetype="uint32_t", bitoffset= 128, sizeinbits = 32}


class.MAGIC4()

MAGIC4.Fields = {}

function MAGIC4:_init(...)
	local args={...}

    self.ClassSize = 4

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[4]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function MAGIC4:SetFieldValue(fieldname, value)
    local field = MAGIC4.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function MAGIC4:set_Signature(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function MAGIC4:get_Signature()
	local byteoffset = 0/8
	local ptr = ffi.cast("char *",self.DataPtr + byteoffset)
	return ptr, 4;
end

MAGIC4.Fields.Signature = {name="Signature", basetype="char", bitoffset= 0, sizeinbits = 32}


class.IMAGE_EXPORT_DIRECTORY()

IMAGE_EXPORT_DIRECTORY.Fields = {}

function IMAGE_EXPORT_DIRECTORY:_init(...)
	local args={...}

    self.ClassSize = 40

	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new("uint8_t[40]")
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	
	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function IMAGE_EXPORT_DIRECTORY:SetFieldValue(fieldname, value)
    local field = IMAGE_EXPORT_DIRECTORY.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

function IMAGE_EXPORT_DIRECTORY:set_Characteristics(value)
	setbitstobytes(self.DataPtr, 0, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_Characteristics()
	return getbitsfrombytes(self.DataPtr, 0, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.Characteristics = {name="Characteristics", basetype="uint32_t", bitoffset= 0, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_TimeDateStamp(value)
	setbitstobytes(self.DataPtr, 32, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_TimeDateStamp()
	return getbitsfrombytes(self.DataPtr, 32, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.TimeDateStamp = {name="TimeDateStamp", basetype="uint32_t", bitoffset= 32, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_MajorVersion(value)
	setbitstobytes(self.DataPtr, 64, 16, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_MajorVersion()
	return getbitsfrombytes(self.DataPtr, 64, 16);
end

IMAGE_EXPORT_DIRECTORY.Fields.MajorVersion = {name="MajorVersion", basetype="uint16_t", bitoffset= 64, sizeinbits = 16}

function IMAGE_EXPORT_DIRECTORY:set_MinorVersion(value)
	setbitstobytes(self.DataPtr, 80, 16, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_MinorVersion()
	return getbitsfrombytes(self.DataPtr, 80, 16);
end

IMAGE_EXPORT_DIRECTORY.Fields.MinorVersion = {name="MinorVersion", basetype="uint16_t", bitoffset= 80, sizeinbits = 16}

function IMAGE_EXPORT_DIRECTORY:set_Name(value)
	setbitstobytes(self.DataPtr, 96, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_Name()
	return getbitsfrombytes(self.DataPtr, 96, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.Name = {name="Name", basetype="uint32_t", bitoffset= 96, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_Base(value)
	setbitstobytes(self.DataPtr, 128, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_Base()
	return getbitsfrombytes(self.DataPtr, 128, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.Base = {name="Base", basetype="uint32_t", bitoffset= 128, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_NumberOfFunctions(value)
	setbitstobytes(self.DataPtr, 160, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_NumberOfFunctions()
	return getbitsfrombytes(self.DataPtr, 160, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.NumberOfFunctions = {name="NumberOfFunctions", basetype="uint32_t", bitoffset= 160, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_NumberOfNames(value)
	setbitstobytes(self.DataPtr, 192, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_NumberOfNames()
	return getbitsfrombytes(self.DataPtr, 192, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.NumberOfNames = {name="NumberOfNames", basetype="uint32_t", bitoffset= 192, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_AddressOfFunctions(value)
	setbitstobytes(self.DataPtr, 224, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_AddressOfFunctions()
	return getbitsfrombytes(self.DataPtr, 224, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.AddressOfFunctions = {name="AddressOfFunctions", basetype="uint32_t", bitoffset= 224, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_AddressOfNames(value)
	setbitstobytes(self.DataPtr, 256, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_AddressOfNames()
	return getbitsfrombytes(self.DataPtr, 256, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.AddressOfNames = {name="AddressOfNames", basetype="uint32_t", bitoffset= 256, sizeinbits = 32}

function IMAGE_EXPORT_DIRECTORY:set_AddressOfNameOrdinals(value)
	setbitstobytes(self.DataPtr, 288, 32, value);
	return self
end

function IMAGE_EXPORT_DIRECTORY:get_AddressOfNameOrdinals()
	return getbitsfrombytes(self.DataPtr, 288, 32);
end

IMAGE_EXPORT_DIRECTORY.Fields.AddressOfNameOrdinals = {name="AddressOfNameOrdinals", basetype="uint32_t", bitoffset= 288, sizeinbits = 32}


