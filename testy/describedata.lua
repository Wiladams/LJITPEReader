
local ffi = require "ffi"

require "bitbang"

--[[
	A prototypical data structure contains the following:

Person = {
	name = "Person",
	fields={
		{name = "id", datatype="int32_t", status="required", ordinal=1};
		{name = "name", datatype="string", status="optional", ordinal=2};
		{name = "email", datatype="string", status="optional", ordinal=3};
	};
};

A field has these basic attributes
    name			- Name of the field.  This is optional
    datatype		- a string of a ctype, or a table of another known type
	repeating		- A count of the number of instances of this type
	status 			- Whether the field is 'optional' or 'required'
	ordinal			- The position within the data structure.  This is optional

So, the description of the field itself would be:

Field = {
	name = "field",
	fields = {
		{name = "name", datatype = "string", required = false, ordinal =1};
		{name = "datatype", datatype = "string", required = true, ordinal =2};
		{name = "repeating", datatype = "int32_t", required = false, ordinal =3};
		{name = "required", datatype = "bool", required = false, ordinal =4};
		{name = "ordinal", datatype = "int32_t", required = false, ordinal =5};
	};
};


--]]



local function BitOffsetsFromTypeInfo(desc)
	local bitoffset = 0;
	local nbits = 0;

	local repeating = 1

	for _,field in ipairs(desc.fields) do
		repeating = field.repeating or 1

		if field.offset then
			bitoffset = field.offset * 8
		end

		field.bitoffset = bitoffset


		if field.subtype == "bit" then
			nbits = repeating
		else
			nbits = (ffi.sizeof(field.basetype)*8)*repeating
		end

		field.sizeinbits = nbits

		bitoffset = bitoffset + nbits
	end

	return desc.fields, math.ceil(bitoffset/8);
end

local function CStructFieldFromTypeInfo(field)
	if not field.basetype then return nil end;

	local repeating = field.repeating or 1

	if field.subtype == "bit" then
		return string.format("%s %s : %d;", field.basetype, field.name, repeating);
	end

	if repeating > 1 then
		return string.format("%s %s[%d];",field.basetype, field.name, repeating);
	end

	if field.basetype == "string" then
		return string.format("char* %s;", field.name);
	end

	return string.format("%s %s;", field.basetype, field.name);
end

local function CStructFromTypeInfo(desc)
	local strucstr = {};

	table.insert(strucstr, string.format("typedef struct %s {\n", desc.name));
	for _,field in ipairs(desc.fields) do
		table.insert(strucstr, string.format("\t%s\n", CStructFieldFromTypeInfo(field)));
	end
	table.insert(strucstr, string.format("} %s;\n", desc.name));

	return table.concat(strucstr);
end





local FieldSerializerFuncs = {
	int8_t = {reader = "readByte", writer= "writeByte"},
	uint8_t = {reader = "readByte", writer= "writeByte"},
	bool = {reader = "readByte", writer= "writeByte"},
	char = {reader= "readByte", writer= "writeByte"},
	int16_t = {reader= "readInt16", writer= "writeInt16"},
	uint16_t = {reader= "readUInt16", writer= "writeUInt16"},
	int32_t = {reader= "readInt32", writer= "writeInt32"},
	uint32_t = {reader= "readUInt32", writer= "writeUInt32"},
	single = {reader= "readSingle", writer= "writeSingle"},
	double = {reader= "readDouble", writer= "writeDouble"},
	string = {reader= "readString", writer= "writeString"},
};

local function CFieldSerializer(field)
	local entry = FieldSerializerFuncs[field.basetype]

	if not entry then return nil end

	local retValue = "stream:"..entry.writer.."(value."..field.name..");\n";
	return retValue;
end

local function CFieldDeSerializer(field)
	local entry = FieldSerializerFuncs[field.basetype]

	if not entry then return nil end

	local retValue = "value."..field.name.." = stream:"..entry.reader.."();\n";
	return retValue;
end

local function CTypeSerializer(info)
	local strtbl = {}

	table.insert(strtbl, string.format("function write_%s_ToStream(stream, value)\n", info.name));
	for i,field in ipairs(info.fields) do
	    table.insert(strtbl,'\t'..CFieldSerializer(field));
	end
	table.insert(strtbl, string.format("end"));

	return table.concat(strtbl);
end

local function CTypeDeSerializer(info)
	local strtbl = {}

	table.insert(strtbl, string.format("function read_%s_FromStream(stream, value)\n", info.name));
	for i,field in ipairs(info.fields) do
	    table.insert(strtbl,'\t'..CFieldDeSerializer(field));
	end
	table.insert(strtbl, string.format("end"));

	return table.concat(strtbl);
end


--[[
Generate code that looks like this:

class.ClassName()

function ClassName:_init(buff)
    self.Buffer = buff
end

-- For each field
function get_FieldName()
	return getbitsfrombytes(self.Buffer, offset, size);
end

function set_FieldName(value)
	setbitstobytes(self.Buffer, offset, size, value);
end

--]]

local function GetPointerForField(dataptr, field)
	local byteoffset = field.bitoffset/8
	local ptr = ffi.cast(field.basetype.." *",dataptr + byteoffset)

	return ptr
end

local function CreateClassFieldWriter(field, classname)
	local str = nil
	local repeating = field.repeating or 1

	if field.subtype == "bit" then
		str = string.format(
[[
function %s:set_%s(value)
	setbitstobytes(self.DataPtr, %d, %d, value);
	return self
end
]], classname, field.name, field.bitoffset, field.sizeinbits);
		return str;
	end

	if field.subtype == "string" then
		str = string.format(
[[
function %s:set_%s(value)
	local maxbytes = math.min(%d-1, string.len(value))
	local byteoffset = %d/8
	local ptr = ffi.cast("%s *",self.DataPtr + byteoffset)

	for i=0,maxbytes-1 do
		ptr[i] = string.byte(value:sub(i+1,i+1))
	end
	ptr[maxbytes+1]= 0
	return self
end
]], classname, field.name, repeating, field.bitoffset, field.basetype);
		return str;
	end


	str = string.format(
[[
function %s:set_%s(value)
	setbitstobytes(self.DataPtr, %d, %d, value);
	return self
end
]], classname, field.name, field.bitoffset, field.sizeinbits);

	return str;
end

local function CreateClassFieldReader(field, classname)
	local str = nil
	local repeating = field.repeating or 1

	if field.subtype == "bit" then
		str = string.format([[
function %s:get_%s()
	return getbitsfrombytes(self.DataPtr, %d, %d);
end
]], classname, field.name, field.bitoffset, repeating);

		return str
	end

	if field.subtype == "string" then
		str = string.format([[
function %s:get_%s()
	local byteoffset = %d/8
	local ptr = ffi.cast("%s *",self.DataPtr + byteoffset)
	return ffi.string(ptr);
end
]], classname, field.name, field.bitoffset, field.basetype, repeating);

		return str

	end

	if repeating > 1 then
		str = string.format([[
function %s:get_%s()
	local byteoffset = %d/8
	local ptr = ffi.cast("%s *",self.DataPtr + byteoffset)
	return ptr, %d;
end
]], classname, field.name, field.bitoffset, field.basetype, repeating);

		return str
	else
		str = string.format([[
function %s:get_%s()
	return getbitsfrombytes(self.DataPtr, %d, %d);
end
]], classname, field.name, field.bitoffset, field.sizeinbits);
		return str
	end

end

local function AppendClassField(field, classname)
	local str

	if field.default then
		str = string.format(classname..[[.Fields.]]..field.name..[[ = {name="]]..field.name..[[", basetype="]]..field.basetype..[[", bitoffset= ]]..field.bitoffset..[[, sizeinbits = ]]..field.sizeinbits..[[, default= ]]..field.default..[[}]])
	else
		str = string.format(classname..[[.Fields.]]..field.name..[[ = {name="]]..field.name..[[", basetype="]]..field.basetype..[[", bitoffset= ]]..field.bitoffset..[[, sizeinbits = ]]..field.sizeinbits..[[}]])
	end

	return str
end



local function CreateClassDefaults(fields)
	local res = {}

	for _,field in ipairs(fields) do
		if field.default then
			local str = [[self:set_]]..field.name..[[(]]..field.default..[[)]]
			table.insert(res, str)
			table.insert(res, "\n");
		end
	end

	return table.concat(res);
end

local function SetClassValues(values)
	if not values then return "" end

	local res = {}
	local str

	for fieldname,value in pairs(values) do
		str = [[self.set_]]..fieldname..[[(self, ]]..value..[[)]]
		table.insert(res, str)
		table.insert(res,"\n")
	end

	return table.concat(res)
end

local function CreateBufferClass(desc)
	local funcs = {}

	-- first create the offsets structure
	local offsets, bytesize = BitOffsetsFromTypeInfo(desc)

	for _,field in ipairs(offsets) do
		table.insert(funcs, CreateClassFieldWriter(field, desc.name))
		table.insert(funcs, "\n");
		table.insert(funcs, CreateClassFieldReader(field, desc.name))
		table.insert(funcs, "\n");

		table.insert(funcs, AppendClassField(field, desc.name))
		table.insert(funcs, "\n\n");
	end

	local funcstr = table.concat(funcs)

	-- go through field by field and create the
	-- bit of code that will write to the buffer

	-- ]]..desc.name..[[._Fields = ]]..desc.fields..[[
	local classTemplate =
[[
class.]]..desc.name..[[()

]]..desc.name..[[.Fields = {}

function ]]..desc.name..[[:_init(...)
	local args={...}

    self.ClassSize = ]]..bytesize..[[


	-- Use passed in memory if specified
	if #args == 2 or #args == 3 then
		if type(args[1]) == "cdata" and type(args[2]) == "number" then
			self.Buffer = args[1]
			self.BufferSize = args[2]
			self.Offset = args[3] or 0
		end
	else
		-- Allocate memory ourselves
		self.Buffer = ffi.new(]]..string.format([["uint8_t[%d]"]], bytesize)..[[)
        self.BufferSize = ffi.sizeof(self.Buffer)
        self.Offset = 0
	end

	self.DataPtr = self.Buffer + self.Offset

	-- Set any default values that might exist on fields
	]]..CreateClassDefaults(desc.fields)..[[

	-- Set values if passed in
	if #args == 1 and type(args[1]) == "table" then
		for fieldname, value in pairs(args[1]) do
			self:SetFieldValue(fieldname, value);
		end
	end
end

-- Create function that can set an individual
-- field value
function ]]..desc.name..[[:SetFieldValue(fieldname, value)
    local field = ]]..desc.name..[[.Fields[fieldname]
	if field then
		setbitstobytes(self.DataPtr, field.bitoffset, field.sizeinbits, value);
	end
end

]]..funcstr..[[
]]

	return classTemplate
end


local exports = {
	CreateBufferClass = CreateBufferClass;
	CStructFromTypeInfo = CStructFromTypeInfo;
}

return exports
