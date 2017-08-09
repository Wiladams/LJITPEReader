-- genstructs.lua
package.path = package.path..";../?.lua"

local peschema = require("peschema")

local function embedcode(code)
	local success, chunk = pcall(loadstring(code))
	if success then
		chunk();
	end
end

local function CreatePEEnums()
	for k,v in pairs(peschema) do
		--print(k,v)
		if v.enums then
			--print("v.enums: ", v.enums)
			for name, value in pairs(v.enums) do
				print(string.format("local %s = {", name));
				for _, enumtuple in pairs(value) do
					print(string.format("    %s = 0x%x,", enumtuple.name, enumtuple.value));
				end
				print(string.format("}\n"));
			end
		end
	end
end

CreatePEEnums()
