-- genstructs.lua
package.path = package.path..";../?.lua"

local peschema = require("peschema")
local ddl = require("describedata")

local function embedcode(code)
	local success, chunk = pcall(loadstring(code))
	if success then
		chunk();
	end
end

local function CreatePEStructs()
	print([[
local ffi = require('ffi')
local class = require('class')
local bitbang = require('bitbang')
bitbang();

]]);

	for k,v in pairs(peschema) do
--print(k)
		local code = ddl.CreateBufferClass(v)
		print(code);
		--embedcode(code);
	end
end

CreatePEStructs()
