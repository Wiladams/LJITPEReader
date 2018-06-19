--[[
-- metatable for enums
-- simply provides the 'reverse lookup' in a 
-- dictionary.  Make this the metatable whenever
-- you need such functionality.
-- 
Usage:
    local myenum = enum {
        name1 = value1;
        name2 = value2;
        name3 = value3;
    }
--]]

local enum = {}
setmetatable(enum, {
    __call = function(self, ...)
        return self:create(...)
    end,
})

local enum_mt = {
    __index = function(tbl, value)
        for key, code in pairs(tbl) do
            if code == value then 
                return key;
            end
        end

        return false;
    end;
}
function enum.init(self, alist)
    setmetatable(alist, enum_mt)

    return alist;
end

function enum.create(self, alist)
    local alist = alist or {}
    return self:init(alist);
end

return enum