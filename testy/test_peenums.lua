package.path = package.path..";../?.lua"

enums = require("pereader.peenums")

local function printValue(tableName, value)
    local key = enums[tableName][value];
    print(string.format("%18s: 0x%04x  %-36s", tableName, value, key),
    enums[tableName][key] == value);
end

printValue("MachineType", 0x14c);
printValue("DllCharacteristics", 0x40);
printValue("Subsystem", 0x1);
printValue("Characteristics", 0x2);
printValue("Characteristics", 0x2000);
