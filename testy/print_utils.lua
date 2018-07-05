local cctype = require("cctype")

    -- print each line as:
    -- offset, Hex-16 digits, ASCII
local function isprintable(c)
        return c >= 0x20 and c < 0x90
end

local function printHex(ms, iterations)
    iterations = iterations or 1

    print("        Offset (h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Decoded text")
    local iteration = 0
    while iteration < iterations do
        local sentinel = ms:tell();
        local bytes = ms:readBytes(16);

        io.write(string.format("0x%016X: ", sentinel))
        
        -- write 16 hex values
        for i=0,15 do
            io.write(string.format("%02X ", bytes[i]))
        end
        
        io.write(' ')
        for i=0,15 do
            if isprintable(bytes[i]) then
                io.write(string.format("%c", bytes[i]))
            else
                io.write('.')
            end
        end

        io.write("\n")

        iteration = iteration + 1;
    end
end

return {
    printHex = printHex;
}