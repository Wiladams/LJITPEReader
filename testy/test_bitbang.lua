package.path = package.path..";../?.lua"

local bb = require("bitbang")

local function test_binarytonumber()
    local function printNumber(str)
        print(str, bb.binarytonumber(str))
    end

    print("==== test_binarytonumber ====")
    printNumber("0001")
    printNumber("0010")
    printNumber("0100")
    printNumber("1000")
    printNumber("1001")
    printNumber("1010")
    printNumber("1100")
    printNumber("1101")
    printNumber("1110")
    printNumber("1111")


end

test_binarytonumber();
