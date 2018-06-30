# LJITPEReader
Various routines related to reading Windows PE format files.

On the Windows OS, there are inbuilt routines for reading information from PE files (the executabl file format for Windows).
The routines in this project replicate that inbuilt capability, but using Lua.  This allows you to read PE format files from
any platform where Lua is supported.

References
    https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
http://www.sunshine2k.de/reversing/tuts/tut_rvait.htm
