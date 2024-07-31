cls
set ver=10.0.22621.0
set folder=%ProgramFiles(x86)%\Windows Kits\10\Include\%ver%
.\idaclang.exe ^
-x c++  ^
-target arm64-pc-windows ^
-ferror-limit=0 ^
--idaclang-log-target ^
--idaclang-tildesc "NTAPI Win10 ARM64" ^
--idaclang-tilname "NTAPI_win10_ARM64.til" ^
-I"%folder%\cppwinrt\winrt" ^
-I"%folder%\km" ^
-I"%folder%\km\crt" ^
-I"%folder%\shared" ^
-I"%folder%\ucrt" ^
-I"%folder%\um" ^
-I"%folder%\winrt" ^
"%folder%\um\Windows.h"