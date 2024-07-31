# TIL creation for NTDDK

Between [this](https://reverseengineering.stackexchange.com/questions/18669/how-to-make-type-libraries-from-windows-10-sdk-and-ddk) stack exchange post, [these](https://hex-rays.com/blog/igors-tip-of-the-week-60-type-libraries/) tips from a hex-ray blog and [this](https://blog.nviso.eu/2023/11/07/generating-ida-type-information-libraries-from-windows-type-libraries/) example blog of how to use idaclang.

For ntddk a single struct is unable to be compiled: comment out the _WHEAP_ROW_FAILURE_EVENT struct from the ntddk.h or use the [ntddk_mod.h](./ntddk_mod.h) directly when [building NTDDK_ARM](./buildNTDDK.bat)
[Building NTWDF ARM](./buildNTWDF.bat) hence requires the modification of the original ntddk.h