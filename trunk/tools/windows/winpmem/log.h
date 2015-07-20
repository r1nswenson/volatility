
#pragma once

#define STR(x)    # x
#define STR2(x)   STR(x)
#define WIDEN2(x) L ## x
#define WIDEN(x)  WIDEN2(x)

#define WADPREF WIDEN(__FILE__) L"(" WIDEN(STR2(__LINE__)) L"):"
#define _WAHDR  WADPREF L":"
#define _WATAG(a) _WAHDR a
#define WAHDR _WAHDR
#define WATAG(a)  WAHDR WIDEN2(a)
#define WASEP1(a) L"==================================\n" a
#define WASEP2(a) L"----------------------------------\n" a

#define ADPREF __FILE__ "(" STR2(__LINE__) "):"
#define _AHDR  ADPREF ":"
#define _ATAG(a) _AHDR a
#define AHDR _AHDR
#define ATAG(a)  AHDR a
#define ASEP1(a) "==================================\n" a
#define ASEP2(a) "----------------------------------\n" a

#if SILENT_OPERATION == 1
#define WinDbgPrint(fmt, ...)
#define vWinDbgPrintEx(x, ...)
#else
#define WinDbgPrint    DbgPrint
#define vWinDbgPrintEx vDbgPrintEx
#endif

