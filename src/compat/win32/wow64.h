#ifdef _WIN64
#ifndef tup_win32_wow64_h
#define tup_win32_wow64_h
#define WOW64_CONTEXT_i386 0x00010000
#define WOW64_CONTEXT_CONTROL (WOW64_CONTEXT_i386 | __MSABI_LONG(0x00000001))

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512
#define WOW64_SIZE_OF_80387_REGISTERS 80

typedef struct _WOW64_FLOATING_SAVE_AREA {
  DWORD   ControlWord;
  DWORD   StatusWord;
  DWORD   TagWord;
  DWORD   ErrorOffset;
  DWORD   ErrorSelector;
  DWORD   DataOffset;
  DWORD   DataSelector;
  BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
  DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT {
  DWORD ContextFlags;
  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;
  WOW64_FLOATING_SAVE_AREA FloatSave;
  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;
  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;
  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;
  BYTE ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT, *PWOW64_CONTEXT;

BOOL WINAPI Wow64GetThreadContext(HANDLE hThread, PWOW64_CONTEXT lpContext);
BOOL WINAPI Wow64SetThreadContext(HANDLE hThread, const WOW64_CONTEXT *lpContext);

#endif

#endif
