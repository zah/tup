/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2010  James McKaskill
 * Copyright (C) 2010-2016  Mike Shal <marfey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define BUILDING_DLLINJECT
#include "dllinject.h"
#include "tup/access_event.h"
#include "iat_patch.h"
#include "hot_patch.h"
#include "patch.h"
#include "trace.h"

#include <windows.h>
#include <ntdef.h>
#include <wow64.h>
#ifndef STATUS_SUCCESS
#include <ntstatus.h>
#endif
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <ctype.h>
#include <shlwapi.h>

#define __DBG_W64		0
#define __DBG_W32		0

#ifndef __in
#define __in
#define __out
#define __inout
#define __in_opt
#define __inout_opt
#define __reserved
#endif

typedef HFILE(WINAPI *OpenFile_t)(
	__in    LPCSTR lpFileName,
	__inout LPOFSTRUCT lpReOpenBuff,
	__in    UINT uStyle);

typedef HANDLE(WINAPI *CreateFileA_t)(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile);

typedef HANDLE(WINAPI *CreateFileW_t)(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile);

typedef HANDLE(WINAPI *CreateFileTransactedA_t)(
	__in       LPCSTR lpFileName,
	__in       DWORD dwDesiredAccess,
	__in       DWORD dwShareMode,
	__in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in       DWORD dwCreationDisposition,
	__in       DWORD dwFlagsAndAttributes,
	__in_opt   HANDLE hTemplateFile,
	__in       HANDLE hTransaction,
	__in_opt   PUSHORT pusMiniVersion,
	__reserved PVOID  lpExtendedParameter);

typedef HANDLE(WINAPI *CreateFileTransactedW_t)(
	__in       LPCWSTR lpFileName,
	__in       DWORD dwDesiredAccess,
	__in       DWORD dwShareMode,
	__in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in       DWORD dwCreationDisposition,
	__in       DWORD dwFlagsAndAttributes,
	__in_opt   HANDLE hTemplateFile,
	__in       HANDLE hTransaction,
	__in_opt   PUSHORT pusMiniVersion,
	__reserved PVOID  lpExtendedParameter);

typedef BOOL(WINAPI *DeleteFileA_t)(
	__in LPCSTR lpFileName);

typedef BOOL(WINAPI *DeleteFileW_t)(
	__in LPCWSTR lpFileName);

typedef BOOL(WINAPI *DeleteFileTransactedA_t)(
	__in     LPCSTR lpFileName,
	__in     HANDLE hTransaction);

typedef BOOL(WINAPI *DeleteFileTransactedW_t)(
	__in     LPCWSTR lpFileName,
	__in     HANDLE hTransaction);

typedef BOOL(WINAPI *MoveFileA_t)(
	__in LPCSTR lpExistingFileName,
	__in LPCSTR lpNewFileName);

typedef BOOL(WINAPI *MoveFileW_t)(
	__in LPCWSTR lpExistingFileName,
	__in LPCWSTR lpNewFileName);

typedef BOOL(WINAPI *MoveFileExA_t)(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in     DWORD    dwFlags);

typedef BOOL(WINAPI *MoveFileExW_t)(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in     DWORD    dwFlags);

typedef BOOL(WINAPI *MoveFileWithProgressA_t)(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags);

typedef BOOL(WINAPI *MoveFileWithProgressW_t)(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags);

typedef BOOL(WINAPI *MoveFileTransactedA_t)(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags,
	__in     HANDLE hTransaction);

typedef BOOL(WINAPI *MoveFileTransactedW_t)(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags,
	__in     HANDLE hTransaction);

typedef BOOL(WINAPI *ReplaceFileA_t)(
	__in       LPCSTR  lpReplacedFileName,
	__in       LPCSTR  lpReplacementFileName,
	__in_opt   LPCSTR  lpBackupFileName,
	__in       DWORD   dwReplaceFlags,
	__reserved LPVOID  lpExclude,
	__reserved LPVOID  lpReserved);

typedef BOOL(WINAPI *ReplaceFileW_t)(
	__in       LPCWSTR lpReplacedFileName,
	__in       LPCWSTR lpReplacementFileName,
	__in_opt   LPCWSTR lpBackupFileName,
	__in       DWORD   dwReplaceFlags,
	__reserved LPVOID  lpExclude,
	__reserved LPVOID  lpReserved);

typedef BOOL(WINAPI *CopyFileA_t)(
	__in LPCSTR lpExistingFileName,
	__in LPCSTR lpNewFileName,
	__in BOOL bFailIfExists);

typedef BOOL(WINAPI *CopyFileW_t)(
	__in LPCWSTR lpExistingFileName,
	__in LPCWSTR lpNewFileName,
	__in BOOL bFailIfExists);

typedef BOOL(WINAPI *CopyFileExA_t)(
	__in     LPCSTR lpExistingFileName,
	__in     LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags);

typedef BOOL(WINAPI *CopyFileExW_t)(
	__in     LPCWSTR lpExistingFileName,
	__in     LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags);

typedef BOOL(WINAPI *CopyFileTransactedA_t)(
	__in     LPCSTR lpExistingFileName,
	__in     LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags,
	__in     HANDLE hTransaction);

typedef BOOL(WINAPI *CopyFileTransactedW_t)(
	__in     LPCWSTR lpExistingFileName,
	__in     LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags,
	__in     HANDLE hTransaction);

typedef DWORD(WINAPI *GetFileAttributesA_t)(
	__in LPCSTR lpFileName);

typedef DWORD(WINAPI *GetFileAttributesW_t)(
	__in LPCWSTR lpFileName);

typedef BOOL(WINAPI *GetFileAttributesExA_t)(
	__in  LPCSTR lpFileName,
	__in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
	__out LPVOID lpFileInformation);

typedef BOOL(WINAPI *GetFileAttributesExW_t)(
	__in  LPCWSTR lpFileName,
	__in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
	__out LPVOID lpFileInformation);

typedef __out HANDLE(WINAPI *FindFirstFileA_t)(
	__in  LPCSTR lpFileName,
	__out LPWIN32_FIND_DATAA lpFindFileData);

typedef __out HANDLE(WINAPI *FindFirstFileW_t)(
	__in  LPCWSTR lpFileName,
	__out LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL(WINAPI *FindNextFileA_t)(
	__in  HANDLE hFindFile,
	__out LPWIN32_FIND_DATAA lpFindFileData);

typedef BOOL(WINAPI *FindNextFileW_t)(
	__in  HANDLE hFindFile,
	__out LPWIN32_FIND_DATAW lpFindFileData);

typedef NTSTATUS(WINAPI *NtOpenFile_t)(
	__out  PHANDLE FileHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__in   ULONG ShareAccess,
	__in   ULONG OpenOptions);

typedef NTSTATUS(WINAPI *NtCreateFile_t)(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG CreateDisposition,
	__in      ULONG CreateOptions,
	__in      PVOID EaBuffer,
	__in      ULONG EaLength);

typedef NTSTATUS(WINAPI *NtCreateUserProcess_t)(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	ULONG_PTR CreateInfo,
	ULONG_PTR AttributeList
	);

typedef int(*access_t)(const char *pathname, int mode);
typedef FILE *(*fopen_t)(const char *path, const char *mode);
typedef int(*rename_t)(const char *oldpath, const char *newpath);
typedef int(*remove_t)(const char *pathname);
typedef int(*stat64_t)(const char *path, void *buffer);
typedef int(*stat32_t)(const char *path, void *buffer);

static char execdir[MAX_PATH];
static char tuptopdir[MAX_PATH];

typedef struct variant_dir variant_dir;

struct variant_dir {
	char *name;
	variant_dir *next;
};

static variant_dir *TupVariants = NULL;
static HANDLE hHeap = INVALID_HANDLE_VALUE;

static void *MemoryPool = NULL;
static size_t TotalMemory = 4096 * 4096;
static size_t CurrentAllocatedMemory = 0;
static HANDLE hMemoryLock;


/*
 * This memory allocator (which is really rudimentary) is used to avoid
 * generating heap corruptions. At some point we should really track
 * down the root cause of the the corruption instead of using this hack.
 */
static void *dll_malloc(size_t size)
{
	if (hHeap == INVALID_HANDLE_VALUE) {
		DEBUG_HOOK("dll_malloc called without heap\n");
		return NULL;
	}

	void *memory = NULL;

	WaitForSingleObject(hMemoryLock, INFINITE);

	// align memory to 16 byte boundary
	size_t realSize = (size + 0x0F) & ~0x0F;

	if ((realSize + CurrentAllocatedMemory) > TotalMemory) {
		DEBUG_HOOK("OUT OF MEMORY\n");
		goto out;
	}

	memory = (void*)((size_t)MemoryPool + CurrentAllocatedMemory);
	CurrentAllocatedMemory += realSize;

out:
	ReleaseMutex(hMemoryLock);

	//DEBUG_HOOK("Allocating %d bytes memory\n", size);
	//size_t realSize = (size + 0x0F) & ~0x0F;
	//memory = HeapAlloc(hHeap, 0, realSize);
	//if (memory == NULL) {
	//    DEBUG_HOOK("DllMalloc failed\n");
	//} 
	return memory;
}

static void dll_free(void *memory)
{
	if (hHeap == INVALID_HANDLE_VALUE) {
		DEBUG_HOOK("dll_free called without heap\n");
		return;
	}

	if (memory) {}

	//BOOL rc = HeapFree(hHeap, 0, memory);
	//if (!rc) {
	//    DEBUG_HOOK("DllFree faile\n");
	//}
}

#define HAS_VARIANTS() ({DEBUG_HOOK("VarCheck in: %s:%d\n", __FUNCTION__, __LINE__); (TupVariants != NULL);})
//#define HAS_VARIANTS() (TupVariants != NULL)

static BOOL add_variant(const char *path)
{
	variant_dir *dir = dll_malloc(sizeof(variant_dir));
	if (dir == NULL)
		return FALSE;

	dir->name = dll_malloc(strlen(path) + 1);
	if (dir->name == NULL)
		return FALSE;

	sprintf(dir->name, "%s", path);
	dir->name[strlen(path)] = 0;

	dir->next = NULL;

	if (TupVariants == NULL)
		TupVariants = dir;
	else {
		variant_dir *ptr = TupVariants;
		while (ptr->next != NULL) ptr = ptr->next;
		ptr->next = dir;
	}
	return TRUE;
}

static OpenFile_t			OpenFile_orig;
static DeleteFileA_t			DeleteFileA_orig;
static DeleteFileW_t			DeleteFileW_orig;
static DeleteFileTransactedA_t		DeleteFileTransactedA_orig;
static DeleteFileTransactedW_t		DeleteFileTransactedW_orig;
static MoveFileA_t			MoveFileA_orig;
static MoveFileW_t			MoveFileW_orig;
static MoveFileExA_t			MoveFileExA_orig;
static MoveFileExW_t			MoveFileExW_orig;
static MoveFileWithProgressA_t		MoveFileWithProgressA_orig;
static MoveFileWithProgressW_t		MoveFileWithProgressW_orig;
static MoveFileTransactedA_t		MoveFileTransactedA_orig;
static MoveFileTransactedW_t		MoveFileTransactedW_orig;
static ReplaceFileA_t			ReplaceFileA_orig;
static ReplaceFileW_t			ReplaceFileW_orig;
static CopyFileA_t			CopyFileA_orig;
static CopyFileW_t			CopyFileW_orig;
static CopyFileExA_t			CopyFileExA_orig;
static CopyFileExW_t			CopyFileExW_orig;
static CopyFileTransactedA_t		CopyFileTransactedA_orig;
static CopyFileTransactedW_t		CopyFileTransactedW_orig;
static GetFileAttributesA_t		GetFileAttributesA_orig;
static GetFileAttributesW_t		GetFileAttributesW_orig;
static GetFileAttributesExA_t		GetFileAttributesExA_orig;
static GetFileAttributesExW_t		GetFileAttributesExW_orig;
static FindFirstFileA_t			FindFirstFileA_orig;
static FindFirstFileW_t			FindFirstFileW_orig;
static FindNextFileA_t			FindNextFileA_orig;
static FindNextFileW_t			FindNextFileW_orig;
static NtCreateFile_t			NtCreateFile_orig;
static NtOpenFile_t			NtOpenFile_orig;
static NtCreateUserProcess_t		NtCreateUserProcess_orig;
static access_t				_access_orig;
static fopen_t				fopen_orig;
static rename_t				rename_orig;
static remove_t				remove_orig;
static stat64_t       _stat64_orig;
static stat32_t       _stat32_orig;

#define TUP_CREATE_WRITE_FLAGS (GENERIC_WRITE | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES)
/* Including ddk/wdm.h causes other issues, and this is all we need... */
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000

#define handle_file(a, b, c) mhandle_file(a, b, c, __LINE__)
static void mhandle_file(const char* file, const char* file2, enum access_type at, int line);
static void handle_file_w(const wchar_t* file, const wchar_t* file2, enum access_type at);
static int canon_path(const char *file, char *dest);

static const char *strcasestr(const char *arg1, const char *arg2);
static const wchar_t *wcscasestr(const wchar_t *arg1, const wchar_t *arg2);

static char s_depfilename[PATH_MAX];
static char s_vardict_file[PATH_MAX];
static HANDLE deph = INVALID_HANDLE_VALUE;

static int writef(const char *data, unsigned int len)
{
	int rc = 0;
	DWORD num_written;

	if (!WriteFile(deph, data, len, &num_written, NULL)) {
		DEBUG_HOOK("failed to write %i bytes\n", len);
		rc = -1;
	}
	if (num_written != len) {
		DEBUG_HOOK("failed to write exactly %i bytes\n", len);
		rc = -1;
	}
	return rc;
}

static char *unicode_to_ansi(PUNICODE_STRING uni)
{
	int len;
	char *name = NULL;

	len = WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / sizeof(wchar_t), 0, 0, NULL, NULL);
	if (len > 0) {
		name = dll_malloc(len + 1);
		if (name == NULL) {
			DEBUG_HOOK("Tried to allocate: %d bytes\n", len + 1);
			perror("malloc uts");
			return NULL;
		}
		WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / sizeof(wchar_t), name, len, NULL, NULL);
		name[len] = 0;
	}
	return name;
}

static char *wchar_to_ansi(LPCWSTR uni)
{
	int len;
	char *name = NULL;

	len = WideCharToMultiByte(CP_UTF8, 0, uni, -1, 0, 0, NULL, NULL);
	if (len > 0) {
		name = dll_malloc(len + 1);
		if (name == NULL) {
			perror("malloc wts");
			return NULL;
		}
		WideCharToMultiByte(CP_UTF8, 0, uni, -1, name, len, NULL, NULL);
		name[len] = 0;
	}
	return name;
}

static int ansi_to_wchar(const char *instr, LPWSTR outstr)
{
	int len;

	len = MultiByteToWideChar(CP_UTF8, 0, instr, -1, NULL, 0);
	if (len > 0) {
		len *= sizeof(wchar_t);
		outstr = dll_malloc(len);
		if (outstr == NULL) {
			perror("malloc atw");
			return 0;
		}
		if (MultiByteToWideChar(CP_UTF8, 0, instr, -1, outstr, len) < 0) {
			DEBUG_HOOK("a2w FAILED\n");
		}
	}
	return len;
}

static int ansi_to_unicode(const char *instr, PUNICODE_STRING outstr)
{
	int len;

	len = MultiByteToWideChar(CP_UTF8, 0, instr, -1, NULL, 0);
	if (len > 0) {
		outstr->Length = outstr->MaximumLength = (len - 1) * sizeof(wchar_t); // -1 for no terminating null character
		outstr->Buffer = dll_malloc(outstr->Length);
		if (outstr->Buffer == NULL) {
			perror("malloc atu");
			return 0;
		}
		if (MultiByteToWideChar(CP_UTF8, 0, instr, -1, outstr->Buffer, outstr->Length) < 0) {
			DEBUG_HOOK("MultiByteToWideChar FAILED\n");
		}
	}
	return len;
}

static int variant_to_source(const char *fileName, char *dest)
{
	char *src, *dst;

	variant_dir *dir = TupVariants;
	int found = 0;

	if (!canon_path(fileName, dest))
		return -1;

	while (dir != NULL) {
		if (strncasecmp(dest, dir->name, strlen(dir->name)) == 0) {
			found = 1;
			break;
		}
		dir = dir->next;
	}

	if (!found) {
		return -1;
	}

	// Remove variant directory
	dst = dest + strlen(tuptopdir);
	dst++;
	src = strchr(dst, '\\');
	src++;

	sprintf(dst, "%s", src);

	return 0;
}

static int variant_to_sourceW(LPCWSTR fileName, LPWSTR dest)
{
	char realName[MAX_PATH];
	char *ansi = wchar_to_ansi(fileName);
	if (ansi == NULL) {
		return -1;
	}

	if (variant_to_source(ansi, realName) != 0) {
		dll_free(ansi);
		return -1;
	}

	ansi_to_wchar(realName, dest);
	dll_free(ansi);

	return 0;
}

static int variant_to_sourceOA(POBJECT_ATTRIBUTES original, POBJECT_ATTRIBUTES *variant)
{
	char realName[MAX_PATH];
	PUNICODE_STRING unicodeVarName = NULL;
	char *ansi = NULL, *ansiName;

	ansi = unicode_to_ansi(original->ObjectName);
	if (ansi == NULL)
		goto error;

	// NT Paths need \??\ prefix to be valid
	snprintf(realName, MAX_PATH, "\\??\\");

	ansiName = ansi;
	if (strncmp(ansiName, "\\??\\", 4) == 0)
		ansiName += 4;

	if (variant_to_source(ansiName, realName + 4) != 0) {
		goto error;
	}

	unicodeVarName = dll_malloc(sizeof(UNICODE_STRING));
	if (unicodeVarName == NULL)
		goto error;

	if (ansi_to_unicode(realName, unicodeVarName) < 0) {
		DEBUG_HOOK("Ansi_to_Unicode FAILED\n");
		goto error;
	}

	(*variant) = dll_malloc(sizeof(OBJECT_ATTRIBUTES));
	if ((*variant) == NULL)
		goto error;

	InitializeObjectAttributes(*variant, unicodeVarName, original->Attributes, NULL, original->SecurityDescriptor);

	dll_free(ansi);
	return 0;

error:
	DEBUG_HOOK("VarRelName failed %s\n", ansi);
	if (ansi != NULL)
		dll_free(ansi);
	if (unicodeVarName != NULL) {
		if (unicodeVarName->Buffer != NULL)
			dll_free(unicodeVarName->Buffer);
		dll_free(unicodeVarName);
	}
	return -1;
}

static void free_object_attribute(POBJECT_ATTRIBUTES attrib)
{
	if (attrib != NULL) {
		if (attrib->ObjectName != NULL) {
			if (attrib->ObjectName->Buffer != NULL)
				dll_free(attrib->ObjectName->Buffer);
			dll_free(attrib->ObjectName);
		}
		dll_free(attrib);
	}
}

static HFILE WINAPI OpenFile_hook(
	__in    LPCSTR lpFileName,
	__inout LPOFSTRUCT lpReOpenBuff,
	__in    UINT uStyle)
{
	char realName[MAX_PATH];
	LPCSTR fileName = lpFileName;
	HFILE f;
	DWORD err;

	f = OpenFile_orig(
		fileName,
		lpReOpenBuff,
		uStyle);

	if (f == HFILE_ERROR && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(fileName, realName) == 0) {
			fileName = realName;
			f = OpenFile_orig(
				fileName,
				lpReOpenBuff,
				uStyle);
		}
		if (f == HFILE_ERROR) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s %s (%s)\n", __FUNCTION__, fileName, f != HFILE_ERROR ? "SUCCESS" : "FAILED");

	if (uStyle & OF_DELETE) {
		handle_file(fileName, NULL, ACCESS_UNLINK);
	} else if (uStyle & (OF_READWRITE | OF_WRITE | OF_SHARE_DENY_WRITE | OF_SHARE_EXCLUSIVE | OF_CREATE)) {
		handle_file(fileName, NULL, ACCESS_WRITE);
	} else {
		handle_file(fileName, NULL, ACCESS_READ);
	}

	return f;
}

static HANDLE WINAPI CreateFileA_hook(
	__in     LPCSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile)
{
	LPCSTR fileName = lpFileName;
	char realName[PATH_MAX];
	DWORD lastError;

	HANDLE h = CreateFileA_orig(
		fileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		lastError = GetLastError();
		if (variant_to_source(lpFileName, realName) == 0) {
			fileName = realName;
			h = CreateFileA_orig(
				fileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile);
		}
		if (h == INVALID_HANDLE_VALUE) {
			SetLastError(lastError);
			fileName = lpFileName;
		}
	}

	DEBUG_HOOK("CreateFileA '%s', %p:%X, %x, %x, %x, %x\n",
		fileName,
		h,
		GetLastError(),
		dwDesiredAccess,
		dwShareMode,
		dwCreationDisposition,
		dwFlagsAndAttributes);

	if (h != INVALID_HANDLE_VALUE && dwDesiredAccess & TUP_CREATE_WRITE_FLAGS) {
		handle_file(fileName, NULL, ACCESS_WRITE);
	} else {
		handle_file(fileName, NULL, ACCESS_READ);
	}

	return h;
}


/* -------------------------------------------------------------------------- */

static HANDLE WINAPI CreateFileW_hook(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile)
{
	LPCWSTR fileName = lpFileName;
	wchar_t realName[PATH_MAX];
	DWORD err;

	HANDLE h = CreateFileW_orig(
		fileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(lpFileName, realName) == 0) {
			fileName = realName;
			h = CreateFileW_orig(
				fileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile);
		}
		if (h == INVALID_HANDLE_VALUE) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("CreateFileW '%S' => '%S', %p:%x, %x, %x, %x, %x\n",
		lpFileName,
		fileName,
		h,
		GetLastError(),
		dwDesiredAccess,
		dwShareMode,
		dwCreationDisposition,
		dwFlagsAndAttributes);

	if (h != INVALID_HANDLE_VALUE && dwDesiredAccess & TUP_CREATE_WRITE_FLAGS) {
		handle_file_w(fileName, NULL, ACCESS_WRITE);
	} else {
		handle_file_w(fileName, NULL, ACCESS_READ);
	}

	return h;
}

/* -------------------------------------------------------------------------- */

HANDLE WINAPI CreateFileTransactedA_hook(
	__in       LPCSTR lpFileName,
	__in       DWORD dwDesiredAccess,
	__in       DWORD dwShareMode,
	__in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in       DWORD dwCreationDisposition,
	__in       DWORD dwFlagsAndAttributes,
	__in_opt   HANDLE hTemplateFile,
	__in       HANDLE hTransaction,
	__in_opt   PUSHORT pusMiniVersion,
	__reserved PVOID  lpExtendedParameter)
{
	LPCSTR fileName = lpFileName;
	char realName[PATH_MAX];
	DWORD err;

	HANDLE h = CreateFileTransactedA_orig(
		fileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile,
		hTransaction,
		pusMiniVersion,
		lpExtendedParameter);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(lpFileName, realName) == 0) {
			fileName = realName;
			h = CreateFileTransactedA_orig(
				fileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile,
				hTransaction,
				pusMiniVersion,
				lpExtendedParameter);
		}
		if (h == INVALID_HANDLE_VALUE) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("CreateFileTransactedA '%s' %p:%x", fileName, h, GetLastError());

	if (h != INVALID_HANDLE_VALUE && dwDesiredAccess & TUP_CREATE_WRITE_FLAGS) {
		handle_file(fileName, NULL, ACCESS_WRITE);
	} else {
		handle_file(fileName, NULL, ACCESS_READ);
	}

	return h;
}

HANDLE WINAPI CreateFileTransactedW_hook(
	__in       LPCWSTR lpFileName,
	__in       DWORD dwDesiredAccess,
	__in       DWORD dwShareMode,
	__in_opt   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in       DWORD dwCreationDisposition,
	__in       DWORD dwFlagsAndAttributes,
	__in_opt   HANDLE hTemplateFile,
	__in       HANDLE hTransaction,
	__in_opt   PUSHORT pusMiniVersion,
	__reserved PVOID  lpExtendedParameter)
{
	LPCWSTR fileName = lpFileName;
	wchar_t realName[PATH_MAX];
	DWORD err;

	HANDLE h = CreateFileTransactedW_orig(
		fileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile,
		hTransaction,
		pusMiniVersion,
		lpExtendedParameter);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(lpFileName, realName) == 0) {
			fileName = realName;
			h = CreateFileTransactedW_orig(
				fileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile,
				hTransaction,
				pusMiniVersion,
				lpExtendedParameter);
		}
		if (h == INVALID_HANDLE_VALUE) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("CreateFileTransactedA '%s' %p:%x", fileName, h, GetLastError());

	if (h != INVALID_HANDLE_VALUE && dwDesiredAccess & TUP_CREATE_WRITE_FLAGS) {
		handle_file_w(fileName, NULL, ACCESS_WRITE);
	} else {
		handle_file_w(fileName, NULL, ACCESS_READ);
	}

	return h;
}

NTSTATUS WINAPI NtCreateFile_hook(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG CreateDisposition,
	__in      ULONG CreateOptions,
	__in      PVOID EaBuffer,
	__in      ULONG EaLength)
{
	char *ansi = NULL;
	POBJECT_ATTRIBUTES objectAttributes = ObjectAttributes;
	POBJECT_ATTRIBUTES variantObjectAttributes = NULL;
	DWORD err;
	NTSTATUS origRc, rc;

	origRc = rc = NtCreateFile_orig(FileHandle,
		DesiredAccess,
		objectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	if (!NT_SUCCESS(rc) && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceOA(objectAttributes, &variantObjectAttributes) == 0) {
			objectAttributes = variantObjectAttributes;
			rc = NtCreateFile_orig(FileHandle,
				DesiredAccess,
				objectAttributes,
				IoStatusBlock,
				AllocationSize,
				FileAttributes,
				ShareAccess,
				CreateDisposition,
				CreateOptions,
				EaBuffer,
				EaLength);
		}
		if (!NT_SUCCESS(rc)) {
			objectAttributes = ObjectAttributes;
			rc = origRc;
			SetLastError(err);
		}
	}

	ansi = unicode_to_ansi(objectAttributes->ObjectName);
	if (ansi != NULL) {
		const char *name = ansi;

		DEBUG_HOOK("NtCreateFile[%X] '%s': %x, %x, %x (CD: %X)\n", rc, ansi, ShareAccess, DesiredAccess, CreateOptions, CreateDisposition);
		if (strncmp(name, "\\??\\", 4) == 0) {
			name += 4;
			/* Windows started trying to read a file called
			 * "\??\Ip", which broke some of the tests. This just
			 * skips anything that doesn't begin with something
			 * like "C:"
			 */
			if (name[0] != 0 && name[1] != ':')
				goto out_free;
		}
		if (rc == STATUS_SUCCESS && DesiredAccess & TUP_CREATE_WRITE_FLAGS) {
			handle_file(name, NULL, ACCESS_WRITE);
		} else {
			handle_file(name, NULL, ACCESS_READ);
		}
	out_free:
		dll_free(ansi);
	}

	if (variantObjectAttributes != NULL)
		free_object_attribute(variantObjectAttributes);

	return rc;
}

NTSTATUS WINAPI NtOpenFile_hook(
	__out  PHANDLE FileHandle,
	__in   ACCESS_MASK DesiredAccess,
	__in   POBJECT_ATTRIBUTES ObjectAttributes,
	__out  PIO_STATUS_BLOCK IoStatusBlock,
	__in   ULONG ShareAccess,
	__in   ULONG OpenOptions)
{
	char *ansi;
	POBJECT_ATTRIBUTES objectAttributes = ObjectAttributes;
	POBJECT_ATTRIBUTES variantObjectAttributes = NULL;
	NTSTATUS rc, origRc;
	DWORD err;

	origRc = rc = NtOpenFile_orig(FileHandle,
		DesiredAccess,
		objectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions);

	if (!NT_SUCCESS(rc) && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceOA(objectAttributes, &variantObjectAttributes) == 0) {
			objectAttributes = variantObjectAttributes;
			rc = NtOpenFile_orig(FileHandle,
				DesiredAccess,
				objectAttributes,
				IoStatusBlock,
				ShareAccess,
				OpenOptions);
		}
		if (!NT_SUCCESS(rc)) {
			objectAttributes = ObjectAttributes;
			rc = origRc;
			SetLastError(err);
		}
	}

	ansi = unicode_to_ansi(objectAttributes->ObjectName);

	if (ansi) {
		const char *name = ansi;

		DEBUG_HOOK("NtOpenFile[%X] '%s': %x, %x, %x\n", rc, ansi, ShareAccess, DesiredAccess, OpenOptions);
		if (strncmp(name, "\\??\\", 4) == 0) {
			name += 4;
			/* Windows started trying to read a file called "\??\Ip",
			 * which broke some of the tests. This just skips
			 * anything that doesn't begin with something like "C:"
			 */
			if (name[0] != 0 && name[1] != ':')
				goto out_free;
		}

		/* The ShareAccess == FILE_SHARE_DELETE check might be
		 * specific to how cygwin handles unlink(). It is very
		 * confusing to follow, but it doesn't ever seem to go through
		 * the DeleteFile() route. This is the only place I've found
		 * that seems to be able to hook those events.
		 *
		 * The DesiredAccess & DELETE check is how cygwin does a
		 * rename() to remove the old file.
		 */
		if (ShareAccess == FILE_SHARE_DELETE ||
			DesiredAccess & DELETE) {
			handle_file(name, NULL, ACCESS_UNLINK);
		} else if (OpenOptions & FILE_OPEN_FOR_BACKUP_INTENT) {
			/* The MSVC linker seems to successfully open
			 * "prog.ilk" for reading (when linking "prog.exe"),
			 * even though no such file exists. This confuses tup.
			 * It seems that this flag is used for temporary files,
			 * so that should be safe to ignore.
			 */
		} else {
			if (rc == STATUS_SUCCESS && DesiredAccess & TUP_CREATE_WRITE_FLAGS) {
				handle_file(name, NULL, ACCESS_WRITE);
			} else {
				handle_file(name, NULL, ACCESS_READ);
			}
		}
	out_free:
		dll_free(ansi);
	}

	if (variantObjectAttributes != NULL)
		free_object_attribute(variantObjectAttributes);

	return rc;
}

NTSTATUS WINAPI NtCreateUserProcess_hook(PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	ULONG_PTR CreateInfo,
	ULONG_PTR AttributeList)
{
	CHAR buffer[1024];
	DWORD err;
	NTSTATUS rc = NtCreateUserProcess_orig(ProcessHandle,
		ThreadHandle, ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags, ThreadFlags,
		ProcessParameters, CreateInfo, AttributeList);


	DEBUG_HOOK("NtCreateUserProcess: %X\n", rc);

	if (!NT_SUCCESS(rc)) {
		return rc;
	}

	err = GetLastError();

	if (GetProcessImageFileNameA(*ProcessHandle, buffer, 1024) == 0) {
		DEBUG_HOOK("Not able to get name: %X\n", GetLastError());
		goto done;
	}

	char *exec = strrchr(buffer, '\\');
	if (exec == NULL) {
		DEBUG_HOOK("Failed to parse exec @ %d: %s\n", __LINE__, buffer);
		goto done;
	}

	exec++;

	if (strncasecmp(exec, "tup32detect.exe", 15) == 0 ||
		strncasecmp(exec, "mspdbsrv.exe", 12) == 0)
		goto done;

	DEBUG_HOOK("NtCreateUserProcess: %s\n", buffer);

	PROCESS_INFORMATION processInformation;
	processInformation.hProcess = *ProcessHandle;
	processInformation.hThread = *ThreadHandle;

	tup_inject_dll(&processInformation, s_depfilename, s_vardict_file);

done:
	SetLastError(err);
	return rc;
}

NTSTATUS WINAPI NtCreateUserProcess_hook(PHANDLE ProcessHandle,
PHANDLE ThreadHandle,
ACCESS_MASK ProcessDesiredAccess,
ACCESS_MASK ThreadDesiredAccess,
POBJECT_ATTRIBUTES ProcessObjectAttributes,
POBJECT_ATTRIBUTES ThreadObjectAttributes,
ULONG ProcessFlags,
ULONG ThreadFlags,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
ULONG_PTR CreateInfo,
ULONG_PTR AttributeList)
{

	NTSTATUS rc = NtCreateUserProcess_orig(ProcessHandle,
		ThreadHandle, ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags, ThreadFlags,
		ProcessParameters,CreateInfo, AttributeList);

        if (rc != STATUS_SUCCESS) {
                return rc;
        }

        TCHAR wbuffer[1024];
        if (GetModuleFileNameEx(*ProcessHandle,0,wbuffer,1024)){
		char buffer[PATH_MAX];
		WideCharToMultiByte(CP_UTF8, 0, wbuffer, -1, buffer, PATH_MAX, NULL, NULL);
		char *exec = strrchr(buffer, '\\');
		if (exec == NULL) return rc;

		exec++;
		if (strncasecmp(exec, "tup32detect.exe", 15) == 0 ||
			strncasecmp(exec, "mspdbsrv.exe", 12) == 0)
			return rc;

                DEBUG_HOOK("NtCreateUser: %s\n", buffer);

		PROCESS_INFORMATION processInformation;
		processInformation.hProcess = *ProcessHandle;
		processInformation.hThread = *ThreadHandle;

		tup_inject_dll(&processInformation, s_depfilename, s_vardict_file);
        }

	return rc;
}

BOOL WINAPI DeleteFileA_hook(
	__in LPCSTR lpFileName)
{
	char realName[MAX_PATH];
	DWORD err;
	LPCSTR fileName = lpFileName;
	BOOL rc = DeleteFileA_orig(fileName);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(fileName, realName) == 0) {
			fileName = realName;
			rc = DeleteFileA_orig(fileName);

		}
		if (!rc) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%s' (%s)\n", __FUNCTION__, fileName, rc ? "SUCCESS" : "FAILED");

	handle_file(fileName, NULL, ACCESS_UNLINK);
	return rc;
}

BOOL WINAPI DeleteFileW_hook(
	__in LPCWSTR lpFileName)
{
	wchar_t realName[MAX_PATH];
	LPCWSTR fileName = lpFileName;
	DWORD err;
	BOOL rc = DeleteFileW_orig(fileName);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(fileName, realName) == 0) {
			fileName = realName;
			rc = DeleteFileW_orig(fileName);
		}
		if (!rc) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%S' (%s)\n", __FUNCTION__, fileName, rc ? "SUCCESS" : "FAILED");

	handle_file_w(fileName, NULL, ACCESS_UNLINK);
	return rc;
}

BOOL WINAPI DeleteFileTransactedA_hook(
	__in     LPCSTR lpFileName,
	__in     HANDLE hTransaction)
{
	char realName[MAX_PATH];
	LPCSTR fileName = lpFileName;
	DWORD err;
	BOOL rc = DeleteFileTransactedA_orig(fileName, hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(fileName, realName) == 0) {
			fileName = realName;
			rc = DeleteFileTransactedA_orig(fileName, hTransaction);
		}
		if (!rc) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%s' (%s)\n", __FUNCTION__, fileName, rc ? "SUCCESS" : "FAILED");

	handle_file(fileName, NULL, ACCESS_UNLINK);
	return rc;
}

BOOL WINAPI DeleteFileTransactedW_hook(
	__in     LPCWSTR lpFileName,
	__in     HANDLE hTransaction)
{
	wchar_t realName[MAX_PATH];
	LPCWSTR fileName = lpFileName;
	DWORD err;
	BOOL rc = DeleteFileTransactedW_orig(fileName, hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(fileName, realName) == 0) {
			fileName = realName;
			rc = DeleteFileTransactedW_orig(fileName, hTransaction);
		}
		if (!rc) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%s' (%s)\n", __FUNCTION__, fileName, rc ? "SUCCESS" : "FAILED");

	handle_file_w(fileName, NULL, ACCESS_UNLINK);
	return rc;
}

BOOL WINAPI MoveFileA_hook(
	__in LPCSTR lpExistingFileName,
	__in LPCSTR lpNewFileName)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileA_orig(existingFileName, newFileName);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName)
			rc = MoveFileA_orig(existingFileName, newFileName);
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	handle_file(existingFileName, newFileName, ACCESS_RENAME);
	return rc;
}

BOOL WINAPI MoveFileW_hook(
	__in LPCWSTR lpExistingFileName,
	__in LPCWSTR lpNewFileName)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileW_orig(existingFileName, newFileName);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;

		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName)
			rc = MoveFileW_orig(existingFileName, newFileName);
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileExA_hook(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in     DWORD    dwFlags)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileExA_orig(existingFileName, newFileName, dwFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName)
			rc = MoveFileExA_orig(existingFileName, newFileName, dwFlags);
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileExW_hook(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in     DWORD    dwFlags)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileExW_orig(existingFileName, newFileName, dwFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName)
			rc = MoveFileExW_orig(existingFileName, newFileName, dwFlags);
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileWithProgressA_hook(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileWithProgressA_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		dwFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = MoveFileWithProgressA_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				dwFlags);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileWithProgressW_hook(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileWithProgressW_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		dwFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = MoveFileWithProgressW_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				dwFlags);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileTransactedA_hook(
	__in     LPCSTR lpExistingFileName,
	__in_opt LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags,
	__in     HANDLE hTransaction)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileTransactedA_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		dwFlags,
		hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = MoveFileTransactedA_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				dwFlags,
				hTransaction);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI MoveFileTransactedW_hook(
	__in     LPCWSTR lpExistingFileName,
	__in_opt LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in     DWORD dwFlags,
	__in     HANDLE hTransaction)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = MoveFileTransactedW_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		dwFlags,
		hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = MoveFileTransactedW_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				dwFlags,
				hTransaction);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI ReplaceFileA_hook(
	__in       LPCSTR  lpReplacedFileName,
	__in       LPCSTR  lpReplacementFileName,
	__in_opt   LPCSTR  lpBackupFileName,
	__in       DWORD   dwReplaceFlags,
	__reserved LPVOID  lpExclude,
	__reserved LPVOID  lpReserved)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpReplacedFileName;
	LPCSTR newFileName = lpReplacementFileName;
	DWORD err;
	BOOL rc = ReplaceFileA_orig(
		existingFileName,
		newFileName,
		lpBackupFileName,
		dwReplaceFlags,
		lpExclude,
		lpReserved);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpReplacementFileName || existingFileName != lpReplacedFileName) {
			rc = ReplaceFileA_orig(
				existingFileName,
				newFileName,
				lpBackupFileName,
				dwReplaceFlags,
				lpExclude,
				lpReserved);
		}
		if (!rc) {
			existingFileName = lpReplacedFileName;
			newFileName = lpReplacementFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI ReplaceFileW_hook(
	__in       LPCWSTR lpReplacedFileName,
	__in       LPCWSTR lpReplacementFileName,
	__in_opt   LPCWSTR lpBackupFileName,
	__in       DWORD   dwReplaceFlags,
	__reserved LPVOID  lpExclude,
	__reserved LPVOID  lpReserved)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpReplacedFileName;
	LPCWSTR newFileName = lpReplacementFileName;
	DWORD err;
	BOOL rc = ReplaceFileW_orig(
		existingFileName,
		newFileName,
		lpBackupFileName,
		dwReplaceFlags,
		lpExclude,
		lpReserved);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpReplacementFileName || existingFileName != lpReplacedFileName) {
			rc = ReplaceFileW_orig(
				existingFileName,
				newFileName,
				lpBackupFileName,
				dwReplaceFlags,
				lpExclude,
				lpReserved);
		}
		if (!rc) {
			existingFileName = lpReplacedFileName;
			newFileName = lpReplacementFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, newFileName, ACCESS_RENAME);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileA_hook(
	__in LPCSTR lpExistingFileName,
	__in LPCSTR lpNewFileName,
	__in BOOL bFailIfExists)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileA_orig(
		existingFileName,
		newFileName,
		bFailIfExists);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileA_orig(
				existingFileName,
				newFileName,
				bFailIfExists);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, NULL, ACCESS_READ);
	handle_file(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileW_hook(
	__in LPCWSTR lpExistingFileName,
	__in LPCWSTR lpNewFileName,
	__in BOOL bFailIfExists)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileW_orig(
		existingFileName,
		newFileName,
		bFailIfExists);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileW_orig(
				existingFileName,
				newFileName,
				bFailIfExists);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, NULL, ACCESS_READ);
	handle_file_w(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileExA_hook(
	__in     LPCSTR lpExistingFileName,
	__in     LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileExA_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileExA_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				pbCancel,
				dwCopyFlags);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, NULL, ACCESS_READ);
	handle_file(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileExW_hook(
	__in     LPCWSTR lpExistingFileName,
	__in     LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileExW_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;

		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileExW_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				pbCancel,
				dwCopyFlags);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, NULL, ACCESS_READ);
	handle_file_w(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%S' => '%S' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileTransactedA_hook(
	__in     LPCSTR lpExistingFileName,
	__in     LPCSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags,
	__in     HANDLE hTransaction)
{
	char existingName[MAX_PATH], newName[MAX_PATH];
	LPCSTR existingFileName = lpExistingFileName;
	LPCSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileTransactedA_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags,
		hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_source(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileTransactedA_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				pbCancel,
				dwCopyFlags,
				hTransaction);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file(existingFileName, NULL, ACCESS_READ);
	handle_file(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

BOOL WINAPI CopyFileTransactedW_hook(
	__in     LPCWSTR lpExistingFileName,
	__in     LPCWSTR lpNewFileName,
	__in_opt LPPROGRESS_ROUTINE lpProgressRoutine,
	__in_opt LPVOID lpData,
	__in_opt LPBOOL pbCancel,
	__in     DWORD dwCopyFlags,
	__in     HANDLE hTransaction)
{
	wchar_t existingName[MAX_PATH], newName[MAX_PATH];
	LPCWSTR existingFileName = lpExistingFileName;
	LPCWSTR newFileName = lpNewFileName;
	DWORD err;
	BOOL rc = CopyFileTransactedW_orig(
		existingFileName,
		newFileName,
		lpProgressRoutine,
		lpData,
		pbCancel,
		dwCopyFlags,
		hTransaction);

	if (!rc && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(existingFileName, existingName) == 0)
			existingFileName = existingName;
		if (variant_to_sourceW(newFileName, newName) == 0)
			newFileName = newName;
		if (newFileName != lpNewFileName || existingFileName != lpExistingFileName) {
			rc = CopyFileTransactedW_orig(
				existingFileName,
				newFileName,
				lpProgressRoutine,
				lpData,
				pbCancel,
				dwCopyFlags,
				hTransaction);
		}
		if (!rc) {
			existingFileName = lpExistingFileName;
			newFileName = lpNewFileName;
			SetLastError(err);
		}
	}

	handle_file_w(existingFileName, NULL, ACCESS_READ);
	handle_file_w(newFileName, NULL, ACCESS_WRITE);
	DEBUG_HOOK("%s '%s' => '%s' (%s)\n", __FUNCTION__, existingFileName, newFileName, rc ? "SUCCESS" : "FAILED");

	return rc;
}

#define ATTRIB_FAIL 0xffffffff
DWORD WINAPI GetFileAttributesA_hook(
	__in LPCSTR lpFileName)
{
	char realName[PATH_MAX];
	LPCSTR fileName = lpFileName;
	DWORD err;
	DWORD attributes = GetFileAttributesA_orig(fileName);

	// If failed, try variant
	if (attributes == ATTRIB_FAIL && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(lpFileName, realName) == 0) {
			fileName = realName;
			attributes = GetFileAttributesA_orig(fileName);
		}
		if (attributes == ATTRIB_FAIL) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("GetFileAttributesA '%s' (%X)\n", fileName, attributes);

	/* If it fails (attributes == -1), we need to handle the read since
	 * it will be a ghost. If the file exists, we only care if it's a file
	 * and not a directory.
	 */
	if (attributes == ATTRIB_FAIL || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file(fileName, NULL, ACCESS_READ);
	return attributes;
}

DWORD WINAPI GetFileAttributesW_hook(
	__in LPCWSTR lpFileName)
{
	LPCWSTR fileName = lpFileName;
	DWORD err;
	DWORD attributes = GetFileAttributesW_orig(fileName);

	if (attributes == ATTRIB_FAIL && HAS_VARIANTS()) {
		err = GetLastError();
		wchar_t realName[PATH_MAX];
		if (variant_to_sourceW(lpFileName, realName) == 0) {
			fileName = realName;
			attributes = GetFileAttributesW_orig(fileName);
		}
		if (attributes == ATTRIB_FAIL) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%S' (%X)\n", __FUNCTION__, fileName, attributes);

	if (attributes == ATTRIB_FAIL || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file_w(fileName, NULL, ACCESS_READ);
	return attributes;
}

BOOL WINAPI GetFileAttributesExA_hook(
	__in  LPCSTR lpFileName,
	__in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
	__out LPVOID lpFileInformation)
{
	LPCSTR fileName = lpFileName;
	DWORD err;
	DWORD attributes = GetFileAttributesExA_orig(
		fileName,
		fInfoLevelId,
		lpFileInformation);

	if (attributes == ATTRIB_FAIL && HAS_VARIANTS()) {
		err = GetLastError();
		char realName[PATH_MAX];
		if (variant_to_source(lpFileName, realName) == 0) {
			fileName = realName;
			attributes = GetFileAttributesExA_orig(
				fileName,
				fInfoLevelId,
				lpFileInformation);
		}
		if (attributes == ATTRIB_FAIL) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%s' (%X)\n", __FUNCTION__, fileName, attributes);

	if (attributes == ATTRIB_FAIL || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file(fileName, NULL, ACCESS_READ);
	return attributes;
}

BOOL WINAPI GetFileAttributesExW_hook(
	__in  LPCWSTR lpFileName,
	__in  GET_FILEEX_INFO_LEVELS fInfoLevelId,
	__out LPVOID lpFileInformation)
{
	LPCWSTR fileName = lpFileName;
	DWORD err;
	DWORD attributes = GetFileAttributesExW_orig(
		fileName,
		fInfoLevelId,
		lpFileInformation);

	if (attributes == ATTRIB_FAIL && HAS_VARIANTS()) {
		err = GetLastError();
		wchar_t realName[PATH_MAX];
		if (variant_to_sourceW(lpFileName, realName) == 0) {
			fileName = realName;
			attributes = GetFileAttributesExW_orig(
				fileName,
				fInfoLevelId,
				lpFileInformation);
		}
		if (attributes == ATTRIB_FAIL) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("%s '%S' (%X)\n", __FUNCTION__, fileName, attributes);

	if (attributes == ATTRIB_FAIL || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		handle_file_w(fileName, NULL, ACCESS_READ);
	return attributes;
}

__out HANDLE WINAPI FindFirstFileA_hook(
	__in  LPCSTR lpFileName,
	__out LPWIN32_FIND_DATAA lpFindFileData)
{
	char realName[MAX_PATH];
	LPCSTR fileName = lpFileName;
	DWORD err;
	HANDLE h = FindFirstFileA_orig(fileName, lpFindFileData);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(fileName, realName) == 0) {
			fileName = realName;
			h = FindFirstFileA_orig(fileName, lpFindFileData);
		}
		if (h == INVALID_HANDLE_VALUE) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("FindFirstFileA '%s'\n", fileName);
	handle_file(fileName, NULL, ACCESS_READ);
	return h;
}

__out HANDLE WINAPI FindFirstFileW_hook(
	__in  LPCWSTR lpFileName,
	__out LPWIN32_FIND_DATAW lpFindFileData)
{
	wchar_t realName[MAX_PATH];
	LPCWSTR fileName = lpFileName;
	DWORD err;
	HANDLE h = FindFirstFileW_orig(fileName, lpFindFileData);

	if (h == INVALID_HANDLE_VALUE && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_sourceW(fileName, realName) == 0) {
			fileName = realName;
			h = FindFirstFileW_orig(fileName, lpFindFileData);
		}
		if (h == INVALID_HANDLE_VALUE) {
			fileName = lpFileName;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("FindFirstFileW '%S'\n", fileName);

	handle_file_w(fileName, NULL, ACCESS_READ);
	return h;
}

BOOL WINAPI FindNextFileA_hook(
	__in  HANDLE hFindFile,
	__out LPWIN32_FIND_DATAA lpFindFileData)
{
	if (!FindNextFileA_orig(hFindFile, lpFindFileData))
		return 0;

	DEBUG_HOOK("FindNextFileA '%s'\n", lpFindFileData->cFileName);
	return 1;
}

BOOL WINAPI FindNextFileW_hook(
	__in  HANDLE hFindFile,
	__out LPWIN32_FIND_DATAW lpFindFileData)
{
	if (!FindNextFileW_orig(hFindFile, lpFindFileData))
		return 0;

	DEBUG_HOOK("FindNextFileW '%S'\n", lpFindFileData->cFileName);
	return 1;
}

int _access_hook(const char *pathname, int mode)
{
	int rc;
	char variantPathName[MAX_PATH];
	const char *path = pathname;
	DWORD err;

	rc = _access_orig(path, mode);

	if (rc == -1 && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(path, variantPathName) == 0) {
			path = variantPathName;
			rc = _access_orig(path, mode);
		}
		if (rc == -1) {
			path = pathname;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("_access_hook: %s (%d)\n", path, rc);
	handle_file(path, NULL, ACCESS_READ);
	return rc;
}

FILE *fopen_hook(const char *path, const char *mode)
{
	char variantPathName[MAX_PATH];
	const char *pathName = path;
	DWORD err;
	FILE *ret = fopen_orig(pathName, mode);

	if (ret == NULL && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(pathName, variantPathName) == 0) {
			pathName = variantPathName;
			ret = fopen_orig(pathName, mode);
		}
		if (ret == NULL) {
			pathName = path;
			SetLastError(err);
		}
	}

	/* Ignore mspdbsrv.exe, since it continues to run in the background */
	if(!lpApplicationName || strcasestr(lpApplicationName, "mspdbsrv.exe") == NULL
	   || strcasestr(lpApplicationName, "tup32detect.exe") == NULL) {
		tup_inject_dll(lpProcessInformation, s_depfilename, s_vardict_file);
	}
	DEBUG_HOOK("fopen %s mode = %s\n", pathName, mode);

	if (strchr(mode, 'w') == NULL &&
		strchr(mode, 'a') == NULL &&
		(strchr(mode, '+') == NULL || ret == NULL)) {
		handle_file(pathName, NULL, ACCESS_READ);
	} else {
		handle_file(pathName, NULL, ACCESS_WRITE);
	}
	return ret;
}

int rename_hook(const char *oldpath, const char *newpath)
{
	int rc;
	char variantPathName[MAX_PATH];
	const char *path = oldpath;
	DWORD err;

	DEBUG_HOOK("Rename hook ENTER\n");

	rc = rename_orig(path, newpath);

	if (rc == -1 && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(path, variantPathName) == 0) {
			path = variantPathName;
			rc = rename_orig(path, newpath);
		}
		if (rc == -1) {
			path = oldpath;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("rename_hook: %s => %s\n", path, newpath);
	handle_file(path, newpath, ACCESS_RENAME);
	return rc;
}

int remove_hook(const char *pathname)
{
	int rc;
	char variantPathName[MAX_PATH];
	const char *path = pathname;
	DWORD err;
	rc = remove_orig(path);

	if (rc == -1 && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(path, variantPathName) == 0) {
			path = variantPathName;
			rc = remove_orig(path);
		}
		if (rc == -1) {
			path = pathname;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("remove_hook: %s\n", path);
	handle_file(path, NULL, ACCESS_UNLINK);
	return rc;
}

int _stat64_hook(const char *path, void *buffer)
{
	int rc;
	char variantPathName[MAX_PATH];
	const char *pathName = path;
	DWORD err;

	rc = _stat64_orig(pathName, buffer);
	if (rc == -1 && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(pathName, variantPathName) == 0) {
			pathName = variantPathName;
			rc = _stat64_orig(pathName, buffer);
		}
		if (rc == -1) {
			pathName = path;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("_stat_hook: %s (%d)\n", pathName, rc);
	handle_file(pathName, NULL, ACCESS_READ);
	return rc;
}

int _stat32_hook(const char *path, void *buffer)
{
	int rc;
	char variantPathName[MAX_PATH];
	const char *pathName = path;
	DWORD err;

	rc = _stat32_orig(pathName, buffer);
	if (rc == -1 && HAS_VARIANTS()) {
		err = GetLastError();
		if (variant_to_source(pathName, variantPathName) == 0) {
			pathName = variantPathName;
			rc = _stat32_orig(pathName, buffer);
		}
		if (rc == -1) {
			pathName = path;
			SetLastError(err);
		}
	}

	DEBUG_HOOK("_stat_hook32: %s (%d)\n", pathName, rc);
	handle_file(pathName, NULL, ACCESS_READ);
	return rc;
}

typedef HMODULE(WINAPI *LoadLibraryA_t)(const char*);
typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, const char*);

struct remote_thread_t {
	LoadLibraryA_t load_library;
	GetProcAddress_t get_proc_address;
	char depfilename[MAX_PATH];
	char vardict_file[MAX_PATH];
	char execdir[MAX_PATH];
	char dll_name[MAX_PATH];
	char func_name[256];
};

struct remote_thread32_t {
	uint32_t load_library;
	uint32_t get_proc_address;
	char depfilename[MAX_PATH];
	char vardict_file[MAX_PATH];
	char execdir[MAX_PATH];
	char dll_name[MAX_PATH];
	char func_name[256];
}__attribute__((packed));

#define HOOK(name) { MODULE_NAME, #name, name##_hook, (void**)&name##_orig, 0 }
static struct patch_entry patch_table[] = {
#define MODULE_NAME "kernel32.dll"
	HOOK(OpenFile),
	HOOK(DeleteFileA),
	HOOK(DeleteFileW),
	HOOK(DeleteFileTransactedA),
	HOOK(DeleteFileTransactedW),
	HOOK(MoveFileA),
	HOOK(MoveFileW),
	HOOK(MoveFileExA),
	HOOK(MoveFileExW),
	HOOK(MoveFileWithProgressA),
	HOOK(MoveFileWithProgressW),
	HOOK(MoveFileTransactedA),
	HOOK(MoveFileTransactedW),
	HOOK(ReplaceFileA),
	HOOK(ReplaceFileW),
	HOOK(CopyFileA),
	HOOK(CopyFileW),
	HOOK(CopyFileExA),
	HOOK(CopyFileExW),
	HOOK(CopyFileTransactedA),
	HOOK(CopyFileTransactedW),
	HOOK(GetFileAttributesA),
	HOOK(GetFileAttributesW),
	HOOK(GetFileAttributesExA),
	HOOK(GetFileAttributesExW),
	HOOK(FindFirstFileA),
	HOOK(FindFirstFileW),
	HOOK(FindNextFileA),
	HOOK(FindNextFileW),
#undef MODULE_NAME
#define MODULE_NAME "ntdll.dll"
	HOOK(NtCreateFile),
	HOOK(NtOpenFile),
	HOOK(NtCreateUserProcess),
#undef MODULE_NAME
#define MODULE_NAME "msvcrt.dll"
	HOOK(_access),
	//HOOK(fopen),  // Redundant, as it chains to NtCreateFile anyway
	HOOK(rename),
	HOOK(remove),
	HOOK(_stat64),
	HOOK(_stat32),
};
#undef HOOK
#undef MODULE_NAME
enum { patch_table_len = sizeof(patch_table) / sizeof(patch_table[0]) };


/* -------------------------------------------------------------------------- */


void tup_inject_setexecdir(const char* dir)
{
	execdir[0] = '\0';
	strncat(execdir, dir, MAX_PATH);
	execdir[MAX_PATH - 1] = '\0';
}

/* -------------------------------------------------------------------------- */

static const char *strcasestr(const char *arg1, const char *arg2)
{
	const char *a, *b;

	for (; *arg1; arg1++) {

		a = arg1;
		b = arg2;

		while (tolower(*a++) == tolower(*b++)) {
			if (!*b) {
				return (arg1);
			}
		}

	}

	return(NULL);
}

static const wchar_t *wcscasestr(const wchar_t *arg1, const wchar_t *arg2)
{
	const wchar_t *a, *b;

	for (; *arg1; arg1++) {

		a = arg1;
		b = arg2;

		while (tolower(*a++) == tolower(*b++)) {
			if (!*b) {
				return (arg1);
			}
		}

	}

	return(NULL);
}

static int ignore_file(const char* file)
{
	if (!file)
		return 0;
	if (stricmp(file, "nul") == 0)
		return 1;
	if (stricmp(file, "nul:") == 0)
		return 1;
	if (stricmp(file, "prn") == 0)
		return 1;
	if (stricmp(file, "aux") == 0)
		return 1;
	if (stricmp(file, "con") == 0)
		return 1;
	if (strncmp(file, "com", 3) == 0 && isdigit(file[3]) && file[4] == '\0')
		return 1;
	if (strncmp(file, "lpt", 3) == 0 && isdigit(file[3]) && file[4] == '\0')
		return 1;
	if (strcasestr(file, "\\PIPE\\") != NULL)
		return 1;
	if (strnicmp(file, "PIPE\\", 5) == 0)
		return 1;
	if (strcasestr(file, "\\Device\\") != NULL)
		return 1;
	if (strstr(file, "$") != NULL)
		return 1;
	if (strncmp(file, "\\\\", 2) == 0)
		return 1;
	if (strcasestr(file, "SQM\\sqmcpp.log") != NULL)
		return 1;
	return 0;
}

static int ignore_file_w(const wchar_t* file)
{
	if (!file)
		return 0;
	if (wcsicmp(file, L"nul") == 0)
		return 1;
	if (wcsicmp(file, L"nul:") == 0)
		return 1;
	if (wcsicmp(file, L"prn") == 0)
		return 1;
	if (wcsicmp(file, L"aux") == 0)
		return 1;
	if (wcsicmp(file, L"con") == 0)
		return 1;
	if (wcsncmp(file, L"com", 3) == 0 && isdigit(file[3]) && file[4] == L'\0')
		return 1;
	if (wcsncmp(file, L"lpt", 3) == 0 && isdigit(file[3]) && file[4] == L'\0')
		return 1;
	if (wcscasestr(file, L"\\PIPE\\") != NULL)
		return 1;
	if (wcsstr(file, L"$") != NULL)
		return 1;
	if (wcsncmp(file, L"\\\\", 2) == 0)
		return 1;
	if (wcscasestr(file, L"SQM\\sqmcpp.log") != NULL)
		return 1;
	return 0;
}

static int canon_path(const char *file, char *dest)
{
	if (!file)
		return 0;
	if (is_full_path(file)) {
		/* Full path */
		PathCanonicalizeA(dest, tmpfile);
	} else {
		/* Relative path */
		char tmp[PATH_MAX];
		int cwdlen;
		int filelen = strlen(tmpfile);

		tmp[0] = 0;
		if (GetCurrentDirectory(sizeof(tmp), tmp) == 0) {
			/* TODO: Error handle? */
			return 0;
		}
		cwdlen = strlen(tmp);
		if (cwdlen + filelen + 2 >= (signed)sizeof(tmp)) {
			/* TODO: Error handle? */
			return 0;
		}
		tmp[cwdlen] = '\\';
		memcpy(tmp + cwdlen + 1, tmpfile, filelen + 1);
		PathCanonicalizeA(dest, tmp);
	}
	return strlen(dest);
}

static void mhandle_file(const char* file, const char* file2, enum access_type at, int line)
{
	DWORD save_error = GetLastError();

	char buf[ACCESS_EVENT_MAX_SIZE];
	struct access_event* e = (struct access_event*) buf;
	char* dest = (char*)(e + 1);
	int ret;
	if (line) {}

	if (ignore_file(file) || ignore_file(file2) || deph == INVALID_HANDLE_VALUE)
		goto exit;

	if (strncmp(file, "@tup@", 5) == 0) {
		const char *var = file + 6;
		e->at = ACCESS_VAR;
		e->len = strlen(var);
		e->len2 = 0;
		strcpy(dest, var);
		dest += e->len;
		*(dest++) = '\0';
		*(dest++) = '\0';
	} else {
		e->at = at;

		e->len = canon_path(file, dest);
		DEBUG_HOOK("Canonicalize1 [%i]: '%s' -> '%s', len=%i\n", line, file, dest, e->len);
		dest += e->len;
		*(dest++) = '\0';

		e->len2 = canon_path(file2, dest);
		DEBUG_HOOK("Canonicalize2: '%s' -> '%s' len2=%i\n", file2, file2 ? dest : NULL, e->len2);
		dest += e->len2;
		*(dest++) = '\0';
	}

	DEBUG_HOOK("%s: '%s' '%s'\n", access_type_name[at], file, file2);
	ret = writef((char*)e, dest - (char*)e);
	DEBUG_HOOK("writef %d\n", ret);
	if (ret) {}

exit:
	SetLastError(save_error);
}

static void handle_file_w(const wchar_t* file, const wchar_t* file2, enum access_type at)
{
	DWORD save_error = GetLastError();

	char buf[ACCESS_EVENT_MAX_SIZE];
	char afile[PATH_MAX];
	char afile2[PATH_MAX];
	size_t fsz;
	size_t f2sz;
	struct access_event* e = (struct access_event*) buf;
	char* dest = (char*)(e + 1);
	int ret;
	int count;
	wchar_t backslash_prefix[] = L"\\\\?\\"; /* \\?\ can be used as a prefix in wide-char paths */
	const int backslash_prefix_len = 4;

	if (ignore_file_w(file) || ignore_file_w(file2) || deph == INVALID_HANDLE_VALUE)
		goto exit;

	if (file)
		if (wcsncmp(file, backslash_prefix, backslash_prefix_len) == 0)
			file += backslash_prefix_len;
	if (file2)
		if (wcsncmp(file2, backslash_prefix, backslash_prefix_len) == 0)
			file2 += backslash_prefix_len;

	fsz = file ? wcslen(file) : 0;
	f2sz = file2 ? wcslen(file2) : 0;

	e->at = at;

	count = WideCharToMultiByte(CP_UTF8, 0, file, fsz, afile, PATH_MAX, NULL, NULL);
	afile[count] = 0;
	count = WideCharToMultiByte(CP_UTF8, 0, file2, f2sz, afile2, PATH_MAX, NULL, NULL);
	afile2[count] = 0;

	e->len = canon_path(afile, dest);
	dest += e->len;
	*(dest++) = '\0';

	e->len2 = canon_path(afile2, dest);
	dest += e->len2;
	*(dest++) = '\0';

	DEBUG_HOOK("%s [wide, %i, %i]: '%S', '%S'\n", access_type_name[at], e->len, e->len2, file, file2);
	ret = writef((char*)e, dest - (char*)e);
	DEBUG_HOOK("writef [wide] %d\n", ret);
	if (ret) {}

exit:
	SetLastError(save_error);
}

static int open_file(const char *depfilename)
{
	deph = CreateFile(depfilename, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (deph == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "tup error: Unable to open dependency file '%s' in dllinject. Windows error code: 0x%08lx\n", depfilename, GetLastError());
		return -1;
	}
	return 0;
}

static int open_vardict_file(const char *vardict_file)
{
	vardicth = CreateFile(vardict_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (vardicth == INVALID_HANDLE_VALUE) {
		/* Not an error if the file doesn't exist - we may not have a vardict. */
		if (GetLastError() != ERROR_FILE_NOT_FOUND) {
			fprintf(stderr, "tup error: Unable to open vardict file '%s' in dllinject. Windows error code: 0x%08lx\n", vardict_file, GetLastError());
			return -1;
		}
	}
	return 0;
}

BOOL WINAPI DllMain(HANDLE HDllHandle, DWORD Reason, LPVOID Reserved)
{
	(void)HDllHandle;

	CHAR filename[1024];
	HANDLE currentProcess;

	currentProcess = GetCurrentProcess();
	GetProcessImageFileNameA(currentProcess, filename, 1024);

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
	{
		DEBUG_HOOK("DllMain attaching to %s (%s)\n", filename, Reserved == NULL ? "DYNAMIC" : "STATIC");
		if (hHeap == INVALID_HANDLE_VALUE) {
			hHeap = GetProcessHeap();

			if (hHeap == INVALID_HANDLE_VALUE) {
				DEBUG_HOOK("Unable to retrieve process heap\n");
				return FALSE;
			}

			MemoryPool = HeapAlloc(hHeap, 0, TotalMemory);
			if (MemoryPool == NULL) {
				DEBUG_HOOK("Memory pool allocation failed\n");
				return FALSE;
			}

			hMemoryLock = CreateMutex(NULL, FALSE, NULL);
			if (hMemoryLock == NULL) {
				DEBUG_HOOK("Memory pool mutex creation failed\n");
				return FALSE;
			}

			DEBUG_HOOK("DLL Heap created at %X\n", hHeap);
		} else {
			DEBUG_HOOK("Heap already initialized!\n");
		}
		break;
	}
	case DLL_PROCESS_DETACH:
		DEBUG_HOOK("DllMain detaching from %s (%s)\n", filename, Reserved == NULL ? "ERROR" : "TERMINATING");
		// Only free heap if we are being dynamically unloaded
		// Not used while using process heap
		if (hHeap != INVALID_HANDLE_VALUE && Reserved == NULL) {
		}
		break;
	case DLL_THREAD_ATTACH:
		DEBUG_HOOK("DllMain attached a new thread to %s\n", filename);
		break;
	}


	return TRUE;
}

/* -------------------------------------------------------------------------- */

typedef DWORD(*tup_init_t)(remote_thread_t*);
DWORD tup_inject_init(remote_thread_t* r)
{
	static int initialised = 0;
	char filename[MAX_PATH];
	OSVERSIONINFO osinfo;

	if (initialised) {
		DEBUG_HOOK("tup_inject_init ran twice..\n");
		return 0;
	}

	initialised = 1;

	if (!GetProcessImageFileNameA(GetCurrentProcess(), filename, sizeof(filename))) {
		return 1;
	}

	if (r != NULL) {
		DEBUG_HOOK("Inside tup_dllinject_init '%s' '%s' '%s' '%s' '%s'\n",
			filename,
			r->execdir,
			r->dll_name,
			r->func_name,
			r->depfilename);
	} else {
		DEBUG_HOOK("Inside tup_dllinject_init 'tup.exe'\n");
	}

	DEBUG_HOOK(" - injected into %d: %s\n", GetCurrentProcessId(), GetCommandLineA());

	if (r != NULL) {
		tup_inject_setexecdir(r->execdir);

		if (open_vardict_file(r->vardict_file))
			return 1;

		if (vardicth != INVALID_HANDLE_VALUE) {
			vardict_fd = _open_osfhandle((intptr_t)vardicth, 0);
		}
		snprintf(vardict_env, sizeof(vardict_env), TUP_VARDICT_NAME "=%i", vardict_fd);
		vardict_env[sizeof(vardict_env) - 1] = 0;
		putenv(vardict_env);

		strcpy(s_vardict_file, r->vardict_file);

		handle_file(filename, NULL, ACCESS_READ);

		if (open_file(r->depfilename))
			return 1;

		strcpy(s_depfilename, r->depfilename);
	}

	/* Find top-level directory, start at CWD */
	getcwd(tuptopdir, MAX_PATH);

	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	char pathBuffer[MAX_PATH];
	BOOL foundTopLevel = FALSE;

	while (foundTopLevel == FALSE) {
		snprintf(pathBuffer, MAX_PATH, "%s\\.tup", tuptopdir);
		DEBUG_HOOK("Checking %s for tuptopdir\n", pathBuffer);
		if (PathFileExists(pathBuffer)) {
			foundTopLevel = TRUE;
		} else {
			// Possibly a variant? (Not a variant if there is only a tup.config at the root hence the else)
			if (!HAS_VARIANTS()) {
				snprintf(pathBuffer, MAX_PATH, "%s\\tup.config", tuptopdir);
				if (PathFileExists(pathBuffer)) {
					if (!add_variant(tuptopdir)) {
						DEBUG_HOOK("Unable to add variant\n");
					}
					DEBUG_HOOK("%s in Variant: %s\n", filename, tuptopdir);
				}
			}
			snprintf(tuptopdir, MAX_PATH, "%.*s", (int)(strrchr(tuptopdir, '\\') - tuptopdir), tuptopdir);
		}
	}

	if (foundTopLevel) {
		DEBUG_HOOK("Found Tup-Src dir at: %s\n", tuptopdir);
	} else {
		DEBUG_HOOK("FATAL-ERROR: Did not find Tup-Src dir\n");
	}

	// tup.exe needs to find all variant directories
	if (r == NULL) {
		snprintf(pathBuffer, MAX_PATH, "%s\\*", tuptopdir);
		hFind = FindFirstFile(pathBuffer, &ffd);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && ffd.cFileName[0] != '.') {
					sprintf(pathBuffer, "%s\\%s\\tup.config", tuptopdir, ffd.cFileName);
					if (PathFileExists(pathBuffer)) {
						sprintf(pathBuffer, "%s\\%s", tuptopdir, ffd.cFileName);
						DEBUG_HOOK("TUP: Found Variant Directory: %s\n", pathBuffer);
						if (!add_variant(pathBuffer)) {
							DEBUG_HOOK("Unable to add variant\n");
						}
					}
				}
			} while (FindNextFile(hFind, &ffd) != 0);
		}
	}

	/* What a horrible API... */
	osinfo.dwOSVersionInfoSize = sizeof(osinfo);
	GetVersionEx(&osinfo);

	DEBUG_HOOK("Os Version: %X - %X\n", osinfo.dwMajorVersion, osinfo.dwMinorVersion);

	if (osinfo.dwMajorVersion >= 6) {
		/* Only hot patch for Windows Vista and above. Hot patching
		 * here gets our hook for FindFirstFile, which iat patching
		 * doesn't get for some reason. I also tried to just iat patch
		 * NtQueryDirectoryFile(), but then that ends up crashing for
		 * some reason.
		 *
		 * For XP, the FindFirstFile hook works with iat patching, but
		 * hot patching breaks file removal for some reason, so for
		 * example 'gcc -flto foo.o -o foo.exe' will fail.
		 */
		hot_patch(patch_table, patch_table + patch_table_len);
	}
	iat_patch(patch_table, patch_table + patch_table_len);

	return 0;
}

inline long long unsigned int low32(long long unsigned int num)
{
	return num & 0x00000000ffffffff;
}
inline long long unsigned int high32(long long unsigned int num)
{
	return num >> 32;
}

struct remote_stub32_t {
	uint8_t stub[22];
	uint8_t remote_init[60];
}__attribute__((packed));

static struct remote_stub32_t remote_stub32 = {
	.stub = {
		0x68, 0x00, 0x00, 0x00, 0x00,       // push   $0x00000000
		0x9c,                               // pushf
		0x60,                               // pusha
		0x68, 0xef, 0xbe, 0xad, 0xde,       // push   $0xdeadbeef
		0xb8, 0xef, 0xbe, 0xad, 0xde,       // mov    $0xdeadbeef,%eax
		0xff, 0xd0,                         // call   *%eax
		0x61,                               // popa
		0x9d,                               // popf
		0xc3                                // ret
	},
	.remote_init = {
		0x55,                               // push   %ebp
		0x89, 0xe5,                         // mov    %esp,%ebp
		0x53,                               // push   %ebx
		0x83, 0xec, 0x14,                   // sub    $0x14,%esp
		0x8b, 0x5d, 0x08,                   // mov    0x8(%ebp),%ebx
		0x8d, 0x83, 0x14, 0x03, 0x00, 0x00, // lea    0x314(%ebx),%eax
		0x89, 0x04, 0x24,                   // mov    %eax,(%esp)
		0xff, 0x13,                         // call   *(%ebx)
		0x85, 0xc0,                         // test   %eax,%eax
		0x51,                               // push   %ecx
		0x74, 0x1b,				            // je 0x1b
		0x8d, 0x93, 0x18, 0x04, 0x00, 0x00, // lea    0x418(%ebx),%edx
		0x89, 0x54, 0x24, 0x04,             // mov    %edx,0x4(%esp)
		0x89, 0x04, 0x24,                   // mov    %eax,(%esp)
		0xff, 0x53, 0x04,                   // call   *0x4(%ebx)
		0x85, 0xc0,                         // test   %eax,%eax
		0x52,                               // push   %edx
		0x52,                               // push   %edx
		0x74, 0x05,				            // je 0x05
		0x89, 0x1c, 0x24,                   // mov    %ebx,(%esp)
		0xff, 0xd0,                         // call   *%eax
		0x8b, 0x5d, 0xfc,                   // mov    -0x4(%ebp),%ebx
		0xc9,                               // leave
		0xc2, 0x04, 0x00                    // ret    $0x4
	}
};

#ifdef _WIN64

struct remote_stub64_t {
	uint8_t stub[96];
	uint8_t remote_init[56];
}__attribute__((packed));

static struct remote_stub64_t remote_stub64 = {
	.stub = {
		0x48, 0x83, 0xec, 0x08,                                     // sub    $0x8,%rsp
		0xc7, 0x04, 0x24, 0x77, 0x66, 0x55, 0x00,                   // movl   $0x556677,(%rsp)
		0xc7, 0x44, 0x24, 0x04, 0x44, 0x33, 0x22, 0x11,             // movl   $0x11223344,0x4(%rsp)
		0x9c,                                                       // pushfq
		0x41, 0x57,                                                 // push   %r15
		0x41, 0x56,                                                 // push   %r14
		0x41, 0x55,                                                 // push   %r13
		0x41, 0x54,                                                 // push   %r12
		0x41, 0x53,                                                 // push   %r11
		0x41, 0x52,                                                 // push   %r10
		0x41, 0x51,                                                 // push   %r9
		0x41, 0x50,                                                 // push   %r8
		0x55,                                                       // push   %rbp
		0x57,                                                       // push   %rdi
		0x56,                                                       // push   %rsi
		0x52,                                                       // push   %rdx
		0x51,                                                       // push   %rcx
		0x53,                                                       // push   %rbx
		0x50,                                                       // push   %rax
		0x48, 0x31, 0xc9,                                           // xor    %rcx,%rcx
		0x48, 0xb9, 0x88, 0x77, 0x66, 0x55, 0x00, 0x00, 0x00, 0x11, // movabs $0x1100000055667788,%rcx
		0x48, 0x31, 0xc0,                                           // xor    %rax,%rax
		0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x00, 0x00, 0x00, 0x99, // movabs $0x9900000055667788,%rax
		0xff, 0xd0,                                                 // callq  *%rax
		0x58,                                                       // pop    %rax
		0x5b,                                                       // pop    %rbx
		0x59,                                                       // pop    %rcx
		0x5a,                                                       // pop    %rdx
		0x5e,                                                       // pop    %rsi
		0x5f,                                                       // pop    %rdi
		0x5d,                                                       // pop    %rbp
		0x41, 0x58,                                                 // pop    %r8
		0x41, 0x59,                                                 // pop    %r9
		0x41, 0x5a,                                                 // pop    %r10
		0x41, 0x5b,                                                 // pop    %r11
		0x41, 0x5c,                                                 // pop    %r12
		0x41, 0x5d,                                                 // pop    %r13
		0x41, 0x5e,                                                 // pop    %r14
		0x41, 0x5f,                                                 // pop    %r15
		0x9d,                                                       // popfq
		0xc3,                                                       // retq
	},
	.remote_init = {
		0x53,                                                       // push   %rbx
		0x48, 0x83, 0xec, 0x20,                                     // sub    $0x20,%rsp
		0x48, 0x89, 0xcb,                                           // mov    %rcx,%rbx
		0x48, 0x8d, 0x89, 0x1c, 0x03, 0x00, 0x00,                   // lea    0x31c(%rcx),%rcx
		0xff, 0x13,                                                 // callq  *(%rbx)
		0x48, 0x85, 0xc0,                                           // test   %rax,%rax
		0x74, 0x1c,                                                 // je     93 <remote_init+0x33>      // jmpq version
		0x48, 0x8d, 0x93, 0x20, 0x04, 0x00, 0x00,                   // lea    0x420(%rbx),%rdx
		0x48, 0x89, 0xc1,                                           // mov    %rax,%rcx
		0xff, 0x53, 0x08,                                           // callq  *0x8(%rbx)
		0x48, 0x85, 0xc0,                                           // test   %rax,%rax
		0x74, 0x0a,                                                 // je     93 <remote_init+0x33>      // jmpq version
		0x48, 0x89, 0xd9,                                           // mov    %rbx,%rcx
		0x48, 0x83, 0xc4, 0x20,                                     // add    $0x20,%rsp
		0x5b,                                                       // pop    %rbx
		0xff, 0xe0,                                                 // jmpq   *%rax
		0x48, 0x83, 0xc4, 0x20,                                     // add    $0x20,%rsp
		0x5b,                                                       // pop    %rbx
		0xc3,                                                       // retq
	}
};

#endif

static uint32_t LOAD_LIBRARY_32 = 0;
static uint32_t GET_PROC_ADDRESS_32 = 0;

#define BUFSIZE 4096

BOOL get_wow64_addresses(void)
{
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO  siStartInfo;
	BOOL ret;

	TCHAR szCmdline[] = TEXT("tup32detect.exe");

	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Pipe stdout
	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		return FALSE;

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		return FALSE;

	// create process
	memset(&siStartInfo, 0, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	memset(&piProcInfo, 0, sizeof(PROCESS_INFORMATION));

	ret = CreateProcessA(
		NULL,
		szCmdline,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&siStartInfo,
		&piProcInfo);

	if (!ret) {
		DEBUG_HOOK("Unable to spawn tup32detect.exe\n");
		return FALSE;
	}

	ret = ReadFile(g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
	if (!ret || dwRead == 0)
		return FALSE;

	if (sscanf(chBuf, "%x-%x", &LOAD_LIBRARY_32, &GET_PROC_ADDRESS_32) != 2)
		return FALSE;

	DEBUG_HOOK("Got addresses: %x, %x\n", LOAD_LIBRARY_32, GET_PROC_ADDRESS_32);
	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	return TRUE;
}


#ifdef _WIN64

int tup_inject_dll(
	LPPROCESS_INFORMATION lpProcessInformation,
	const char *depfilename,
	const char *vardict_file)
{
	char* remote_data;
	size_t code_size;
	DWORD old_protect;
	HANDLE process;

	BOOL bWow64 = 0;
	IsWow64Process(lpProcessInformation->hProcess, &bWow64);

	CHAR buffer[1024];
	if (GetProcessImageFileNameA(lpProcessInformation->hProcess, buffer, 1024)) {
		DEBUG_HOOK("%s is WOW64: %i\n", buffer, bWow64);
	}

	// Loading 32bit application from 64bit application
	if (bWow64) {
		remote_thread32_t remote;

		if (GET_PROC_ADDRESS_32 == 0) {
			if (!get_wow64_addresses()) {
				DEBUG_HOOK("Unable to retrieve WOW64 info\n");
				return -1;
			}
		}

		memset(&remote, 0, sizeof(remote));
		remote.load_library = LOAD_LIBRARY_32;
		remote.get_proc_address = GET_PROC_ADDRESS_32;
		strcpy(remote.depfilename, depfilename);
		strcpy(remote.vardict_file, vardict_file);
		strcat(remote.execdir, execdir);
		strcat(remote.dll_name, execdir);
		strcat(remote.dll_name, "\\");
		strcat(remote.dll_name, "tup-dllinject32.dll");
		strcat(remote.func_name, "tup_inject_init");

		WOW64_CONTEXT ctx;
		ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
		if (!Wow64GetThreadContext(lpProcessInformation->hThread, &ctx))
			return -1;

		/* Align code_size to a 16 byte boundary */
		code_size = (sizeof(remote_stub32) + 0x0F) & ~0x0F;

		DEBUG_HOOK("Injecting dll '%s' '%s' %s' '%s'\n",
			remote.execdir,
			remote.dll_name,
			remote.func_name,
			remote.depfilename,
			remote.vardict_file);

		process = lpProcessInformation->hProcess;

		if (!WaitForInputIdle(process, INFINITE))
			return -1;

		remote_data = (char*)VirtualAllocEx(
			process,
			NULL,
			code_size + sizeof(remote),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (!remote_data)
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_READWRITE, &old_protect))
			return -1;

		unsigned char code[code_size];
		memset(code, 0, code_size);

		memcpy(code, &remote_stub32, sizeof(remote_stub32));

		*(DWORD*)(code + 0x1) = ctx.Eip;											// Return addr
		*(DWORD*)(code + 0x8) = (DWORD)((DWORD_PTR)remote_data + code_size);							// Arg (ptr to remote (TCB))
		*(DWORD*)(code + 0xd) = (DWORD)((DWORD_PTR)remote_data + ((DWORD_PTR)&remote_stub32.remote_init - (DWORD_PTR)&remote_stub32));	// Func (ptr to remote_init)

		if (!WriteProcessMemory(process, remote_data, code, code_size, NULL))
			return -1;

		if (!WriteProcessMemory(process, remote_data + code_size, &remote, sizeof(remote), NULL))
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_EXECUTE_READ, &old_protect))
			return -1;

		if (!FlushInstructionCache(process, remote_data, code_size + sizeof(remote)))
			return -1;

		ctx.Eip = (DWORD_PTR)remote_data;
		ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
		if (!Wow64SetThreadContext(lpProcessInformation->hThread, &ctx))
			return -1;
	} else {
		HMODULE kernel32;
		remote_thread_t remote;

		memset(&remote, 0, sizeof(remote));
		kernel32 = LoadLibraryA("kernel32.dll");
		remote.load_library = (LoadLibraryA_t)GetProcAddress(kernel32, "LoadLibraryA");
		remote.get_proc_address = (GetProcAddress_t)GetProcAddress(kernel32, "GetProcAddress");
		strcpy(remote.depfilename, depfilename);
		strcpy(remote.vardict_file, vardict_file);
		strcat(remote.execdir, execdir);
		strcat(remote.dll_name, execdir);
		strcat(remote.dll_name, "\\");
		strcat(remote.dll_name, "tup-dllinject.dll");
		strcat(remote.func_name, "tup_inject_init");

		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (!GetThreadContext(lpProcessInformation->hThread, &ctx)) {
			DEBUG_HOOK("Unable to get thread context\n");
			return -1;
		}

		/* Align code_size to a 16 byte boundary */
		code_size = (sizeof(remote_stub64) + 0x0F) & ~0x0F;

		DEBUG_HOOK("Injecting dll '%s' '%s' %s' '%s'\n",
			remote.execdir,
			remote.dll_name,
			remote.func_name,
			remote.depfilename,
			remote.vardict_file);

		process = lpProcessInformation->hProcess;

		if (!WaitForInputIdle(process, INFINITE))
			return -1;

		remote_data = (char*)VirtualAllocEx(
			process,
			NULL,
			code_size + sizeof(remote),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (!remote_data)
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_READWRITE, &old_protect))
			return -1;

		unsigned char code[code_size];
		memset(code, 0, code_size);

		memcpy(code, &remote_stub64, sizeof(remote_stub64));
		*(DWORD*)(code + 0x7) = low32(ctx.Rip);
		*(DWORD*)(code + 0xf) = high32(ctx.Rip);
		*(DWORD64*)(code + 0x30) = (long long unsigned int)(remote_data + code_size);
		*(DWORD64*)(code + 0x3d) = (long long unsigned int)(DWORD_PTR)remote_data + ((DWORD_PTR)&remote_stub64.remote_init - (DWORD_PTR)&remote_stub64);

		if (!WriteProcessMemory(process, remote_data, code, code_size, NULL))
			return -1;

		if (!WriteProcessMemory(process, remote_data + code_size, &remote, sizeof(remote), NULL))
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_EXECUTE_READ, &old_protect))
			return -1;

		if (!FlushInstructionCache(process, remote_data, code_size + sizeof(remote)))
			return -1;

		ctx.Rip = (DWORD_PTR)remote_data;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (!SetThreadContext(lpProcessInformation->hThread, &ctx))
			return -1;
	}

	return 0;
}
#endif


#if __DBG_W64 == 1
static void printHex(const void *lpvbits, const unsigned int n)
{
    char* data = (char*) lpvbits;
    unsigned int i = 0;
    char line[17] = {};
    printf("%.8X | ", (unsigned char*)data);
    while ( i < n ) {
        line[i%16] = *(data+i);
        if ((line[i%16] < 32) || (line[i%16] > 126)) {
            line[i%16] = '.';
        }
        printf("%.2X", (unsigned char)*(data+i));
        i++;
        if (i%4 == 0) {
            if (i%16 == 0) {
                if (i < n-1)
                    printf(" | %s\n%.8X | ", &line, data+i);
            } else {
                printf(" ");
            }
        }
    }
    while (i%16 > 0) {
        (i%4 == 0)?printf("   "):printf("  ");
        line[i%16] = ' ';
        i++;
    }
    printf(" | %s\n", &line);
}
#endif

inline long long unsigned int low32(long long unsigned int tall)
{
        return tall & 0x00000000ffffffff;
}
inline long long unsigned int high32(long long unsigned int tall)
{
        return tall >> 32;
}

struct remote_stub_t {
	uint8_t stub[23];
	uint8_t fileA_Hook[39];
	uint8_t fileW_Hook[39];
	uint8_t remote_init[60];
}__attribute__((packed));

static struct remote_stub_t remote_stub32 = {
	.stub = {
0x68, 0x00, 0x00, 0x00, 0x00,
0x9c,
0x60,
0x68, 0xef, 0xbe, 0xad, 0xde,
0xb8, 0xef, 0xbe, 0xad, 0xde,
0xff, 0xd0,
0x61,
0x9d,
0xc3
},
	.fileA_Hook = {
0x55,
0x89, 0xe5,
0x83, 0xec, 0x18,
0x8b, 0x45, 0x0c,
0x89, 0x44, 0x24, 0x04,
0x8b, 0x45, 0x08,
0x89, 0x04, 0x24,
0xff, 0x15, 0x78, 0x00, 0x00, 0x00,
0x85, 0xc0,
0x52,
0x0f, 0x95, 0xc0,
0x52,
0x0f, 0xb6, 0xc0,
0xc9,
0xc2, 0x08, 0x00
},

	.fileW_Hook = {
0x55,
0x89, 0xe5,
0x83, 0xec, 0x18,
0x8b, 0x45, 0x0c,
0x89, 0x44, 0x24, 0x04,
0x8b, 0x45, 0x08,
0x89, 0x04, 0x24,
0xff, 0x15, 0x7c, 0x00, 0x00, 0x00,
0x85, 0xc0,
0x51,
0x0f, 0x95, 0xc0,
0x51,
0x0f, 0xb6, 0xc0,
0xc9,
0xc2, 0x08, 0x00
},

	.remote_init = {
0x55,
0x89, 0xe5,
0x53,
0x83, 0xec, 0x14,
0x8b, 0x5d, 0x08,
0x8d, 0x83, 0x14, 0x03, 0x00, 0x00,
0x89, 0x04, 0x24,
0xff, 0x13,
0x85, 0xc0,
0x51,
0x74, 0x1b,				// JE 0x1b
0x8d, 0x93, 0x18, 0x04, 0x00, 0x00,
0x89, 0x54, 0x24, 0x04,
0x89, 0x04, 0x24,
0xff, 0x53, 0x04,
0x85, 0xc0,
0x52,
0x52,
0x74, 0x05,				// JE 0x05
0x89, 0x1c, 0x24,
0xff, 0xd0,
0x8b, 0x5d, 0xfc,
0xc9,
0xc2, 0x04, 0x00}
};

static uint32_t LOAD_LIBRARY_32 = 0;
static uint32_t GET_PROC_ADDRESS_32 = 0;

#define BUFSIZE 4096

BOOL get_wow64_addresses(void)
{
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOA  siStartInfo;
	BOOL ret;
	char cmdline[MAX_PATH];

	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;

	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Pipe stdout
	if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0) )
		return FALSE;

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
		return FALSE;

	// create process
	memset(&siStartInfo, 0, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	memset(&piProcInfo, 0, sizeof(PROCESS_INFORMATION));

	if(snprintf(cmdline, MAX_PATH, "%s\\%s", execdir, "tup32detect.exe") >= MAX_PATH) {
		fprintf(stderr, "tup error: cmdline is sized wrong for tup32detect.exe");
		return FALSE;
	}

	// Detect and avoid inception!
	if (CreateProcessA_orig != NULL)
		ret = CreateProcessA_orig(
				NULL,
				cmdline,
				NULL,
				NULL,
				TRUE,
				0,
				NULL,
				NULL,
				&siStartInfo,
				&piProcInfo);
	else
		ret = CreateProcessA(
				NULL,
				cmdline,
				NULL,
				NULL,
				TRUE,
				0,
				NULL,
				NULL,
				&siStartInfo,
				&piProcInfo);

	if (!ret) {
		DEBUG_HOOK("Unable to spawn tup32detect.exe\n");
		return FALSE;
	}

	ret = ReadFile( g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
	if (!ret || dwRead == 0)
		return FALSE;

	if (sscanf(chBuf, "%x-%x", &LOAD_LIBRARY_32, &GET_PROC_ADDRESS_32) != 2)
		return FALSE;

	DEBUG_HOOK("Got addresses: %x, %x\n", LOAD_LIBRARY_32, GET_PROC_ADDRESS_32);
	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);

	return TRUE;
}



#else

int tup_inject_dll(
	LPPROCESS_INFORMATION lpProcessInformation,
	const char *depfilename,
	const char *vardict_file)
{
	char* remote_data;
	size_t code_size;
	DWORD old_protect;
	HANDLE process;
	HMODULE kernel32;
	remote_thread_t remote;
	BOOL bWow64 = 0;

	// Make sure we do not try to inject into 64bit processes
	IsWow64Process(lpProcessInformation->hProcess, &bWow64);
	if (!bWow64) {
		fprintf(stderr, "tup error: Unable to start 64bit applications from 32bit\n");
		fflush(stderr);
		return -1;
	}

	memset(&remote, 0, sizeof(remote));
	kernel32 = LoadLibraryA("kernel32.dll");
	remote.load_library = (LoadLibraryA_t)GetProcAddress(kernel32, "LoadLibraryA");
	remote.get_proc_address = (GetProcAddress_t)GetProcAddress(kernel32, "GetProcAddress");
	strcpy(remote.depfilename, depfilename);
	strcpy(remote.vardict_file, vardict_file);
	strcat(remote.execdir, execdir);
	strcat(remote.dll_name, execdir);
	strcat(remote.dll_name, "\\");
	strcat(remote.dll_name, "tup-dllinject32.dll");
	strcat(remote.func_name, "tup_inject_init");

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(lpProcessInformation->hThread, &ctx)) {
		DEBUG_HOOK("Unable to get thread context\n");
		return -1;
	}

	/* Align code_size to a 16 byte boundary */
	code_size = (sizeof(remote_stub32) + 0x0F) & ~0x0F;

	IsWow64Process(lpProcessInformation->hProcess, &bWow64);

	// WOW64
	DEBUG_HOOK("%s is WOW64: %i\n", GetCommandLineA(), bWow64);
	if (bWow64) {
		remote_thread32_t remote;

		if (GET_PROC_ADDRESS_32 == 0) {
			if ( ! get_wow64_addresses() ) {
				printf("Unable to retrieve WOW64 info\n");
				return -1;
			}
		}

		memset(&remote, 0, sizeof(remote));
		remote.load_library = LOAD_LIBRARY_32;
		remote.get_proc_address = GET_PROC_ADDRESS_32;
		strcpy(remote.depfilename, depfilename);
		strcpy(remote.vardict_file, vardict_file);
		strcat(remote.execdir, execdir);
		strcat(remote.dll_name, execdir);
		strcat(remote.dll_name, "\\");
		strcat(remote.dll_name, "tup-dllinject32.dll");
		strcat(remote.func_name, "tup_inject_init");

		WOW64_CONTEXT ctx;
		ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
		if ( !Wow64GetThreadContext( lpProcessInformation->hThread, &ctx ) )
			return -1;

		/* Align code_size to a 16 byte boundary */
		code_size = (sizeof(remote_stub32) + 0x0F) & ~0x0F;
	
		DEBUG_HOOK("Injecting dll '%s' '%s' %s' '%s'\n",
			remote.execdir,
			remote.dll_name,
			remote.func_name,
			remote.depfilename,
			remote.vardict_file);

		process = lpProcessInformation->hProcess;

		if (!WaitForInputIdle(process, INFINITE))
			return -1;

		remote_data = (char*) VirtualAllocEx(
			process,
			NULL,
			code_size + sizeof(remote),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (!remote_data)
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_READWRITE, &old_protect))
			return -1;

		unsigned char code[code_size];

		memcpy( code, &remote_stub32, code_size );

		*(DWORD*)(code + 0x1) = ctx.Eip;											// Return addr
		*(DWORD*)(code + 0x8) = (DWORD)((DWORD_PTR)remote_data + code_size);							// Arg (ptr to remote (TCB))
		*(DWORD*)(code + 0xd) = (DWORD)((DWORD_PTR)remote_data + ((DWORD_PTR)&remote_stub32.remote_init - (DWORD_PTR)&remote_stub32));	// Func (ptr to remote_init)

		if (!WriteProcessMemory(process, remote_data, code, code_size, NULL))
			return -1;

		if (!WriteProcessMemory(process, remote_data + code_size, &remote, sizeof(remote), NULL))
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_EXECUTE_READ, &old_protect))
			return -1;

		if (!FlushInstructionCache(process, remote_data, code_size + sizeof(remote)))
			return -1;

		ctx.Eip = (DWORD_PTR)remote_data;
		ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
		if( !Wow64SetThreadContext( lpProcessInformation->hThread, &ctx ) )
			return -1;
	} else {
#ifdef _WIN64
		HMODULE kernel32;
		remote_thread_t remote;

		memset(&remote, 0, sizeof(remote));
		kernel32 = LoadLibraryA("kernel32.dll");
		remote.load_library = (LoadLibraryA_t) GetProcAddress(kernel32, "LoadLibraryA");
		remote.get_proc_address = (GetProcAddress_t) GetProcAddress(kernel32, "GetProcAddress");
		strcpy(remote.depfilename, depfilename);
		strcpy(remote.vardict_file, vardict_file);
		strcat(remote.execdir, execdir);
		strcat(remote.dll_name, execdir);
		strcat(remote.dll_name, "\\");
		strcat(remote.dll_name, "tup-dllinject.dll");
		strcat(remote.func_name, "tup_inject_init");

		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if( !GetThreadContext( lpProcessInformation->hThread, &ctx ) )
			return -1;

		/* Align code_size to a 16 byte boundary */
		code_size = (  (uintptr_t) &remote_end
			     - (uintptr_t) &remote_stub + 0x0F)
			  & ~0x0F;

		DEBUG_HOOK("Injecting dll '%s' '%s' %s' '%s'\n",
			remote.execdir,
			remote.dll_name,
			remote.func_name,
			remote.depfilename,
			remote.vardict_file);

		process = lpProcessInformation->hProcess;

		if (!WaitForInputIdle(process, INFINITE))
			return -1;

		remote_data = (char*) VirtualAllocEx(
			process,
			NULL,
			code_size + sizeof(remote),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (!remote_data)
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_READWRITE, &old_protect))
			return -1;

		unsigned char code[code_size];

		memcpy( code, &remote_stub, code_size );
		*(DWORD*)(code + 0x7) = low32(ctx.Rip);
		*(DWORD*)(code + 0xf) = high32(ctx.Rip);
		*(DWORD64*)(code + 0x30) = (long long unsigned int)(remote_data + code_size);
		*(DWORD64*)(code + 0x3d) = (long long unsigned int)(DWORD_PTR)remote_data + ((DWORD_PTR)&remote_init - (DWORD_PTR)&remote_stub);

		if (!WriteProcessMemory(process, remote_data, code, code_size, NULL))
			return -1;

		if (!WriteProcessMemory(process, remote_data + code_size, &remote, sizeof(remote), NULL))
			return -1;

		if (!VirtualProtectEx(process, remote_data, code_size + sizeof(remote), PAGE_EXECUTE_READ, &old_protect))
			return -1;

		if (!FlushInstructionCache(process, remote_data, code_size + sizeof(remote)))
			return -1;

		ctx.Rip = (DWORD_PTR)remote_data;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if( !SetThreadContext( lpProcessInformation->hThread, &ctx ) )
			return -1;
#else
		DEBUG_HOOK("Error: Shouldn't be hooking here for the 32-bit dll.\n");
		return -1;
#endif
	}

	return 0;
}

#endif
