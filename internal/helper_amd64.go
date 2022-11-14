// winnt.h
package memorymodule

import (
	"debug/pe"
	"unsafe"
)

const (
	IMAGE_DOS_SIGNATURE           = 0x5A4D
	IMAGE_NT_SIGNATURE            = 0x00004550
	HOST_MACHINE                  = 0x8664
	IMAGE_SCN_MEM_NOT_CACHED      = 0x04000000
	IMAGE_SIZEOF_SHORT_NAME       = 8
	DLL_PROCESS_ATTACH            = 1
	LANG_NEUTRAL, SUBLANG_NEUTRAL = 0, 0
	DEFAULT_LANGUAGE              = ((WORD(LANG_NEUTRAL)) << 10) | (WORD(SUBLANG_NEUTRAL))
)

type (
	CHAR      = byte
	TCHAR     = byte
	WORD      = uint16
	wchar_t   = uint16
	WCHAR     = uint16
	DWORD     = uint32
	LCID      = DWORD
	LONG      = int32
	BOOL      = int32
	UINT      = uint32
	ptrdiff_t = int64
	INT_PTR   = int64
	size_t    = uint64
	ULONG_PTR = uint64
	DWORD_PTR = ULONG_PTR
	UINT_PTR  = uint64
	uintptr_t = uint64
	ULONGLONG = uint64
	SIZE_T    = uint64

	FARPROC       = *func() INT_PTR
	LPCSTR        = *CHAR
	PBYTE         = *byte
	LPTSTR        = *byte
	LPCTSTR       = *byte
	LPCWSTR       = *WORD
	LPWSTR        = *WCHAR
	PVOID         = unsafe.Pointer
	LPVOID        = unsafe.Pointer
	HMEMORYMODULE = unsafe.Pointer
	HMEMORYRSRC   = unsafe.Pointer
	HCUSTOMMODULE = unsafe.Pointer
)

type IMAGE_IMPORT_BY_NAME struct {
	Hint WORD
	Name [1]BYTE
}

type PIMAGE_IMPORT_BY_NAME = *IMAGE_IMPORT_BY_NAME

type SECTIONFINALIZEDATA struct {
	address         LPVOID
	alignedAddress  LPVOID
	size            SIZE_T
	characteristics DWORD
	last            BOOL
}

type IMAGE_TLS_DIRECTORY struct {
	StartAddressOfRawData ULONGLONG
	EndAddressOfRawData   ULONGLONG
	AddressOfIndex        ULONGLONG
	AddressOfCallBacks    ULONGLONG
	SizeOfZeroFill        DWORD
	characteristics       DWORD
}
type PIMAGE_TLS_DIRECTORY = *IMAGE_TLS_DIRECTORY

type IMAGE_TLS_CALLBACK func(DllHandle PVOID, Reason DWORD, Reserved PVOID)
type PIMAGE_TLS_CALLBACK = *IMAGE_TLS_CALLBACK

// DOS .EXE header
type IMAGE_DOS_HEADER struct {
	e_magic    WORD     // Magic number
	e_cblp     WORD     // Bytes on last page of file
	e_cp       WORD     // Pages in file
	e_crlc     WORD     // Relocations
	e_cparhdr  WORD     // Size of header in paragraphs
	e_minalloc WORD     // Minimum extra paragraphs needed
	e_maxalloc WORD     // Maximum extra paragraphs needed
	e_ss       WORD     // Initial (relative) SS value
	e_sp       WORD     // Initial SP value
	e_csum     WORD     // Checksum
	e_ip       WORD     // Initial IP value
	e_cs       WORD     // Initial (relative) CS value
	e_lfarlc   WORD     // File address of relocation table
	e_ovno     WORD     // Overlay number
	e_res      [4]WORD  // Reserved words
	e_oemid    WORD     // OEM identifier (for e_oeminfo)
	e_oeminfo  WORD     // OEM information; e_oemid specific
	e_res2     [10]WORD // Reserved words
	e_lfanew   LONG     // File address of new exe header
}

type PIMAGE_DOS_HEADER = *IMAGE_DOS_HEADER

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}
type PIMAGE_NT_HEADERS = *IMAGE_NT_HEADERS

type IMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]BYTE
	Misc struct {
		PhysicalAddress DWORD
		VirtualSize     DWORD
	}
	VirtualAddress       DWORD
	SizeOfRawData        DWORD
	PointerToRawData     DWORD
	PointerToRelocations DWORD
	PointerToLinenumbers DWORD
	NumberOfRelocations  WORD
	NumberOfLinenumbers  WORD
	Characteristics      DWORD
}

type PIMAGE_SECTION_HEADER = *IMAGE_SECTION_HEADER

type POINTER_LIST struct {
	next    *POINTER_LIST
	address unsafe.Pointer
}

type ExportNameEntry struct {
	name unsafe.Pointer
	idx  WORD
}

type MEMORYMODULE struct {
	headers          PIMAGE_NT_HEADERS
	codeBase         PBYTE
	modules          *HCUSTOMMODULE
	numModules       int32
	initialized      BOOL
	isDLL            BOOL
	isRelocated      BOOL
	alloc            CustomAllocFunc
	free             CustomFreeFunc
	loadLibrary      CustomLoadLibraryFunc
	getProcAddress   CustomGetProcAddressFunc
	freeLibrary      CustomFreeLibraryFunc
	nameExportsTable *ExportNameEntry
	userdata         unsafe.Pointer
	exeEntry         ExeEntryProc
	pageSize         DWORD
	blockedMemory    *POINTER_LIST
}

type PMEMORYMODULE = *MEMORYMODULE

type HINSTANCE_ struct {
	_ /* unused */ int32
}
type HINSTANCE = *HINSTANCE_

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       DWORD
	TimeDateStamp         DWORD
	MajorVersion          WORD
	MinorVersion          WORD
	Name                  DWORD
	Base                  DWORD
	NumberOfFunctions     DWORD
	NumberOfNames         DWORD
	AddressOfFunctions    DWORD // RVA from base of image
	AddressOfNames        DWORD // RVA from base of image
	AddressOfNameOrdinals DWORD // RVA from base of image
}

type PIMAGE_EXPORT_DIRECTORY = *IMAGE_EXPORT_DIRECTORY

func IMAGE_FIRST_SECTION(ntheader PIMAGE_NT_HEADERS) PIMAGE_SECTION_HEADER {
	var ptr = to[ULONG_PTR](ntheader) +
		the_OFFSET() +
		ULONG_PTR(ntheader.FileHeader.SizeOfOptionalHeader)

	return to[PIMAGE_SECTION_HEADER](ptr)
}

func the_OFFSET() ULONG_PTR {
	var tmp = IMAGE_NT_HEADERS{}
	start := to[ULONG_PTR](&tmp)
	end := to[ULONG_PTR](&tmp.OptionalHeader)
	if start > end {
		return start - end
	} else {
		return end - start
	}
}

func OK[T int | uint | uint32 | int32 | uintptr](n T) bool {
	return n != 0
}

func IMAGE_SNAP_BY_ORDINAL(Ordinal uintptr_t) bool {
	return IMAGE_SNAP_BY_ORDINAL64(Ordinal)
}

const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

func IMAGE_SNAP_BY_ORDINAL64(Ordinal uintptr_t) bool {
	return Ordinal&IMAGE_ORDINAL_FLAG64 != 0
}

func IMAGE_ORDINAL(Ordinal uintptr_t) uintptr_t {
	return IMAGE_ORDINAL64(Ordinal)
}

func IMAGE_ORDINAL64(Ordinal uintptr_t) uintptr_t {
	return Ordinal & uint64(0xffff)
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	Characteristics    DWORD // 0 for terminating null import descriptor
	OriginalFirstThunk DWORD // RVA to original unbound IAT (PIMAGE_THUNK_DATA)

	TimeDateStamp DWORD // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	ForwarderChain DWORD // -1 if no forwarders
	Name           DWORD
	FirstThunk     DWORD
}

type PIMAGE_IMPORT_DESCRIPTOR = *IMAGE_IMPORT_DESCRIPTOR

type IMAGE_DATA_DIRECTORY = pe.DataDirectory
type PIMAGE_DATA_DIRECTORY = *IMAGE_DATA_DIRECTORY

func malloc(size int) PVOID {
	return nil
}

func GET_HEADER_DICTIONARY(module *MEMORYMODULE, idx int) PIMAGE_DATA_DIRECTORY {
	return &module.headers.OptionalHeader.DataDirectory[idx]
}

func HIWORD(l LPCSTR) WORD {
	return WORD((to[DWORD_PTR](l) >> 16) & 0xffff)
}

func LOWORD(l LPCSTR) WORD {
	return WORD(to[DWORD_PTR](l) & 0xffff)
}
