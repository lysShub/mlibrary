// winnt.h
package mlibrary

import (
	"debug/pe"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IMAGE_DOS_SIGNATURE      = 0x5A4D
	IMAGE_NT_SIGNATURE       = 0x00004550
	HOST_MACHINE             = 0x8664
	IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
)

type (
	CHAR      = byte
	WORD      = uint16
	DWORD     = uint32
	LONG      = int32
	BOOL      = int32
	ptrdiff_t = int64
	INT_PTR   = int64
	size_t    = uint64
	ULONG_PTR = uint64
	UINT_PTR  = uint64
	uintptr_t = uint64
	ULONGLONG = uint64
	SIZE_T    = uint64

	FARPROC       = *func() INT_PTR
	LPCSTR        = *CHAR
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

type IMAGE_TLS_CALLBACK func(DllHandle PVOID, Reason DWORD, Reserved PVOID)
type PIMAGE_TLS_CALLBACK = *IMAGE_TLS_CALLBACK

var ProtectionFlags = [2][2][2]DWORD{
	{
		// not executable
		{windows.PAGE_NOACCESS, windows.PAGE_WRITECOPY},
		{windows.PAGE_READONLY, windows.PAGE_READWRITE},
	},
	{
		// executable
		{windows.PAGE_EXECUTE, windows.PAGE_EXECUTE_WRITECOPY},
		{windows.PAGE_EXECUTE_READ, windows.PAGE_EXECUTE_READWRITE},
	},
}

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

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}

type IMAGE_SECTION_HEADER struct {
	// TODO: Name似乎不匹配
	pe.SectionHeader
}

type POINTER_LIST struct {
	next    *POINTER_LIST
	address unsafe.Pointer
}

type ExportNameEntry struct {
	name unsafe.Pointer
	idx  WORD
}

type MLIBRARY struct {
	headers          *IMAGE_NT_HEADERS
	codeBase         *uint8
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
	exeEntry         func() int
	pageSize         DWORD
	blockMemory      *POINTER_LIST
}

type HINSTANCE_ struct {
	unused int32
}
type HINSTANCE = *HINSTANCE_

// #define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)
//
//	((ULONG_PTR)(ntheader) +
//	 FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +
//	 ((ntheader))->FileHeader.SizeOfOptionalHeader
//	))
func IMAGE_FIRST_SECTION(ntheader *IMAGE_NT_HEADERS) *IMAGE_SECTION_HEADER {
	var ptr = to[ULONG_PTR](ntheader) + _FIELD_OFFSET_IMAGE_NT_HEADERS_OptionalHeader() + ULONG_PTR(ntheader.FileHeader.SizeOfOptionalHeader)
	return to[*IMAGE_SECTION_HEADER](ptr)
}

func _FIELD_OFFSET_IMAGE_NT_HEADERS_OptionalHeader() ULONG_PTR {
	var tmp = IMAGE_NT_HEADERS{}
	return to[ULONG_PTR](&tmp.OptionalHeader) - to[ULONG_PTR](&tmp)
}

func IMAGE_SNAP_BY_ORDINAL(Ordinal uintptr_t) bool {
	return IMAGE_SNAP_BY_ORDINAL64(Ordinal)
}

const IMAGE_ORDINAL_FLAG64 = uint64(0x8000000000000000)

func IMAGE_SNAP_BY_ORDINAL64(Ordinal uintptr_t) bool {
	return Ordinal&IMAGE_ORDINAL_FLAG64 != 0
}

func IMAGE_ORDINAL(Ordinal uintptr_t) uintptr_t {
	return IMAGE_ORDINAL64(Ordinal)
}

func IMAGE_ORDINAL64(Ordinal uintptr_t) uintptr_t {
	return Ordinal & uint64(0xffff)
}

type IMAGE_IMPORT_DESCRIPTOR = pe.ImportDirectory

type IMAGE_DATA_DIRECTORY = pe.DataDirectory

func GET_HEADER_DICTIONARY(module *MLIBRARY, idx int) *IMAGE_DATA_DIRECTORY {
	return &module.headers.OptionalHeader.DataDirectory[idx]
}
