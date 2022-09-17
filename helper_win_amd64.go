//go:build windows
// +build windows

// winnt.h
package mlibrary

import (
	"debug/pe"
	"unsafe"
)

type WORD uint16
type DWORD uint32
type LONG int32
type size_t uint64
type BOOL int
type ULONG_PTR uint64
type ptrdiff_t int64
type UINT_PTR uint64
type uintptr_t uint64
type INT_PTR int64
type FARPROC *func() INT_PTR
type SIZE_T ULONG_PTR

// TODO:
//
//	所有C中的 void* 都映射为unsafe.Pointer
type LPVOID = unsafe.Pointer

type (
	HMEMORYMODULE = unsafe.Pointer
	HMEMORYRSRC   = unsafe.Pointer
	HCUSTOMMODULE = unsafe.Pointer
)

type (
	LPCSTR unsafe.Pointer
)

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D

	IMAGE_NT_SIGNATURE = 0x00004550 // PE00

	HOST_MACHINE = pe.IMAGE_FILE_MACHINE_AMD64
)

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
	modules          unsafe.Pointer
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

type IMAGE_IMPORT_DESCRIPTOR = pe.ImportDirectory

type IMAGE_DATA_DIRECTORY = pe.DataDirectory

func GET_HEADER_DICTIONARY(module *MLIBRARY, idx int) *IMAGE_DATA_DIRECTORY {
	return &module.headers.OptionalHeader.DataDirectory[idx]
}
