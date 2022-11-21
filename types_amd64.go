package mlibrary

import "debug/pe"

type (
	WORD      = uint16
	LONG      = int32
	DWORD     = uint32
	ULONGLONG = uint64
	BYTE      = byte
)

type IMAGE_DOS_HEADER struct {
	e_magic    WORD
	e_cblp     WORD
	e_cp       WORD
	e_crlc     WORD
	e_cparhdr  WORD
	e_minalloc WORD
	e_maxalloc WORD
	e_ss       WORD
	e_sp       WORD
	e_csum     WORD
	e_ip       WORD
	e_cs       WORD
	e_lfarlc   WORD
	e_ovno     WORD
	e_res      [4]WORD
	e_oemid    WORD
	e_oeminfo  WORD
	e_res2     [10]WORD
	e_lfanew   LONG
}

type IMAGE_NT_HEADERS struct {
	Signature      DWORD
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress DWORD
	SizeOfBlock    DWORD
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk DWORD
	TimeDateStamp      DWORD
	ForwarderChain     DWORD
	Name               DWORD
	FirstThunk         DWORD
}

type IMAGE_THUNK_DATA struct {
	ForwarderString ULONGLONG
	Function        ULONGLONG
	Ordinal         ULONGLONG
	AddressOfData   ULONGLONG
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint WORD
	Name [1]BYTE
}
