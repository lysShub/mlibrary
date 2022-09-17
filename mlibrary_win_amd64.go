//go:build windows
// +build windows

package mlibrary

import (
	"debug/pe"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {

}

func MemoryLoadLibrary(b []byte) (*syscall.DLL, error) {

	return nil, nil
}

// HMEMORYMODULE MemoryLoadLibraryEx(const void *data, size_t size,
//     CustomAllocFunc allocMemory,
//     CustomFreeFunc freeMemory,
//     CustomLoadLibraryFunc loadLibrary,
//     CustomGetProcAddressFunc getProcAddress,
//     CustomFreeLibraryFunc freeLibrary,
//     void *userdata)

func MemoryLoadLibraryEx(data []byte,
	allocMemory CustomAllocFunc,
	freeMemory CustomFreeFunc,
	loadLibrary CustomLoadLibraryFunc,
	getProceAddress CustomGetProcAddressFunc,
	freeLibrary CustomFreeLibraryFunc,
) {

	// -----------------------
	if len(data) < int(unsafe.Sizeof(IMAGE_DOS_HEADER{})) {
		panic("格式不正确1")
	}

	var dos_header = to[*IMAGE_DOS_HEADER](&data[0])
	if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
		panic("格式不正确2")
	}

	if len(data) != int(dos_header.e_lfanew)+int(unsafe.Sizeof(IMAGE_NT_HEADERS{})) {
		panic("格式不正确3")
	}

	var old_header = addTo[*IMAGE_NT_HEADERS](data, int(dos_header.e_lfanew))
	if old_header.Signature != IMAGE_NT_SIGNATURE {
		panic("格式不正确4")
	}
	if old_header.FileHeader.Machine != HOST_MACHINE {
		panic("格式不正确5")
	}
	if old_header.OptionalHeader.SectionAlignment%2 == 1 {
		panic("格式不正确6")
	}

	var section = IMAGE_FIRST_SECTION(old_header)
	// p, err := pe.NewFile(bytes.NewReader(data))
	// if err != nil {
	// 	panic(err.Error())
	// }
	// var section = p.Sections[0]

	var optionalSectionSize = old_header.OptionalHeader.SectionAlignment
	var lastSectionEnd size_t
	var sectionStep = int(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	for i := 0; i < int(old_header.FileHeader.NumberOfSections); i, section = i+1, addTo[*IMAGE_SECTION_HEADER](section, sectionStep) {
		var endOfSection size_t
		if section.Size == 0 {
			endOfSection = size_t(section.VirtualAddress) + size_t(optionalSectionSize)
		} else {
			endOfSection = size_t(section.VirtualAddress) + size_t(section.Size)
		}

		if endOfSection > lastSectionEnd {
			lastSectionEnd = endOfSection
		}
	}

	// os.Getpagesize()

	var alignedImageSize = AlignValueUp(size_t(old_header.OptionalHeader.SizeOfImage), size_t(os.Getpagesize()))
	if alignedImageSize != AlignValueUp(lastSectionEnd, size_t(os.Getpagesize())) {
		panic("格式错误7")
	}

	code, err := (*allocMemory)(to[LPVOID](old_header.OptionalHeader.ImageBase), SIZE_T(alignedImageSize), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Errorf("格式错误8: %s", err))
	}

	// TODO:
	//   这是在干嘛？
	var blockMemory *POINTER_LIST

	for to[uintptr_t](code)>>32 < to[uintptr_t](addTo[uintptr_t](code, int(alignedImageSize)))>>32 {
		var node *POINTER_LIST = &POINTER_LIST{}

		node.next = blockMemory
		node.address = to[unsafe.Pointer](code)
		blockMemory = node

		code, err = (*allocMemory)(unsafe.Pointer(nil), SIZE_T(alignedImageSize), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if err != nil {
			FreePointerList(blockMemory, freeMemory)
			panic(fmt.Errorf("格式错误9: %s", err))
		}
	}

	tResult, err := HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size_t(unsafe.Sizeof(MLIBRARY{})))
	if err != nil {
		(*freeMemory)(code, 0, windows.MEM_RELEASE)
		FreePointerList(blockMemory, freeMemory)
		panic(fmt.Errorf("格式错误10: %s", err))
	}
	var result = to[*MLIBRARY](tResult)
	result.codeBase = to[*uint8](code)
	result.isDLL = BOOL(old_header.FileHeader.Characteristics & pe.IMAGE_FILE_DLL)
	result.alloc = allocMemory
	result.free = freeMemory
	result.loadLibrary = loadLibrary
	result.getProcAddress = getProceAddress
	result.freeLibrary = freeLibrary
	result.pageSize = DWORD(os.Getpagesize())
	result.blockMemory = blockMemory

	if !CheckSize(size_t(len(data)), size_t(old_header.OptionalHeader.SizeOfHeaders)) {
		panic(fmt.Errorf("格式错误11"))
	}

	// commit memory for headers
	headers, err := (*allocMemory)(code, SIZE_T(old_header.OptionalHeader.SizeOfHeaders), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Errorf("格式错误12"))
	}

	// copy PE header to code
	memcpy(to[uintptr](headers), to[uintptr](dos_header), int(old_header.OptionalHeader.SizeOfHeaders))

	var tmp = addTo[unsafe.Pointer](headers, int(dos_header.e_lfanew))
	result.headers = to[*IMAGE_NT_HEADERS](&tmp)

	result.headers = (*IMAGE_NT_HEADERS)(unsafe.Add(unsafe.Pointer(headers), dos_header.e_lfanew))

	// update position
	result.headers.OptionalHeader.ImageBase = to[uint64](code)

	// copy sections from DLL file block to new memory location
	if !CopySections((*uint8)(unsafe.Pointer(&data[0])), size_t(len(data)), old_header, result) {
		panic(fmt.Errorf("格式错误15"))
	}

	// adjust base address of imported data
	var locationDelta = ptrdiff_t(result.headers.OptionalHeader.ImageBase - old_header.OptionalHeader.ImageBase)
	if locationDelta != 0 {
		panic(fmt.Errorf("格式错误16"))
	} else {
		result.isRelocated = 1
	}

	// load required dlls and adjust function table of imports
}

func CopySections(data *uint8, size size_t, old_headers *IMAGE_NT_HEADERS, module *MLIBRARY) bool {
	var i, section_size int32
	var codeBase = module.codeBase
	var dest *uint8
	var section *pe.SectionHeader //= IMAGE_FIRST_SECTION(module.headers)
	var err error
	for i = 0; i < int32(module.headers.FileHeader.NumberOfSections); i, section = i+1, (*pe.SectionHeader)(unsafe.Add(unsafe.Pointer(section), 1)) {
		if section.Size == 0 {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			section_size = int32(old_headers.OptionalHeader.SectionAlignment)
			if section_size > 0 {
				_, err = (*module.alloc)(
					unsafe.Add(unsafe.Pointer(codeBase), section.VirtualAddress),
					SIZE_T(section_size),
					windows.MEM_COMMIT,
					windows.PAGE_READWRITE,
				)
				if err != nil {
					panic(err.Error())
				}

				// Always use position from file to support alignments smaller
				// than page size (allocation above will align to page size).
				dest = (*uint8)(unsafe.Add(unsafe.Pointer(codeBase), section.VirtualAddress))

				section.VirtualSize = uint32(*(*uintptr_t)(unsafe.Pointer(dest)) & 0xffffffff)
				// memset(dest, 0, section_size) 为什么要重置呢？
			}

			// section is empty
			continue
		}

		if !CheckSize(size, size_t(section.Size+section.Offset)) {
			panic(fmt.Errorf("格式错误13"))
		}

		// commit memory block and copy data from dll
		var tdest, err = (*module.alloc)(
			unsafe.Add(unsafe.Pointer(codeBase), section.VirtualAddress),
			SIZE_T(section.Size),
			windows.MEM_COMMIT,
			syscall.PAGE_READWRITE,
		)
		dest = to[*uint8](tdest)
		if err != nil {
			panic(fmt.Errorf("格式错误14"))
		}

		// Always use position from file to support alignments smaller
		// than page size (allocation above will align to page size).
		dest = ptrAdd(codeBase, section.VirtualAddress)
		memcpy((uintptr)(unsafe.Pointer(dest)), (uintptr)(unsafe.Pointer(ptrAdd(data, section.Offset))), int(section.Size))

		section.VirtualAddress = uint32(*(*uintptr_t)(unsafe.Pointer(dest)) & 0xffffffff)
	}
	return true
}

func BuildImportTable(module *MLIBRARY) bool {
	var codeBase *uint8 = module.codeBase
	var importDesc *IMAGE_IMPORT_DESCRIPTOR
	var result bool = true

	var directory = GET_HEADER_DICTIONARY(module, pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
	if directory.Size == 0 {
		return true
	}

	importDesc = (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Add(unsafe.Pointer(codeBase), directory.VirtualAddress))
	// for ; !IsBadReadPtr(*(*uintptr)(unsafe.Pointer(importDesc)), UINT_PTR(unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{}))) && uint8(importDesc.Name); (*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Add(unsafe.Pointer(importDesc), 1)) {
	// 	var thunkRef *uintptr_t
	// 	var funcRef *FARPROC
	// 	var tmp *HCUSTOMMODULE
	// 	var handle HCUSTOMMODULE = module.loadLibrary(*(*lpcstr))
	// }
	fmt.Println(importDesc)
	return result
}

// -------------------------------------------------------------------------------------------------
//
// -------------------------------------------------------------------------------------------------

func MemoryDefaultAlloc(address uintptr, size uintptr, alloctype uint32, protect uint32) (value uintptr, err error) {
	return windows.VirtualAlloc(address, size, alloctype, protect)
}

func MemoryDefaultFree(address uintptr, size uintptr, freetype uint32) error {
	return windows.VirtualFree(address, size, freetype)
}

func MemoryDefaultLoadLibrary(libname string) (handle windows.Handle, err error) {
	return LoadLibraryA(libname)
}

func MemoryDefaultGetProcAddress(module windows.Handle, procname string) (proc uintptr, err error) {
	return windows.GetProcAddress(module, procname)
}

func MemoryDefaultFreeLibrary(handle windows.Handle) (err error) {
	return windows.FreeLibrary(handle)
}

func FreePointerList(head *POINTER_LIST, freeMemory CustomFreeFunc) {
	var node *POINTER_LIST = head
	for node != nil {
		var next *POINTER_LIST
		// freeMemory(node.address, 0, windows.MEM_RELEASE)
		next = node.next
		// free(node); // belong to golang gc
		node = next
	}
}

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procHeapAlloc = modkernel32.NewProc("HeapAlloc")
var procIsBadReadPtr = modkernel32.NewProc("IsBadReadPtr")
var procGetProcessHeap = modkernel32.NewProc("GetProcessHeap")
var procLoadLibraryA = modkernel32.NewProc("LoadLibraryA")

func HeapAlloc(hHeap windows.Handle, dwFlags DWORD, dwBytes size_t) (p uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procHeapAlloc.Addr(), uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	if r0 == 0 {
		err = errnoErr(e1)
	}
	return r0, err
}

func IsBadReadPtr(lp uintptr, ucb UINT_PTR) bool {
	r0, _, _ := syscall.SyscallN(procIsBadReadPtr.Addr(), lp, uintptr(ucb))
	if r0 == 0 {
		return false
	}
	return true
}

func GetProcessHeap() windows.Handle {
	r0, _, e1 := syscall.SyscallN(procGetProcessHeap.Addr())
	if r0 == 0 {
		panic(errnoErr(e1).Error())
	}
	return windows.Handle(r0)
}

func LoadLibraryA(libname string) (handle windows.Handle, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(libname)
	if err != nil {
		return
	}
	return _LoadLibraryA(_p0)
}

func _LoadLibraryA(libname *uint16) (handle windows.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procLoadLibraryA.Addr(), uintptr(unsafe.Pointer(libname)))
	handle = windows.Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return handle, err
}

func AlignValueUp(value, alignment size_t) size_t {
	return (value + alignment - 1) & (^(alignment - 1))
}

func errnoErr(e syscall.Errno) error {
	switch syscall.Errno(e) {
	case 0:
		return syscall.EINVAL
	case 997:
		return syscall.Errno(997)
	default:
		return e
	}
}

func CheckSize(size, exprcted size_t) bool {
	if size < exprcted {
		return false
	}
	return true
}
