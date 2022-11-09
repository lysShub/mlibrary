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

func MemoryLoadLibraryEx(data []byte,
	allocMemory CustomAllocFunc,
	freeMemory CustomFreeFunc,
	loadLibrary CustomLoadLibraryFunc,
	getProceAddress CustomGetProcAddressFunc,
	freeLibrary CustomFreeLibraryFunc,
) {
	var size = len(data)
	var err error

	// -----------------------
	if !CheckSize(size_t(size), size_t(unsafe.Sizeof(IMAGE_DOS_HEADER{}))) {
		panic("格式不正确1")
	}

	var dos_header = to[*IMAGE_DOS_HEADER](&data[0])
	if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
		panic("格式不正确2")
	}

	if !CheckSize(size_t(size), size_t(dos_header.e_lfanew)+size_t(unsafe.Sizeof(IMAGE_NT_HEADERS{}))) {
		panic("格式不正确3")
	}

	// old_header = (PIMAGE_NT_HEADERS) & ((const unsigned char *)(data))[dos_header->e_lfanew];
	// 中间的那个&是什么作用？因为对data取了偏移，需要重新取地址才行，并不是指针取地址
	var old_header = to[*IMAGE_NT_HEADERS](add(&data[0], int(dos_header.e_lfanew)))
	if old_header.Signature != IMAGE_NT_SIGNATURE {
		panic("格式不正确4")
	}
	if old_header.FileHeader.Machine != HOST_MACHINE {
		panic("格式不正确5")
	}
	if old_header.OptionalHeader.SectionAlignment%2 != 0 {
		panic("格式不正确6")
	}

	var section = IMAGE_FIRST_SECTION(old_header)
	var optionalSectionSize = old_header.OptionalHeader.SectionAlignment
	var lastSectionEnd size_t
	var sectionSize = int(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	for i := 0; i < int(old_header.FileHeader.NumberOfSections); i, section = i+1, add(section, sectionSize) {
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

	for to[uintptr_t](code)>>32 < to[uintptr_t](add(code, int(alignedImageSize)))>>32 {
		var node *POINTER_LIST = &POINTER_LIST{}

		node.next = blockMemory
		node.address = code
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

	if !CheckSize(size_t(size), size_t(old_header.OptionalHeader.SizeOfHeaders)) {
		panic(fmt.Errorf("格式错误11"))
	}

	// commit memory for headers
	headers, err := (*allocMemory)(code, SIZE_T(old_header.OptionalHeader.SizeOfHeaders), windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		panic(fmt.Errorf("格式错误12"))
	}

	// copy PE header to code
	memcpy(headers, to[unsafe.Pointer](dos_header), int(old_header.OptionalHeader.SizeOfHeaders))
	result.headers = to[*IMAGE_NT_HEADERS](add(headers, int(dos_header.e_lfanew)))

	result.headers = (*IMAGE_NT_HEADERS)(unsafe.Add(unsafe.Pointer(headers), dos_header.e_lfanew))

	// update position
	result.headers.OptionalHeader.ImageBase = to[uint64](code)

	// copy sections from DLL file block to new memory location
	if !CopySections(to[*uint8](&data[0]), size_t(len(data)), old_header, result) {
		panic(fmt.Errorf("格式错误15"))
	}

	// adjust base address of imported data
	var locationDelta = ptrdiff_t(result.headers.OptionalHeader.ImageBase - old_header.OptionalHeader.ImageBase)
	if locationDelta != 0 {
		panic("result->isRelocated = PerformBaseRelocation(result, locationDelta);")
	} else {
		result.isRelocated = TRUE
	}

	// load required dlls and adjust function table of imports
	if !BuildImportTable(result) {
		panic("格式错误16")
	}

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	if FinalizeSections(result) == FALSE {
		panic("格式错误17")
	}

	// TLS callbacks are executed BEFORE the main loading
	if ExecuteTLS(result) != TRUE {
		panic("tls 回调错误")
	}

	// get entry point of loaded library
	if result.headers.OptionalHeader.AddressOfEntryPoint != 0 {
		if result.isDLL == TRUE {
			var DllEntry DllEntryProc = nil

		}

	}
}

func CopySections(data *uint8, size size_t, old_headers *IMAGE_NT_HEADERS, module *MLIBRARY) bool {
	var i, section_size int32
	var codeBase = module.codeBase
	var dest *uint8
	var section = IMAGE_FIRST_SECTION(module.headers)
	var err error
	var sectionSize = int(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	for i = 0; i < int32(module.headers.FileHeader.NumberOfSections); i, section = i+1, add(section, sectionSize) {
		if section.Size == 0 {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			section_size = int32(old_headers.OptionalHeader.SectionAlignment)
			if section_size > 0 {
				_, err = (*module.alloc)(
					to[unsafe.Pointer](add(codeBase, int(section.VirtualAddress))),
					SIZE_T(section_size),
					windows.MEM_COMMIT,
					windows.PAGE_READWRITE,
				)
				if err != nil {
					panic(err.Error())
				}

				// Always use position from file to support alignments smaller
				// than page size (allocation above will align to page size).
				dest = add(codeBase, int(section.VirtualAddress))
				// NOTE: On 64bit systems we truncate to 32bit here but expand
				// again later when "PhysicalAddress" is used.
				section.VirtualSize = to[DWORD](to[uintptr_t](dest) & 0xffffffff)
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
			to[unsafe.Pointer](add(codeBase, int(section.VirtualAddress))),
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
		dest = to[*uint8](add(codeBase, int(section.VirtualAddress)))

		memcpy(to[unsafe.Pointer](dest), to[unsafe.Pointer](add(data, int(section.Offset))), int(section.Size))

		section.VirtualAddress = to[DWORD](to[uintptr_t](dest) & 0xffffffff)
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

	importDesc = to[*IMAGE_IMPORT_DESCRIPTOR](add(codeBase, int(directory.VirtualAddress)))
	var importDescSize = unsafe.Sizeof(*importDesc)
	for ; IsBadReadPtr(to[unsafe.Pointer](importDesc), UINT_PTR(importDescSize)); importDesc = add(importDesc, int(importDescSize)) {

		var thunkRef *uintptr_t
		var funcRef *FARPROC
		var tmp *HCUSTOMMODULE
		handle, err := (*module.loadLibrary)(to[LPCSTR](add(codeBase, int(importDesc.Name))))
		if err != nil {
			result = false
			panic(fmt.Sprintf("23312", err.Error()))
		}

		ttmp, err := realloc(to[unsafe.Pointer](module.modules), size_t(module.numModules+1)*size_t(unsafe.Sizeof(HCUSTOMMODULE(nil))))
		if err != nil {
			result = false
			panic(fmt.Sprintf("2353", err.Error()))
		}
		tmp = to[*HCUSTOMMODULE](ttmp)
		module.modules = tmp

		// TODO: 这里不太拿得准
		// module->modules[module->numModules++] = handle;
		tmp = add(module.modules, int(module.numModules)*int(unsafe.Sizeof(module.modules)))
		module.numModules += 1
		*tmp = to[HCUSTOMMODULE](handle)

		if importDesc.OriginalFirstThunk == 1 {
			thunkRef = to[*uintptr_t](add(codeBase, int(importDesc.OriginalFirstThunk)))
			funcRef = to[*FARPROC](add(codeBase, int(importDesc.FirstThunk)))
		} else {
			// no hint table
			thunkRef = to[*uintptr_t](add(codeBase, int(importDesc.FirstThunk)))
			funcRef = to[*FARPROC](add(codeBase, int(importDesc.FirstThunk)))
		}
		for ; *thunkRef == 1; thunkRef, funcRef = add(thunkRef, int(unsafe.Sizeof(*thunkRef))), add(funcRef, int(unsafe.Sizeof(*funcRef))) {

			if IMAGE_SNAP_BY_ORDINAL(*thunkRef) {
				*funcRef, err = (*module.getProcAddress)(handle, nil)
				if err != nil {
					panic(fmt.Sprint("23232323", err.Error()))
				}
			} else {
				var thunkData = to[*IMAGE_IMPORT_BY_NAME](add(codeBase, int(*thunkRef)))
				*funcRef, err = (*module.getProcAddress)(handle, to[LPCSTR](&thunkData.Name))
				if err != nil {
					panic(fmt.Sprint("22453262", err.Error()))
				}
			}

			if (**funcRef)() == 0 {
				result = false
			}
		}

		if !result {
			(*module.freeLibrary)(handle)
			break
		}
	}

	return result
}

func FinalizeSections(module *MLIBRARY) BOOL {
	var i int32
	var section *IMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(module.headers)
	var imageOffset uintptr_t = uintptr_t(module.headers.OptionalHeader.ImageBase) & 0xffffffff00000000
	var sectionData SECTIONFINALIZEDATA
	sectionData.address = to[LPVOID](uintptr_t(section.VirtualSize) | imageOffset)
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, uintptr_t(module.pageSize))
	sectionData.size = GetRealSectionSize(module, section)
	sectionData.characteristics = section.Characteristics
	sectionData.last = FALSE
	section = add(section, int(unsafe.Sizeof(*section)))

	for i = 1; i < int32(module.headers.FileHeader.NumberOfSections); i, section = i+1, add(section, int(unsafe.Sizeof(*section))) {

		var sectionAddress LPVOID = to[LPVOID](uintptr_t(section.VirtualSize) | imageOffset)
		var alignedAddress LPVOID = AlignAddressDown(sectionAddress, uint64(module.pageSize))
		var sectionSize SIZE_T = GetRealSectionSize(module, section)
		// Combine access flags of all sections that share a page
		// TODO(fancycode): We currently share flags of a trailing large section
		//   with the page of a first small section. This should be optimized.
		if sectionData.alignedAddress == alignedAddress ||
			to[uintptr_t](sectionData.address)+sectionData.size > to[uintptr_t](alignedAddress) {
			// Section shares page with previous
			if ((section.Characteristics & pe.IMAGE_SCN_MEM_DISCARDABLE) == 0) ||
				(sectionData.characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE) == 0 {
				sectionData.characteristics = (sectionData.characteristics | section.Characteristics) & (^uint32(pe.IMAGE_SCN_MEM_DISCARDABLE))
			} else {
				sectionData.characteristics |= section.Characteristics
			}
			sectionData.size = to[uintptr_t](sectionAddress) + (to[uintptr_t](sectionSize) - to[uintptr_t](sectionData.address))
			continue
		}

		if !FinalizeSection(module, &sectionData) {
			return FALSE
		}
		sectionData.address = sectionAddress
		sectionData.alignedAddress = alignedAddress
		sectionData.size = sectionSize
		sectionData.characteristics = section.Characteristics
	}
	sectionData.last = TRUE
	if !FinalizeSection(module, &sectionData) {
		return FALSE
	}
	return FALSE
}

func FinalizeSection(module *MLIBRARY, sectionData *SECTIONFINALIZEDATA) bool {
	var protect, oldProtect DWORD
	var executable BOOL = FALSE
	var readable BOOL = FALSE
	var writeable BOOL

	if sectionData.size == 0 {
		return true
	}

	if sectionData.characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE == uint32(TRUE) {
		// section is not needed any more and can safely be freed
		if sectionData.address == sectionData.alignedAddress && (sectionData.last == TRUE || module.headers.OptionalHeader.SectionAlignment == module.pageSize || (sectionData.size%uint64(module.pageSize)) == 0) {
			// Only allowed to decommit whole pages
			(*module.free)(sectionData.address, sectionData.size, windows.MEM_DECOMMIT)
		}
		return true
	}

	// determine protection flags based on characteristics
	if (sectionData.characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0 {
		executable = TRUE
	}
	if (sectionData.characteristics & pe.IMAGE_SCN_MEM_READ) != 0 {
		readable = TRUE
	}
	if (sectionData.characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0 {
		readable = TRUE
	}
	protect = ProtectionFlags[executable][readable][writeable]
	if sectionData.characteristics&IMAGE_SCN_MEM_NOT_CACHED == uint32(TRUE) {
		protect |= windows.PAGE_NOCACHE
	}

	// change memory access flags
	if err := windows.VirtualProtect(uintptr(sectionData.address), uintptr(sectionData.size), protect, &oldProtect); err == nil {
		panic(fmt.Sprint("sfw2332", err))
		return false
	}

	return true
}

func ExecuteTLS(module *MLIBRARY) BOOL {

	// don't execute TLS callback
	return TRUE

	var codeBase = module.codeBase
	var tls *IMAGE_TLS_DIRECTORY
	var callback *PIMAGE_TLS_CALLBACK

	var directory *IMAGE_DATA_DIRECTORY = GET_HEADER_DICTIONARY(module, pe.IMAGE_DIRECTORY_ENTRY_TLS)
	if directory.VirtualAddress == 0 {
		return TRUE
	}

	tls = to[*IMAGE_TLS_DIRECTORY](add(codeBase, int(directory.VirtualAddress)*int(unsafe.Sizeof(*codeBase))))
	callback = to[*PIMAGE_TLS_CALLBACK](tls.AddressOfCallBacks)
	if callback == nil {
		return TRUE
	}
	return TRUE
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
