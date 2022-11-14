//go:build windows
// +build windows

package memorymodule

import (
	"debug/pe"
	"fmt"
	"os"
	"reflect"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {

}

func AlignValueDown(value uintptr_t, alignment uintptr_t) uintptr_t {
	return value & (^(alignment - 1))
}

func AlignAddressDown(address LPVOID, alignment uintptr_t) LPVOID {
	return to[LPVOID](AlignValueDown(to[uintptr_t](address), alignment))
}

func AlignValueUp(value, alignment size_t) size_t {
	return (value + alignment - 1) & (^(alignment - 1))
}

func OffsetPointer(data PBYTE, offset ptrdiff_t) PBYTE { return nil }

func OutputLastError(msg string) {}

func FreePointerList(head *POINTER_LIST, freeMemory CustomFreeFunc, userdate unsafe.Pointer) {
	var node *POINTER_LIST = head
	var next *POINTER_LIST
	for node != nil {
		// freeMemory(node.address, 0, windows.MEM_RELEASE)
		next = node.next
		// free(node); // belong to golang gc
		node = next
	}
}

func CheckSize(size, exprcted size_t) bool {
	return size >= exprcted
}

func CopySections(data *uint8, size size_t, old_headers *IMAGE_NT_HEADERS, module *MEMORYMODULE) bool {
	var section_size int32
	var codeBase = module.codeBase
	var dest LPVOID
	var section = IMAGE_FIRST_SECTION(module.headers)
	var err error
	var sectionSize = (unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	for i := uint16(0); i < module.headers.FileHeader.NumberOfSections; i, section = i+1, add(section, sectionSize) {
		if section.SizeOfRawData == 0 {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			section_size = int32(old_headers.OptionalHeader.SectionAlignment)
			if section_size > 0 {
				_, err = (*module.alloc)(
					to[unsafe.Pointer](add(codeBase, section.VirtualAddress)),
					SIZE_T(section_size),
					windows.MEM_COMMIT,
					windows.PAGE_READWRITE,
					module.userdata,
				)
				if err != nil {
					panic(err.Error())
				}

				// Always use position from file to support alignments smaller
				// than page size (allocation above will align to page size).
				dest = to[unsafe.Pointer](add(codeBase, section.VirtualAddress))
				// NOTE: On 64bit systems we truncate to 32bit here but expand
				// again later when "PhysicalAddress" is used.
				section.Misc.PhysicalAddress = DWORD(to[uintptr_t](dest) & 0xffffffff)
				// note: dest use for "dest == NULL"
			}

			// section is empty
			continue
		}

		if !CheckSize(size, size_t(section.PointerToRawData+section.SizeOfRawData)) {
			panic(fmt.Errorf("格式错误13"))
		}

		// commit memory block and copy data from dll
		_, err = (*module.alloc)(
			to[unsafe.Pointer](add(codeBase, section.VirtualAddress)),
			SIZE_T(section.SizeOfRawData),
			windows.MEM_COMMIT,
			syscall.PAGE_READWRITE,
			module.userdata,
		)
		if err != nil {
			panic(fmt.Errorf("格式错误14"))
		}

		// Always use position from file to support alignments smaller
		// than page size (allocation above will align to page size).
		dest = to[unsafe.Pointer](add(codeBase, section.VirtualAddress))

		memcpy(
			dest,
			to[unsafe.Pointer](add(data, section.SizeOfRawData)), int(section.SizeOfRawData),
		)
		// NOTE: On 64bit systems we truncate to 32bit here but expand
		// again later when "PhysicalAddress" is used.
		section.Misc.PhysicalAddress = DWORD(to[uintptr_t](dest) & 0xffffffff)
	}
	return true
}

// Protection flags for memory pages (Executable, Readable, Writeable)
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

func GetRealSectionSize(module *MEMORYMODULE, section PIMAGE_SECTION_HEADER) SIZE_T {
	var size DWORD = section.SizeOfRawData
	if size == 0 {
		if section.Characteristics&pe.IMAGE_SCN_CNT_INITIALIZED_DATA == uint32(TRUE) {
			size = module.headers.OptionalHeader.SizeOfInitializedData
		} else if section.Characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA == uint32(TRUE) {
			size = module.headers.OptionalHeader.SizeOfUninitializedData
		}
	}
	return to[SIZE_T](size)
}

func FinalizeSection(module *MEMORYMODULE, sectionData *SECTIONFINALIZEDATA) bool {
	var protect, oldProtect DWORD
	var executable BOOL = FALSE
	var readable BOOL = FALSE
	var writeable BOOL = FALSE

	if sectionData.size == 0 {
		return true
	}

	if sectionData.characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE == uint32(TRUE) {
		// section is not needed any more and can safely be freed
		if sectionData.address == sectionData.alignedAddress && (sectionData.last == TRUE || module.headers.OptionalHeader.SectionAlignment == module.pageSize || (sectionData.size%uint64(module.pageSize)) == 0) {

			// Only allowed to decommit whole pages
			(*module.free)(
				sectionData.address,
				sectionData.size,
				windows.MEM_DECOMMIT,
				module.userdata,
			)
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
	}

	return true
}

func FinalizeSections(module *MEMORYMODULE) BOOL {
	var section *IMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(module.headers)
	var imageOffset uintptr_t = uintptr_t(module.headers.OptionalHeader.ImageBase) & 0xffffffff00000000
	var sectionData SECTIONFINALIZEDATA
	sectionData.address = to[LPVOID](uintptr_t(section.Misc.PhysicalAddress) | imageOffset)
	sectionData.alignedAddress = AlignAddressDown(sectionData.address, uintptr_t(module.pageSize))
	sectionData.size = GetRealSectionSize(module, section)
	sectionData.characteristics = section.Characteristics
	sectionData.last = FALSE
	section = add(section, int(unsafe.Sizeof(*section)))

	// loop through all sections and change access flags
	for i := uint16(1); i < module.headers.FileHeader.NumberOfSections; i, section = i+1, add(section, int(unsafe.Sizeof(*section))) {

		var sectionAddress = to[LPVOID](uintptr_t(section.Misc.PhysicalAddress) | imageOffset)
		var alignedAddress = AlignAddressDown(sectionAddress, uint64(module.pageSize))
		var sectionSize = GetRealSectionSize(module, section)
		// Combine access flags of all sections that share a page
		// TODO(fancycode): We currently share flags of a trailing large section
		//   with the page of a first small section. This should be optimized.
		if sectionData.alignedAddress == alignedAddress ||
			to[uintptr_t](add(sectionData.address, sectionData.size)) > to[uintptr_t](alignedAddress) {

			// Section shares page with previous
			if ((section.Characteristics & pe.IMAGE_SCN_MEM_DISCARDABLE) == 0) ||
				(sectionData.characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE) == 0 {

				sectionData.characteristics = (sectionData.characteristics | section.Characteristics) & (^uint32(pe.IMAGE_SCN_MEM_DISCARDABLE))
			} else {
				sectionData.characteristics |= section.Characteristics
			}
			sectionData.size = (to[uintptr_t](sectionAddress) + (to[uintptr_t](sectionSize)) - to[uintptr_t](sectionData.address))
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

func ExecuteTLS(module *MEMORYMODULE) BOOL {

	var codeBase = module.codeBase
	var tls PIMAGE_TLS_DIRECTORY
	var callback *PIMAGE_TLS_CALLBACK

	var directory PIMAGE_DATA_DIRECTORY = GET_HEADER_DICTIONARY(module, pe.IMAGE_DIRECTORY_ENTRY_TLS)
	if directory.VirtualAddress == 0 {
		return TRUE
	}

	tls = to[PIMAGE_TLS_DIRECTORY](add(codeBase, int(directory.VirtualAddress)*1))
	callback = to[*PIMAGE_TLS_CALLBACK](tls.AddressOfCallBacks)
	if callback == nil {

		for *callback != nil {
			syscall.SyscallN(
				to[uintptr](*callback),
				to[uintptr](codeBase),
				DLL_PROCESS_ATTACH,
				0,
			)

			callback = add(callback, unsafe.Sizeof(callback))
		}

		return TRUE
	}
	return TRUE
}

func PerformBaseRelocation(module PMEMORYMODULE, delta ptrdiff_t) BOOL { return 0 }

func BuildImportTable(module *MEMORYMODULE) bool {
	var codeBase = module.codeBase
	var importDesc *IMAGE_IMPORT_DESCRIPTOR
	var result bool = true

	var directory = GET_HEADER_DICTIONARY(module, pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
	if directory.Size == 0 {
		return true
	}

	importDesc = to[PIMAGE_IMPORT_DESCRIPTOR](add(codeBase, int(directory.VirtualAddress)))
	var importDescSize = unsafe.Sizeof(*importDesc)
	for ; !IsBadReadPtr(to[unsafe.Pointer](importDesc), UINT_PTR(importDescSize)) && importDesc.Name != 0; importDesc = add(importDesc, importDescSize) {

		var thunkRef *uintptr_t
		var funcRef *FARPROC
		var tmp *HCUSTOMMODULE
		handle, err := (*module.loadLibrary)(
			to[LPCSTR](add(codeBase, int(importDesc.Name))),
			nil,
		)
		if err != nil {
			result = false
			panic(fmt.Sprintf("23312 %s", err.Error()))
		}

		ttmp, err := realloc(
			to[unsafe.Pointer](module.modules),
			size_t(module.numModules+1)*size_t(unsafe.Sizeof(0)),
		)
		if err != nil {
			result = false
			panic(fmt.Sprintf("2353 %s", err.Error()))
		}
		tmp = to[*HCUSTOMMODULE](ttmp)
		module.modules = tmp

		*add(module.modules, module.numModules) = handle
		module.numModules += 1
		if importDesc.OriginalFirstThunk == 1 {
			thunkRef = to[*uintptr_t](add(codeBase, importDesc.OriginalFirstThunk))
			funcRef = to[*FARPROC](add(codeBase, importDesc.FirstThunk))
		} else {
			// no hint table
			thunkRef = to[*uintptr_t](add(codeBase, importDesc.FirstThunk))
			funcRef = to[*FARPROC](add(codeBase, importDesc.FirstThunk))
		}
		for ; *thunkRef == 1; thunkRef, funcRef = add(thunkRef, unsafe.Sizeof(*thunkRef)), add(funcRef, unsafe.Sizeof(*funcRef)) {

			if IMAGE_SNAP_BY_ORDINAL(*thunkRef) {
				*funcRef, err = (*module.getProcAddress)(
					handle,
					to[LPCSTR](IMAGE_ORDINAL(*thunkRef)),
					module.userdata,
				)
				if err != nil {
					panic(fmt.Sprint("23232323", err.Error()))
				}
			} else {
				var thunkData = to[PIMAGE_IMPORT_BY_NAME](add(codeBase, *thunkRef))
				*funcRef, err = (*module.getProcAddress)(
					handle,
					to[LPCSTR](&thunkData.Name),
					module.userdata,
				)
				if err != nil {
					panic(fmt.Sprint("22453262", err.Error()))
				}
			}

			if (**funcRef)() == 0 {
				result = false
			}
		}

		if !result {
			(*module.freeLibrary)(handle, module.userdata)
			break
		}
	}

	return result
}

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

// ----------------------

func MemoryLoadLibrary(b []byte) (*syscall.DLL, error) {

	return nil, nil
}

func MemoryLoadLibraryEx(data []byte,
	allocMemory CustomAllocFunc,
	freeMemory CustomFreeFunc,
	loadLibrary CustomLoadLibraryFunc,
	getProceAddress CustomGetProcAddressFunc,
	freeLibrary CustomFreeLibraryFunc,
	userdata PVOID,
) HMEMORYMODULE {
	var size = size_t(len(data))
	var err error

	var (
		result              PMEMORYMODULE
		dos_header          PIMAGE_DOS_HEADER
		old_header          PIMAGE_NT_HEADERS
		code, headers       LPVOID
		locationDelta       ptrdiff_t
		section             PIMAGE_SECTION_HEADER
		optionalSectionSize size_t
		lastSectionEnd      size_t
		alignedImageSize    size_t
		blockedMemory       *POINTER_LIST
	)

	// -----------------------
	if !CheckSize(size, size_t(unsafe.Sizeof(IMAGE_DOS_HEADER{}))) {
		panic("格式不正确1")
	}

	dos_header = to[PIMAGE_DOS_HEADER](&data[0])
	if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
		panic("格式不正确2")
	}

	if !CheckSize(size, size_t(dos_header.e_lfanew)+size_t(unsafe.Sizeof(IMAGE_NT_HEADERS{}))) {
		panic("格式不正确3")
	}

	old_header = to[*IMAGE_NT_HEADERS](add(&data[0], int(dos_header.e_lfanew)))
	if old_header.Signature != IMAGE_NT_SIGNATURE {
		panic("格式不正确4")
	}
	if old_header.FileHeader.Machine != HOST_MACHINE {
		panic("格式不正确5")
	}
	if old_header.OptionalHeader.SectionAlignment%2 != 0 {
		panic("格式不正确6, 只支持偶数")
	}

	section = IMAGE_FIRST_SECTION(old_header)
	optionalSectionSize = size_t(old_header.OptionalHeader.SectionAlignment)
	var _secSize = int(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))
	for i := 0; i < int(old_header.FileHeader.NumberOfSections); i, section = i+1, add(section, _secSize) {
		var endOfSection size_t
		if section.SizeOfRawData == 0 {
			endOfSection = size_t(section.VirtualAddress) + size_t(optionalSectionSize)
		} else {
			endOfSection = size_t(section.VirtualAddress) + size_t(section.SizeOfRawData)
		}

		if endOfSection > lastSectionEnd {
			lastSectionEnd = endOfSection
		}
	}

	alignedImageSize = AlignValueUp(size_t(old_header.OptionalHeader.SizeOfImage), size_t(os.Getpagesize()))
	if alignedImageSize != AlignValueUp(lastSectionEnd, size_t(os.Getpagesize())) {
		panic("格式错误7")
	}

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	code, err = (*allocMemory)(
		to[LPVOID](old_header.OptionalHeader.ImageBase),
		SIZE_T(alignedImageSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE,
		userdata,
	)
	if err != nil {
		panic(fmt.Errorf("格式错误8: %s", err))
	}

	// Memory block may not span 4 GB boundaries.
	for to[uintptr_t](code)>>32 < to[uintptr_t](add(code, alignedImageSize))>>32 {
		var node *POINTER_LIST = &POINTER_LIST{}

		node.next = blockedMemory
		node.address = code
		blockedMemory = node

		code, err = (*allocMemory)(
			unsafe.Pointer(nil),
			SIZE_T(alignedImageSize),
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE,
			userdata,
		)
		if err != nil {
			panic(fmt.Errorf("格式错误9: %s", err))
		}
	}

	tResult, err := HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size_t(unsafe.Sizeof(MEMORYMODULE{})))
	if err != nil {
		(*freeMemory)(code, 0, windows.MEM_RELEASE, userdata)
		panic(fmt.Errorf("格式错误10: %s", err))
	}

	result = to[*MEMORYMODULE](tResult)
	result.codeBase = to[PBYTE](code)
	result.isDLL = BOOL(old_header.FileHeader.Characteristics & pe.IMAGE_FILE_DLL)
	result.alloc = allocMemory
	result.free = freeMemory
	result.loadLibrary = loadLibrary
	result.getProcAddress = getProceAddress
	result.freeLibrary = freeLibrary
	result.userdata = userdata
	result.pageSize = DWORD(os.Getpagesize())
	result.blockedMemory = blockedMemory

	if !CheckSize(size_t(size), size_t(old_header.OptionalHeader.SizeOfHeaders)) {
		panic(fmt.Errorf("格式错误11"))
	}

	// commit memory for headers
	headers, err = (*allocMemory)(
		code,
		SIZE_T(old_header.OptionalHeader.SizeOfHeaders),
		windows.MEM_COMMIT,
		windows.PAGE_READWRITE,
		userdata,
	)
	if err != nil {
		panic(fmt.Errorf("格式错误12"))
	}

	// copy PE header to code
	memcpy(
		headers,
		to[unsafe.Pointer](dos_header),
		int(old_header.OptionalHeader.SizeOfHeaders),
	)
	result.headers = to[PIMAGE_NT_HEADERS](add(headers, int(dos_header.e_lfanew)))

	// update position
	result.headers.OptionalHeader.ImageBase = to[uint64](code)

	// copy sections from DLL file block to new memory location
	if !CopySections(to[*uint8](&data[0]), size, old_header, result) {
		panic(fmt.Errorf("格式错误15"))
	}

	// adjust base address of imported data
	locationDelta = ptrdiff_t(result.headers.OptionalHeader.ImageBase - old_header.OptionalHeader.ImageBase)
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
			var DllEntry DllEntryProc = to[DllEntryProc](add(code, result.headers.OptionalHeader.AddressOfEntryPoint))
			// notify library about attaching to process

			r1, _, err := syscall.SyscallN(
				to[uintptr](DllEntry),
				DLL_PROCESS_ATTACH,
				0,
			)
			if err != 0 {
				println(err)
			}
			if BOOL(r1) == FALSE {
				println("xxxrfasefasdf")
			}

			result.initialized = TRUE
		} else {
			result.exeEntry = to[ExeEntryProc](add(code, result.headers.OptionalHeader.AddressOfEntryPoint))

		}
	} else {
		result.exeEntry = nil
	}

	return to[HMEMORYMODULE](result)
}

func MemoryGetProcAddress(mod HMEMORYMODULE, name LPCSTR) FARPROC {
	var module = to[PMEMORYMODULE](mod)
	var codeBase = module.codeBase
	var idx DWORD = 0
	var exports PIMAGE_EXPORT_DIRECTORY
	var directory PIMAGE_DATA_DIRECTORY = GET_HEADER_DICTIONARY(module, pe.IMAGE_DIRECTORY_ENTRY_EXPORT)

	if directory.Size == 0 {
		panic("格式错误 23日期容器3")
		return nil
	}

	exports = to[PIMAGE_EXPORT_DIRECTORY](add(codeBase, directory.VirtualAddress))
	if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
		panic("格式错误 235234")
		return nil
	}

	if HIWORD(name) == 0 {
		// load function by ordinal value
		if LOWORD(name) < uint16(exports.Base) {
			panic("格式错误 6734")
			return nil
		}

		idx = uint32(LOWORD(name)) - exports.Base
	} else if !OK(exports.NumberOfNames) {
		panic("格式错误 568245")
		return nil
	} else {

		// Lazily build name table and sort it by names
		if !OK(to[uintptr](module.nameExportsTable)) {

			var nameRef = to[*DWORD](add(codeBase, exports.AddressOfNames))
			var ordinal = to[*WORD](add(codeBase, exports.AddressOfNameOrdinals))
			var entry = to[*ExportNameEntry](
				malloc(int(exports.NumberOfNames) * int(unsafe.Sizeof(ExportNameEntry{}))),
			)
			module.nameExportsTable = entry
			if !OK(to[uintptr](entry)) {
				panic("格式错误 456354")
				return nil
			}
			for i := DWORD(0); i < exports.NumberOfNames; i, nameRef = i+1, add(nameRef, unsafe.Sizeof(*nameRef)) {

				entry.name = to[unsafe.Pointer](add(codeBase, *nameRef))
				entry.idx = *ordinal
			}

			// module.nameExportsTable  		数据
			// exports.NumberOfNames    		元素个数
			// unsafe.Sizeof(ExportNameEntry{}) 元素大小
			// less	name						比较函数

			var t = reflect.SliceHeader{
				Data: to[uintptr](module.nameExportsTable),
				Len:  int(exports.NumberOfNames),
				Cap:  int(exports.NumberOfNames),
			}
			st := to[[]ExportNameEntry](t)
			sort.Slice(st, func(i, j int) bool { return to[uintptr](st[i].name) < to[uintptr](st[j].name) })
		}

		// search function name in list of exported names with binary search
		eSize := int(unsafe.Sizeof(ExportNameEntry{}))
		jdx := sort.Search(
			int(exports.NumberOfNames),
			func(i int) bool {
				e := to[*ExportNameEntry](add(module.nameExportsTable, i*eSize))

				return to[uintptr](e.name) < to[uintptr](name)
			},
		)
		if jdx < int(exports.NumberOfNames) {
			e := to[*ExportNameEntry](add(module.nameExportsTable, jdx*eSize))
			if to[uintptr](e.name) < to[uintptr](name) {
				goto found
			}
		}
		// exported symbol not found
		panic("exported symbol not found")
		return nil
	found:
		idx = uint32(to[*ExportNameEntry](add(module.nameExportsTable, jdx*eSize)).idx)
	}

	if idx > exports.NumberOfFunctions {
		// name <-> ordinal number don't match
		panic("搜索出错")
		return nil
	}

	// AddressOfFunctions contains the RVAs to the "real" functions
	tmp := to[*DWORD](add(codeBase, exports.AddressOfFunctions+(idx*4)))

	return to[FARPROC](to[LPVOID](add(codeBase, *tmp)))
}

func MemoryFreeLibrary(mod HMEMORYMODULE) {
	var module = to[PMEMORYMODULE](mod)

	if module == nil {
		return
	}
	if OK(module.initialized) {
		// notify library about detaching from process
		var DllEntry = to[DllEntryProc](to[LPVOID](add(module.codeBase, module.headers.OptionalHeader.AddressOfEntryPoint)))

		syscall.SyscallN(
			to[uintptr](DllEntry),
			to[uintptr](module.codeBase),
			DLL_PROCESS_ATTACH,
			0,
		)
	}
	// free(module->nameExportsTable);
	if module.nameExportsTable != nil {
		// free previously opened libraries
		eSize := int32(unsafe.Sizeof(0))
		for i := int32(0); i < module.numModules; i++ {

			// TODO: 拿不稳
			if e := add(module.modules, eSize*i); *e != nil {
				(*module.freeLibrary)(*e, module.userdata)
			}
		}
		// free(module->modules);
	}

	if module.codeBase != nil {
		// release memory of library
		(*module.free)(
			to[unsafe.Pointer](module.codeBase),
			0,
			windows.MEM_RELEASE,
			module.userdata,
		)
	}

	FreePointerList(module.blockedMemory, module.free, module.userdata)

	HeapFree(GetProcessHeap(), 0, module)
}

func MemoryCallEntryPoint(mod HMEMORYMODULE) int32 {
	var module = to[PMEMORYMODULE](mod)

	if module == nil || OK(module.isDLL) || module.exeEntry == nil || !OK(module.isRelocated) {
		return -1
	}

	return (*module.exeEntry)()
}

func MemoryFindResource(module HMEMORYMODULE, name, typ LPCTSTR) HMEMORYRSRC {
	return MemoryFindResourceEx(module, name, typ, DEFAULT_LANGUAGE)
}

func _MemorySearchResourceEntry(root PBYTE, resources PIMAGE_RESOURCE_DIRECTORY, key LPCTSTR) PIMAGE_RESOURCE_DIRECTORY_ENTRY {

	return nil
}

func MemoryFindResourceEx(module HMEMORYMODULE, name, typ LPCTSTR, language WORD) HMEMORYRSRC {

	var codeBase = to[PMEMORYMODULE](module).codeBase
	var directory = GET_HEADER_DICTIONARY(to[PMEMORYMODULE](module), pe.IMAGE_DIRECTORY_ENTRY_RESOURCE)
	var rootResources PIMAGE_RESOURCE_DIRECTORY
	var nameResourcts PIMAGE_RESOURCE_DIRECTORY
	var typeResourcts PIMAGE_RESOURCE_DIRECTORY
	var foundType PIMAGE_RESOURCE_DIRECTORY_ENTRY
	var foundName PIMAGE_RESOURCE_DIRECTORY_ENTRY
	var foundLanguage PIMAGE_RESOURCE_DIRECTORY_ENTRY
	if directory.Size == 0 {
		// no resource table found
		panic("ERROR_RESOURCE_DATA_NOT_FOUND")
		return nil
	}

	if language == DEFAULT_LANGUAGE {
		// use language from current thread
		language = LANGIDFROMLCID(GetThreadLocale())
	}

	// resources are stored as three-level tree
	// - first node is the type
	// - second node is the name
	// - third node is the language
	rootResources = to[PIMAGE_RESOURCE_DIRECTORY](add(codeBase, directory.VirtualAddress))
	foundType = _MemorySearchResourceEntry(to[PBYTE](rootResources), rootResources, typ)
	if foundType == nil {
		panic("ERROR_RESOURCE_TYPE_NOT_FOUND 11")
		return nil
	}
	return nil
}

func MemorySizeofResource(module HMEMORYMODULE, resource HMEMORYRSRC) DWORD { return 0 }

func MemoryLoadResource(module HMEMORYMODULE, resource HMEMORYRSRC) LPVOID { return nil }

func MemoryLoadString(module HMEMORYMODULE, id UINT, buffer LPTSTR, maxsize int32) int32 { return 0 }

func MemoryLoadStringEx(module HMEMORYMODULE, id UINT, buffer LPTSTR, maxsize int32, language WORD) int32 {
	return 0
}
