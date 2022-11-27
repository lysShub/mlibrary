package mlibrary

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"

	"debug/pe"

	"golang.org/x/sys/windows"
)

func NewMLibrary(b []byte) (dll *windows.DLL, err error) {
	p, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var mempe uintptr

	var fileHeader = p.FileHeader
	var optHeader = p.OptionalHeader.(*pe.OptionalHeader64)
	var sections = p.Sections
	var sectNum = fileHeader.NumberOfSections
	var imageSize = uintptr(optHeader.SizeOfImage)
	if fileHeader.Characteristics&pe.IMAGE_FILE_DLL == 0 {
		return nil, fmt.Errorf("pe file isn't a dll")
	}

	var reloc bool = true
	mempe, err = windows.VirtualAlloc(uintptr(optHeader.ImageBase), imageSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		mempe, err = windows.VirtualAlloc(uintptr(0), imageSize, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return nil, err
		}
	} else {
		reloc = false
		_, err = windows.VirtualAlloc(mempe, imageSize, windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
		if err != nil {
			windows.VirtualFree(mempe, 0, windows.MEM_RELEASE)
		}
	}()

	{ // load
		var oldprotect DWORD
		if err := windows.VirtualProtect(mempe, imageSize, windows.PAGE_EXECUTE_READWRITE, &oldprotect); err != nil {
			return nil, err
		}

		// copy headers
		memcpy(
			mempe,
			uintptr(unsafe.Pointer(&b[0])),
			int(optHeader.SizeOfHeaders),
		)

		// copy sections
		for i := uint16(0); i < sectNum; i++ {
			pSectHeader := sections[i].SectionHeader
			if pSectHeader.Size == 0 {
				continue
			}

			off := int(pSectHeader.Offset)
			size := int(pSectHeader.Size) /*SizeOfRawData*/
			memcpy(
				mempe+uintptr(pSectHeader.VirtualAddress),
				uintptr(unsafe.Pointer(&b[off])),
				size,
			)
		}

		if err := windows.VirtualProtect(mempe, imageSize, oldprotect, &oldprotect); err != nil {
			return nil, err
		}
	}

	var pDOSHeader = to[*IMAGE_DOS_HEADER](mempe)
	var pNTHeader = to[*IMAGE_NT_HEADERS](mempe + uintptr(pDOSHeader.e_lfanew))
	var pOptHeader = &pNTHeader.OptionalHeader

	{ // mem alignment
		pSectHeader := to[*IMAGE_SECTION_HEADER](uintptr(unsafe.Pointer(pOptHeader)) + uintptr(pNTHeader.FileHeader.SizeOfOptionalHeader))

		pOptHeader.FileAlignment = pOptHeader.SectionAlignment
		for i := uint16(0); i < sectNum; i++ {
			pSectHeader.PointerToRawData = pSectHeader.VirtualAddress

			pSectHeader = add(pSectHeader, 1)
		}
	}

	if reloc { // relocate

		var pRelocationTable = pNTHeader.OptionalHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		var pRelocEntry = to[*IMAGE_BASE_RELOCATION](mempe + uintptr(pRelocationTable.VirtualAddress))
		var offset = DWORD(mempe - uintptr(pNTHeader.OptionalHeader.ImageBase))

		for pRelocEntry != nil && (pRelocEntry.SizeOfBlock != 0 && pRelocEntry.VirtualAddress != 0) {

			var count = (pRelocEntry.SizeOfBlock - 8) / 2
			for i := uint32(0); i < count; i++ {
				var typeInfo = *(*uint16)(unsafe.Add(unsafe.Pointer(pRelocEntry), 8+i*2))

				var type_ = typeInfo >> 12
				if type_ == 3 || type_ == 10 {
					var relocAddrOff = uintptr(pRelocEntry.VirtualAddress) + uintptr(typeInfo&0xfff)
					var relocAddr = mempe + relocAddrOff

					*to[*DWORD](relocAddr) += offset
				}
			}

			newEntryAddr := uintptr(unsafe.Pointer(pRelocEntry)) + uintptr(pRelocEntry.SizeOfBlock)
			pRelocEntry = to[*IMAGE_BASE_RELOCATION](newEntryAddr)
		}
	}

	{ // load iat

		var pImpEntry = pOptHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		var pImpDesc = to[*IMAGE_IMPORT_DESCRIPTOR](mempe + uintptr(pImpEntry.VirtualAddress))

		var pName string
		var pThunk *IMAGE_THUNK_DATA
		var pOThunk *IMAGE_THUNK_DATA
		for ; pImpDesc.Name != 0; pImpDesc = add(pImpDesc, 1) {

			pName = toStr(mempe + uintptr(pImpDesc.Name))
			pThunk = to[*IMAGE_THUNK_DATA](mempe + uintptr(pImpDesc.FirstThunk))
			pOThunk = to[*IMAGE_THUNK_DATA](mempe + uintptr(pImpDesc.OriginalFirstThunk))

			h, err := windows.LoadLibrary(pName)
			if err != nil {
				return nil, err
			}
			for pThunk.Function != 0 && pOThunk.Function != 0 {
				addr := mempe + uintptr(pOThunk.Function /*AddressOfData*/)
				pImpByName := to[*IMAGE_IMPORT_BY_NAME](addr)
				funcname := toStr(uintptr(unsafe.Pointer(&pImpByName.Name[0])))

				fp, err := windows.GetProcAddress(h, funcname)
				if err != nil {
					return nil, err
				} else {
					pThunk.Function = uint64(fp)
				}

				pThunk = add(pThunk, 1)
				pOThunk = add(pOThunk, 1)
			}
		}
	}

	{ // release

	}

	{ // get entry point

		entry := mempe + uintptr(pOptHeader.AddressOfEntryPoint)

		// typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
		r1, _, err := syscall.SyscallN(entry, mempe, DLL_PROCESS_ATTACH, 0)
		if err != 0 || r1 == 0 {
			return nil, fmt.Errorf("dll process attach failed, %s", err)
		}

		return &windows.DLL{
			Name:   "memory module",
			Handle: windows.Handle(mempe),
		}, nil
	}
}

func memcpy(dst, src uintptr, size int) {
	var sdst = struct {
		array uintptr
		len   int
		cap   int
	}{
		array: dst,
		len:   size,
		cap:   size,
	}
	var ssrc = struct {
		array uintptr
		len   int
		cap   int
	}{
		array: src,
		len:   size,
		cap:   size,
	}
	n := copy(*(*[]byte)(unsafe.Pointer(&sdst)), *(*[]byte)(unsafe.Pointer(&ssrc)))
	if n != size {
		panic("memory copy failed")
	}
}

type pLiteral interface {
	*byte | *IMAGE_DOS_HEADER | *IMAGE_NT_HEADERS | *IMAGE_SECTION_HEADER | *IMAGE_BASE_RELOCATION | *DWORD | *IMAGE_IMPORT_DESCRIPTOR | *IMAGE_THUNK_DATA | *IMAGE_IMPORT_BY_NAME | *IMAGE_TLS_DIRECTORY
}

type Literal interface {
	IMAGE_DOS_HEADER | IMAGE_NT_HEADERS | IMAGE_SECTION_HEADER | IMAGE_BASE_RELOCATION | IMAGE_IMPORT_DESCRIPTOR | IMAGE_THUNK_DATA
}

func to[T pLiteral](p uintptr) T {
	return (T)(unsafe.Add(nil, p))
}

func add[T Literal](p *T, step int) *T {
	s := unsafe.Sizeof(*p)
	return (*T)(unsafe.Add(unsafe.Pointer(p), s*uintptr(step)))
}

func toStr(p uintptr) string {
	return windows.BytePtrToString((*byte)(unsafe.Add(nil, p)))
}
