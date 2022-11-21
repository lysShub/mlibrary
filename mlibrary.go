package mlibrary

import (
	"fmt"
	"io"
	"unsafe"

	"debug/pe"

	"golang.org/x/sys/windows"
)

func NewMLibrary(src io.ReaderAt, da uintptr) (*windows.DLL, error) {
	p, err := pe.NewFile(src)
	if err != nil {
		return nil, err
	}
	var mempe uintptr

	var fileHeader = p.FileHeader
	var optHeader = p.OptionalHeader.(*pe.OptionalHeader64)
	var sections = p.Sections
	var sectNum = fileHeader.NumberOfSections
	var imageSize = uintptr(optHeader.SizeOfImage)

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

	{ // load

		// copy headers
		var buf []byte = make([]byte, optHeader.SizeOfHeaders)
		if n, err := src.ReadAt(buf, 0); err != nil {
			return nil, err
		} else if n != int(optHeader.SizeOfHeaders) {
			return nil, io.ErrUnexpectedEOF
		}
		CopyMemory(
			mempe,
			uintptr(unsafe.Pointer(&buf[0])),
			int(optHeader.SizeOfHeaders),
		)

		var pDOSHeader = to[*IMAGE_DOS_HEADER](mempe)
		var pNTHeader = to[*IMAGE_NT_HEADERS](mempe + uintptr(pDOSHeader.e_lfanew))
		fmt.Println(pNTHeader)

		// copy sections
		for i := uint16(0); i < sectNum; i++ {
			var pSectHeader = sections[i].SectionHeader
			if pSectHeader.Size == 0 {
				continue
			}

			var buf []byte = make([]byte, pSectHeader.Size /*SizeOfRawData*/)
			if n, err := src.ReadAt(buf, int64(pSectHeader.Offset /*PointerToRawData*/)); err != nil {
				return nil, err
			} else if n != int(pSectHeader.Size) {
				return nil, io.ErrUnexpectedEOF
			}
			CopyMemory(
				mempe+uintptr(pSectHeader.VirtualAddress),
				uintptr(unsafe.Pointer(&buf[0])),
				len(buf),
			)
		}

		// validate mem align
		// TODO
	}

	var pDOSHeader = to[*IMAGE_DOS_HEADER](mempe)
	var pNTHeader = to[*IMAGE_NT_HEADERS](mempe + uintptr(pDOSHeader.e_lfanew))
	var pOptHeader = &pNTHeader.OptionalHeader

	if reloc { // relocate

		var pRelocationTable = pNTHeader.OptionalHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		var pRelocEntry = to[*IMAGE_BASE_RELOCATION](mempe + uintptr(pRelocationTable.VirtualAddress))
		var offset = DWORD(mempe - uintptr(pNTHeader.OptionalHeader.ImageBase))
		if mempe < uintptr(pNTHeader.OptionalHeader.ImageBase) {
			panic(mempe)
		}

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
		// 导入dll文件数量
		for ; pImpDesc.Name != 0; pImpDesc = add(pImpDesc, 1) {
			pName = toStr(mempe + uintptr(pImpDesc.Name))
			pThunk = to[*IMAGE_THUNK_DATA](mempe + uintptr(pImpDesc.FirstThunk))
			pOThunk = to[*IMAGE_THUNK_DATA](mempe + uintptr(pImpDesc.OriginalFirstThunk))

			// 导入此文件的函数数量
			h, err := windows.LoadLibrary(pName)
			if err != nil {
				return nil, err
			}
			for j := 0; pThunk.Function != 0 && pOThunk.Function != 0; j++ {
				pOThunk = add(pOThunk, j)
				var _addr = mempe + uintptr(pOThunk.AddressOfData)

				pImpByName := to[*IMAGE_IMPORT_BY_NAME](_addr)

				var funcname = toStr(uintptr(unsafe.Pointer(&pImpByName.Name[0])))

				fp, err := windows.GetProcAddress(h, funcname)
				if err != nil {
					return nil, err
				}
				pThunk = add(pThunk, j)
				pThunk.Function = uint64(fp)
			}
		}
	}

	return nil, nil
}

func CopyMemory(dst, src uintptr, size int) {
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
	println(n)
}

type pLiteral interface {
	*byte | *IMAGE_DOS_HEADER | *IMAGE_NT_HEADERS | *IMAGE_BASE_RELOCATION | *DWORD | *IMAGE_IMPORT_DESCRIPTOR | *IMAGE_THUNK_DATA | *IMAGE_IMPORT_BY_NAME
}

type Literal interface {
	IMAGE_DOS_HEADER | IMAGE_NT_HEADERS | IMAGE_BASE_RELOCATION | IMAGE_IMPORT_DESCRIPTOR | IMAGE_THUNK_DATA
}

func to[T pLiteral](p uintptr) T {
	return (T)(unsafe.Add(nil, p))
}

func add[T Literal](p *T, n int) *T {
	s := unsafe.Sizeof(*p)
	return (*T)(unsafe.Add(unsafe.Pointer(p), s*uintptr(n)))
}

func toStr(p uintptr) string {
	return windows.BytePtrToString((*byte)(unsafe.Add(nil, p)))
}
