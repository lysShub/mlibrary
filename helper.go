package mlibrary

import (
	"debug/pe"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const _typeOffset = unsafe.Sizeof(uintptr(0))*2 + 7
const _typeMask = ((1 << 5) - 1)

const (
	HEAP_ZERO_MEMORY = 0x00000008
)

const (
	FALSE BOOL = 1
	TRUE  BOOL = 1
)
const GMEM_MOVEABLE = 0x0002

// typedef LPVOID (*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
type CustomAllocFunc *func(LPVOID, SIZE_T, DWORD, DWORD) (LPVOID, error)

// typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
type CustomFreeFunc *func(LPVOID, SIZE_T, DWORD) (BOOL, error)

// typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
type CustomLoadLibraryFunc *func(LPCSTR) (HCUSTOMMODULE, error)

// typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
type CustomGetProcAddressFunc *func(HCUSTOMMODULE, LPCSTR) (FARPROC, error)

// typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);
type CustomFreeLibraryFunc *func(HCUSTOMMODULE) error

type BYTE = byte

type Literal interface {
	LPVOID | uintptr | uint64 | uint32 | *int | *uint8 | []byte | string | *IMAGE_DOS_HEADER | *IMAGE_NT_HEADERS | *IMAGE_SECTION_HEADER | *MLIBRARY | *IMAGE_IMPORT_DESCRIPTOR | *HCUSTOMMODULE | *uintptr | *uint16 | uint16 | uint8 | *uintptr_t | *FARPROC | *IMAGE_IMPORT_BY_NAME | *IMAGE_TLS_DIRECTORY | *PIMAGE_TLS_CALLBACK
}

// TAG: here!!!!!!!!!!!!!!!!!!!!!!
// typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
type DllEntryProc func(hinstDLL HINSTANCE, fdwReson DWORD, lpReserved LPVOID) BOOL

func to[T Literal](v any) T {
	var typ = *(*uint8)(unsafe.Add(*(*unsafe.Pointer)(unsafe.Pointer(&v)), _typeOffset)) & _typeMask
	var data = *(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&v), unsafe.Sizeof(uintptr(0))))
	// kindPtr或kindUnsafePointer data = unsafe.Pointer(v)
	// else						  data = unsafe.Pointer(&v)
	if typ == uint8(reflect.Pointer) || typ == uint8(reflect.UnsafePointer) {
		return *(*T)(unsafe.Pointer(&data))
	} else {
		var r = **(**T)(unsafe.Pointer(&data))
		return r
	}
}

func add[T Literal](v T, delta int) T {
	var p = unsafe.Add(*(*unsafe.Pointer)(unsafe.Pointer(&v)), delta)
	return *(*T)(unsafe.Pointer(&p))
}

func memcpy(ptr1, ptr2 unsafe.Pointer, size int) {
	var s1 = struct {
		array unsafe.Pointer
		len   int
		cap   int
	}{
		array: ptr1,
		len:   size,
		cap:   size,
	}
	var s2 = struct {
		array unsafe.Pointer
		len   int
		cap   int
	}{
		array: ptr2,
		len:   size,
		cap:   size,
	}
	copy(to[[]byte](s1), to[[]byte](s2))
}

func AlignValueUp(value, alignment size_t) size_t {
	return (value + alignment - 1) & (^(alignment - 1))
}

func AlignValueDown(value uintptr_t, alignment uintptr_t) uintptr_t {
	return value & (^(alignment - 1))
}

func AlignAddressDown(address LPVOID, alignment uintptr_t) LPVOID {
	return to[LPVOID](AlignValueDown(to[uintptr_t](address), alignment))
}

func GetRealSectionSize(module *MLIBRARY, section *IMAGE_SECTION_HEADER) SIZE_T {
	var size DWORD = section.Size
	if size == 0 {
		if section.Characteristics&pe.IMAGE_SCN_CNT_INITIALIZED_DATA == uint32(TRUE) {
			size = module.headers.OptionalHeader.SizeOfInitializedData
		} else if section.Characteristics&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA == uint32(TRUE) {
			size = module.headers.OptionalHeader.SizeOfUninitializedData
		}
	}
	return to[SIZE_T](size)
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

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procHeapAlloc = modkernel32.NewProc("HeapAlloc")
var procIsBadReadPtr = modkernel32.NewProc("IsBadReadPtr")
var procGetProcessHeap = modkernel32.NewProc("GetProcessHeap")
var procGlobalReAlloc = modkernel32.NewProc("GlobalReAlloc")
var procLoadLibraryA = modkernel32.NewProc("LoadLibraryA")

func HeapAlloc(hHeap windows.Handle, dwFlags DWORD, dwBytes size_t) (p uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procHeapAlloc.Addr(), uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	if r0 == 0 {
		err = errnoErr(e1)
	}
	return r0, err
}

func IsBadReadPtr(lp unsafe.Pointer, ucb UINT_PTR) bool {
	r0, _, _ := syscall.SyscallN(procIsBadReadPtr.Addr(), uintptr(lp), uintptr(ucb))
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

func realloc(ptr unsafe.Pointer, newSize size_t) (unsafe.Pointer, error) {
	r0, _, e1 := syscall.SyscallN(procGlobalReAlloc.Addr(), uintptr(ptr), uintptr(newSize), GMEM_MOVEABLE)
	if r0 == 0 {
		return nil, errnoErr(e1)
	}
	return unsafe.Pointer(r0), nil
}

func LoadLibraryA(libname string) (handle windows.Handle, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(libname)
	if err != nil {
		return
	}

	r0, _, e1 := syscall.SyscallN(procLoadLibraryA.Addr(), uintptr(unsafe.Pointer(_p0)))
	handle = windows.Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return handle, err
}
