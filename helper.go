package mlibrary

import (
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
type CustomAllocFunc *func(LPVOID, SIZE_T, DWORD, DWORD, PVOID) (LPVOID, error)

// typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
type CustomFreeFunc *func(LPVOID, SIZE_T, DWORD, PVOID) (BOOL, error)

// typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
type CustomLoadLibraryFunc *func(LPCSTR, PVOID) (HCUSTOMMODULE, error)

// typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
type CustomGetProcAddressFunc *func(HCUSTOMMODULE, LPCSTR, PVOID) (FARPROC, error)

// typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);
type CustomFreeLibraryFunc *func(HCUSTOMMODULE, PVOID) error

type BYTE = byte

type Literal interface {
	LPVOID | uintptr | uint64 | uint32 | *int | *uint8 | []byte | string | *IMAGE_DOS_HEADER | *IMAGE_NT_HEADERS | *IMAGE_SECTION_HEADER | *MLIBRARY | *IMAGE_IMPORT_DESCRIPTOR | *HCUSTOMMODULE | *uintptr | *uint16 | uint16 | uint8 | *uintptr_t | *FARPROC | *IMAGE_IMPORT_BY_NAME | *IMAGE_TLS_DIRECTORY | *PIMAGE_TLS_CALLBACK | DllEntryProc | ExeEntryProc
}

// typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
type DllEntryProc *func(hinstDLL HINSTANCE, fdwReson DWORD, lpReserved LPVOID) BOOL

type ExeEntryProc *func() int

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

type Number interface {
	int | uintptr | uint64 | uint32 | int32
}

func add[T Literal, N Number](v T, delta N) T {
	var p = unsafe.Add(*(*unsafe.Pointer)(unsafe.Pointer(&v)), delta)
	return *(*T)(unsafe.Pointer(&p))
}

func memcpy(dst, src unsafe.Pointer, size int) {
	var s1 = struct {
		array unsafe.Pointer
		len   int
		cap   int
	}{
		array: dst,
		len:   size,
		cap:   size,
	}
	var s2 = struct {
		array unsafe.Pointer
		len   int
		cap   int
	}{
		array: src,
		len:   size,
		cap:   size,
	}
	copy(to[[]byte](s1), to[[]byte](s2))
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
	return r0 != 0 // 0:false  1:true
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
	return to[unsafe.Pointer](r0), nil
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
