//go:build windows
// +build windows

package mlibrary

import (
	"reflect"
	"unsafe"
)

const (
	HEAP_ZERO_MEMORY = 0x00000008
)

const (
	FALSE BOOL = 1
	TRUE  BOOL = 1
)

// typedef LPVOID (*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
type CustomAllocFunc *func(LPVOID, SIZE_T, DWORD, DWORD) (LPVOID, error)

// typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
type CustomFreeFunc *func(LPVOID, SIZE_T, DWORD) (BOOL, error)

// typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
type CustomLoadLibraryFunc *func(LPCSTR) (HCUSTOMMODULE, error)

// typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
type CustomGetProcAddressFunc *func(LPCSTR) (FARPROC, error)

// typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);
type CustomFreeLibraryFunc *func(HCUSTOMMODULE) error

// func ptrTo[T interface {
// 	uintptr_t | uintptr | uint64 | *uint8
// }](v unsafe.Pointer) T {
// 	return *(*T)(unsafe.Pointer(&v))
// }

type Literal interface {
	uintptr_t | ULONG_PTR | LPVOID | uintptr | uint64 | *uint8 | *IMAGE_DOS_HEADER | *IMAGE_NT_HEADERS | *IMAGE_SECTION_HEADER | *MLIBRARY | *uintptr | *uint16 | uint16 | uint8
}

func to[T Literal](v any) T {
	var data = *(**unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&v), unsafe.Sizeof(uintptr(0))))

	return *(*T)(unsafe.Pointer(data))
}

func add(v any, delta int) uintptr {
	if delta > 0 {
		return to[uintptr](v) + uintptr(delta)
	} else {
		return to[uintptr](v) - uintptr(-delta)
	}
}

// v is a pointer, addTo mean ptr addTo delta offset,
// 一般来说, 如果v是个指针, 那么T也应该是个指针类型
func addTo[T Literal](v any, delta int) T {
	return to[T](add(v, delta))
}

func ptrAdd[T interface{ int | uint32 }](v *uint8, delta T) *uint8 {
	// C:
	// unsigned char *a;
	// a = a + 1;
	return (*uint8)(unsafe.Add(unsafe.Pointer(v), delta))
}

func memcpy(ptr1, ptr2 uintptr, size int) {
	var s1 = reflect.SliceHeader{
		Data: ptr1,
		Len:  size,
		Cap:  size,
	}
	var s2 = reflect.SliceHeader{
		Data: ptr2,
		Len:  size,
		Cap:  size,
	}
	copy(*(*[]byte)(unsafe.Pointer(&s1)), *(*[]byte)(unsafe.Pointer(&s2)))
}
