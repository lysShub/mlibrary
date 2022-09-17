package mlibrary

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestA(t *testing.T) {

	var a []byte = []byte{1, 2, 3, 4, 5, 6}

	var b0 = unsafe.Pointer(&a[1])
	// var b1 = (*uintptr)(unsafe.Pointer(&a[1]))

	// var r0 = to[unsafe.Pointer](&a[1])

	var c uint64 = 0x0000f00f

	var r1 = to[uint16](c)

	fmt.Println(r1, b0, a, c)
}
