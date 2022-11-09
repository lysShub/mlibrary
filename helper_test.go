package mlibrary

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func Test_PtrTo(t *testing.T) {
	var data1 uint64 = 0x0000f00f
	var r1 = to[uint16](data1)
	require.Equal(t, uint16(0xf00f), r1)

	var data2 uint64 = 0x0000f00f
	var r2 = *to[*uint16](&data2)
	require.Equal(t, uint16(0xf00f), r2)

	var data3 = [6]byte{1, 2, 3, 4, 5, 6}
	var r3 = *to[*uint16](&data3[1])
	require.Equal(t, uint16(0x302), r3)

	var data4 int = 0xff
	var r4 = to[*int](unsafe.Pointer(&data4))
	require.Equal(t, int(0xff), *r4)

	var data5 = []byte{'m', 'l', 'i', 'b', 'r', 'a', 'r', 'y'}
	var r5 = to[string](data5)
	require.Equal(t, "mlibrary", r5)
}

func Test_Add(t *testing.T) {
	var data1 = []byte{1, 2, 3, 4, 5, 6}

	var r1 = add(&data1[0], 2)
	require.Equal(t, byte(3), *r1)

	var r2 = add(uintptr(0), 1)
	require.Equal(t, uintptr(1), r2)
}

func Test_Memcpy(t *testing.T) {
	var data1 = [8]byte{1, 2, 3, 4, 4, 3, 2, 1}
	var data2 uint64

	memcpy(unsafe.Pointer(&data2), unsafe.Pointer(&data1), 8)
	require.Equal(t, uint64(0x102030404030201), data2)
}
