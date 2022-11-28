package main

import (
	"fmt"
	"io"
	"mlibrary"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	filename := "D:\\OneDrive\\code\\C\\ctest\\a.dll"
	// filename := "D:\\OneDrive\\code\\go\\MyApp\\sciter.dll"

	// dll1, err := windows.LoadDLL(filename)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer dll1.Release()
	// write(uintptr(dll1.Handle), "C:\\Users\\lys\\Desktop\\o.b")
	// return
	// 1711800320 = 0x66080000
	// 81920 = 0x14000

	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	rb, _ := io.ReadAll(f)

	dll, err := mlibrary.NewMLibrary(rb)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dll.Release()

	var da []byte = make([]byte, 81920)
	fh, err := os.Open("C:\\Users\\lys\\Desktop\\o.b")
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = fh.Read(da)
	if err != nil {
		fmt.Println(err)
		return
	}

	memcpy(uintptr(dll.Handle), uintptr(unsafe.Pointer(&da[0])), 81920)

	r, err := windows.GetProcAddress(windows.Handle(dll.Handle), "echo")
	fmt.Println(r, err)

	// "Failed to find echo procedure in memory module: The specified module could not be found."

	// write(uintptr(dll.Handle), "C:\\Users\\lys\\Desktop\\m.b")

}

func write(from uintptr, path string) {

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err.Error())
	}

	var b = make([]byte, 81920)

	memcpy(uintptr(unsafe.Pointer(&b[0])), from, 81920)

	n, err := f.Write(b)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(n)
	f.Close()
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
