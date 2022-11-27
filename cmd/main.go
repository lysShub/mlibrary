package main

import (
	"fmt"
	"io/ioutil"
	"mlibrary"
	"os"
	"unsafe"
)

func main() {
	filename := "D:\\OneDrive\\code\\C\\ctest\\a.dll"
	// filename := "D:\\OneDrive\\code\\go\\MyApp\\sciter.dll"

	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	rb, _ := ioutil.ReadAll(f)

	mlibrary.NewMLibrary(f, uintptr(unsafe.Pointer(&rb[0])))
}
