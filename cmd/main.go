package main

import (
	"fmt"
	"io"
	"mlibrary"
	"os"

	"golang.org/x/sys/windows"
)

func main() {
	filename := "D:\\OneDrive\\code\\C\\ctest\\a.dll"
	// filename := "D:\\OneDrive\\code\\go\\MyApp\\sciter.dll"

	dll1, err := windows.LoadDLL(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dll1.Release()
	fmt.Println(dll1)
	p1, err := dll1.FindProc("echo")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(p1)
	return

	// 1711800320 = 0x66080000

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

	p, err := dll.FindProc("echo")
	if err != nil {
		fmt.Println(err)
		return
	}

	p.Call()
}
