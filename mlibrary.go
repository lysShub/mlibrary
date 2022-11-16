package mlibrary

import (
	"log"

	"github.com/saferwall/pe"
	"golang.org/x/sys/windows"
)

func main() {
	filename := "D:\\OneDrive\\code\\C\\ctest\\a.dll"
	p, err := pe.New(filename, &pe.Options{})
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", filename, err)
	}

	err = p.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", filename, err)
	}

}

func NewMLibrary(d []byte) (*windows.DLL, error) {
	p, err := pe.NewBytes(d, &pe.Options{})
	if err != nil {
		return nil, err
	}
	err = p.Parse()
	if err != nil {
		return nil, err
	}

	size := (p.NtHeader.OptionalHeader).(*pe.ImageOptionalHeader64).SizeOfImage
	base := (p.NtHeader.OptionalHeader).(*pe.ImageOptionalHeader64).ImageBase
	baseAddr, err := windows.VirtualAlloc(uintptr(base), uintptr(size), windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}

	// copy sections
	for i := range p.Sections {

		sAddr := p.Sections[i].Header.VirtualAddress
		sSize := p.Sections[i].Header.SizeOfRawData
		dest, err := windows.VirtualAlloc(baseAddr+uintptr(sAddr), uintptr(sSize), windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if err != nil {
			return nil, err
		}

	}

	return nil, nil
}
