package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

func findSymbol(e *elf.File, symbol string) (*elf.Symbol, error) {
	syms, err := e.Symbols()
	if err != nil {
		return nil, err
	}

	for _, sym := range syms {
		if sym.Name == symbol {
			return &sym, nil
		}
	}

	return nil, nil
}

func readString(e *elf.File, sym *elf.Symbol) (string, error) {
	buf := make([]byte, sym.Size)
	sect := e.Sections[sym.Section]
	if _, err := sect.ReadAt(buf, int64(sym.Value-sect.Addr)); err != nil {
		return "", err
	}

	straddr := uint64(0)
	strlen  := uint64(0)
	switch e.Class {
	case elf.ELFCLASS32:
		straddr = uint64(binary.LittleEndian.Uint32(buf))
		strlen = uint64(binary.LittleEndian.Uint32(buf[4:]))
	case elf.ELFCLASS64:
		straddr = binary.LittleEndian.Uint64(buf)
		strlen = binary.LittleEndian.Uint64(buf[8:])
	}

	sindex := -1 
	for i, s := range e.Sections {
		if s.Addr <= straddr && straddr < s.Addr + s.Size {
			sindex = i
		}
	}
	sect = e.Sections[sindex]
	value := make([]byte, strlen)
	if _, err := sect.ReadAt(value, int64(straddr-sect.Addr)); err != nil {
		return "", err
	}

	return string(value), nil
}

func findVersion(file string) (string, error) {
	e, err := elf.Open(file)
	if err != nil {
		return "", err
	}
	defer e.Close()

	sym, err := findSymbol(e, "runtime.buildVersion")
	if err != nil {
		return "", err
	}
	if sym == nil {
		return "", fmt.Errorf("can't find version symbol")
	}

	return readString(e, sym)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <file>\n", os.Args[0])
		os.Exit(1)
	}

	ver, err := findVersion(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "gover: %s\n", err)
		os.Exit(1)
	}
	fmt.Println(ver)
}
