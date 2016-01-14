package main

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

type variable struct {
	Addr uint64
	Type dwarf.Type
}

func findSection(e *elf.File, addr uint64) *elf.Section {
	for _, sect := range e.Sections {
		if addr >= sect.Addr && addr < sect.Addr+sect.Size {
			return sect
		}
	}
	return nil
}

func readString(e *elf.File, v *variable) (string, error) {
	if v.Type.String() != "struct string" {
		return "", fmt.Errorf("wrong type %q", v.Type.String())
	}
	s := findSection(e, v.Addr)
	if s == nil {
		return "", fmt.Errorf("no section for addr")
	}
	val := make([]byte, v.Type.Size())
	_, err := s.ReadAt(val, int64(v.Addr-s.Addr))
	if err != nil {
		return "", err
	}

	sptr := uint64(0)
	slen := uint64(0)
	switch e.Class {
	case elf.ELFCLASS32:
		sptr = uint64(binary.LittleEndian.Uint32(val))
		slen = uint64(binary.LittleEndian.Uint32(val[4:]))
	case elf.ELFCLASS64:
		sptr = binary.LittleEndian.Uint64(val)
		slen = binary.LittleEndian.Uint64(val[8:])
	}

	s = findSection(e, sptr)
	if s == nil {
		return "", fmt.Errorf("no section for addr")
	}
	val = make([]byte, slen)
	_, err = s.ReadAt(val, int64(sptr-s.Addr))
	if err != nil {
		return "", err
	}
	return string(val), nil
}

func findVariable(d *dwarf.Data, name string) (*variable, error) {
	dr := d.Reader()
	for {
		e, err := dr.Next()
		if e == nil || err != nil {
			return nil, err
		}

		if e.Tag != dwarf.TagVariable {
			continue
		}

		aname, ok := e.Val(dwarf.AttrName).(string)
		if !ok || aname != name {
			continue
		}
		loc, ok := e.Val(dwarf.AttrLocation).([]uint8)
		if !ok {
			continue
		}
		if loc[0] != 3 {
			return nil, fmt.Errorf("can't determine variable addr")
		}
		addr := uint64(0)
		switch len(loc) {
		case 5:
			addr = uint64(binary.LittleEndian.Uint32(loc[1:]))
		case 9:
			addr = uint64(binary.LittleEndian.Uint64(loc[1:]))
		default:
			return nil, fmt.Errorf("unknown addr size")
		}

		off, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			continue
		}
		typ, err := d.Type(off)
		if err != nil {
			return nil, err
		}

		return &variable{Addr: addr, Type: typ}, nil
	}
	return nil, nil
}

func findVersion(file string) (string, error) {
	e, err := elf.Open(file)
	if err != nil {
		return "", err
	}
	defer e.Close()

	d, err := e.DWARF()
	if err != nil {
		return "", err
	}
	v, err := findVariable(d, "runtime.buildVersion")
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", fmt.Errorf("can't find version symbol")
	}
	return readString(e, v)
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
