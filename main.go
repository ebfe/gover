package main

import (
	"debug/dwarf"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

type Binary interface {
	DWARF() (*dwarf.Data, error)
	Close() error

	ReadAtVaddr(b []byte, vaddr uint64) (int, error)
	PtrSize() uint
}

func openBinary(name string) (Binary, error) {
	e, err := elf.Open(name)
	if err == nil {
		return &elfBinary{File: e}, nil
	}
	p, err := pe.Open(name)
	if err == nil {
		return &peBinary{File: p}, nil
	}
	return nil, err
}

type elfBinary struct {
	*elf.File
}

func (e *elfBinary) ReadAtVaddr(b []byte, vaddr uint64) (int, error) {
	for _, s := range e.Sections {
		if vaddr >= s.Addr && vaddr < s.Addr+s.Size {
			return s.ReadAt(b, int64(vaddr-s.Addr))
		}
	}
	return 0, fmt.Errorf("addr not mapped")
}

func (e *elfBinary) PtrSize() uint {
	switch e.Class {
	case elf.ELFCLASS32:
		return 4
	case elf.ELFCLASS64:
		return 8
	default:
		panic("unknown elf class")
	}
}

type peBinary struct {
	*pe.File
}

func (p *peBinary) ReadAtVaddr(b []byte, vaddr uint64) (int, error) {
	base := p.imageBase()
	for _, s := range p.Sections {
		start := base + uint64(s.VirtualAddress)
		end := start + uint64(s.Size)
		if vaddr >= start && vaddr < end {
			return s.ReadAt(b, int64(vaddr-(base+uint64(s.VirtualAddress))))
		}
	}
	return 0, fmt.Errorf("addr not mapped")
}

func (p *peBinary) PtrSize() uint {
	// FIXME?
	switch p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return 4
	case *pe.OptionalHeader64:
		return 8
	}
	panic("unknown pe format")
}

func (p *peBinary) imageBase() uint64 {
	switch oh := p.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	panic("unknown pe format")
}

type variable struct {
	Addr uint64
	Type dwarf.Type
}

func readString(b Binary, v *variable) (string, error) {
	if v.Type.String() != "struct string" {
		return "", fmt.Errorf("wrong type %q", v.Type.String())
	}

	val := make([]byte, v.Type.Size())
	if _, err := b.ReadAtVaddr(val, v.Addr); err != nil {
		return "", err
	}

	sptr := uint64(0)
	slen := uint64(0)
	switch b.PtrSize() {
	case 4:
		sptr = uint64(binary.LittleEndian.Uint32(val))
		slen = uint64(binary.LittleEndian.Uint32(val[4:]))
	case 8:
		sptr = binary.LittleEndian.Uint64(val)
		slen = binary.LittleEndian.Uint64(val[8:])
	}

	val = make([]byte, slen)
	if _, err := b.ReadAtVaddr(val, sptr); err != nil {
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
	e, err := openBinary(file)
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
