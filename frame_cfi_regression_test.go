package dwarf

import (
	"encoding/binary"
	"math"
	"testing"
)

func frameTestU32(dst []byte, n uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	return append(dst, b[:]...)
}

func frameTestU64(dst []byte, n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return append(dst, b[:]...)
}

func frameTestEntry(body []byte) []byte {
	for (len(body)+4)%8 != 0 {
		body = append(body, 0)
	}
	return append(frameTestU32(nil, uint32(len(body))), body...)
}

func frameTestDebugCIE(cfis []byte) []byte {
	body := frameTestU32(nil, 0xffffffff)
	body = append(body, 4, 0, 8, 0, 1, 0x78, 16)
	return frameTestEntry(append(body, cfis...))
}

func frameTestDebugFDE(cieOffset uint32, cfis []byte) []byte {
	body := frameTestU32(nil, cieOffset)
	body = frameTestU64(body, 0x1000)
	body = frameTestU64(body, 0x20)
	return frameTestEntry(append(body, cfis...))
}

func TestFrameIndirectPointers(t *testing.T) {
	const sectionAddress = uint64(0x100000000)
	for _, encoding := range []byte{0x1b, 0x9b} {
		// zPLR with PC-relative sdata4 personality, LSDA, and code pointers.
		cie := frameTestU32(nil, 0)
		cie = append(cie, 1, 'z', 'P', 'L', 'R', 0, 1, 0x78, 16, 7, encoding)
		cie = frameTestU32(cie, 0x3000-uint32(4+len(cie)))
		cie = append(cie, encoding, 0x1b, 0x0c, 7, 8)
		data := frameTestEntry(cie)

		fde := frameTestU32(nil, uint32(len(data)+4))
		fde = frameTestU32(fde, 0x1000-uint32(len(data)+8))
		fde = frameTestU32(fde, 0x20)
		fde = append(fde, 4)
		fde = frameTestU32(fde, 0x4000-uint32(len(data)+4+len(fde)))
		data = append(data, frameTestEntry(fde)...)

		f, err := ParseFrame(data, binary.LittleEndian, 8, sectionAddress, true)
		if err != nil {
			t.Fatalf("encoding %#x: %v", encoding, err)
		}
		c, d := f.CIEs[0], f.FDEs[0]
		if c.PersonalityEncoding == nil || *c.PersonalityEncoding != encoding || c.Personality == nil || *c.Personality != sectionAddress+0x3000 {
			t.Fatalf("encoding %#x: wrong personality: %+v", encoding, c)
		}
		if c.LSDAPointerEncoding != encoding || d.LSDAAddress == nil || *d.LSDAAddress != sectionAddress+0x4000 {
			t.Fatalf("encoding %#x: wrong LSDA: %+v", encoding, d)
		}
		if d.InitialLocation != sectionAddress+0x1000 || d.AddressRange != 0x20 {
			t.Fatalf("encoding %#x: wrong FDE range: %+v", encoding, d)
		}

		// Code addresses must be usable for PC lookup without dereferencing.
		data[24] = 0x9b // R encoding follows the personality and L fields.
		if _, err := ParseFrame(data, binary.LittleEndian, 8, sectionAddress, true); err == nil {
			t.Fatal("accepted an unresolved indirect initial location")
		}
	}
}

func TestFrameEHSetLocEncoding(t *testing.T) {
	const sectionAddress = uint64(0x100000000)
	data := append([]byte(nil), ehFrame[:0x14]...)
	body := frameTestU32(nil, uint32(len(data)+4))
	body = frameTestU32(body, 0x1000-uint32(len(data)+8))
	body = frameTestU32(body, 0x20)
	body = append(body, 0, 0x01)
	body = frameTestU32(body, 0x1004-uint32(len(data)+4+len(body)))
	body = append(body, 0x0e, 16)
	data = append(data, frameTestEntry(body)...)
	f, err := ParseFrame(data, binary.LittleEndian, 8, sectionAddress, true)
	if err != nil {
		t.Fatal(err)
	}
	table, err := f.FDEs[0].UnwindTable()
	if err != nil {
		t.Fatal(err)
	}
	r := table.RowForPC(sectionAddress + 0x1004)
	if r == nil || r.PC != sectionAddress+0x1004 || r.CFA.Offset != 16 {
		t.Fatalf("wrong set_loc row: %+v", r)
	}
}

func TestFrameZeroCFA(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cie, fde []byte
		defined  bool
	}{
		{"unspecified", nil, nil, false},
		{"cie", []byte{0x0c, 0, 0}, nil, true},
		{"fde", nil, []byte{0x0c, 0, 0}, true},
		{"restore", []byte{0x0c, 0, 0}, []byte{0x0a, 0x0c, 7, 8, 0x0b}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(frameTestDebugCIE(tc.cie), frameTestDebugFDE(0, tc.fde)...)
			f, err := ParseFrame(data, binary.LittleEndian, 8, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			table, err := f.FDEs[0].UnwindTable()
			if err != nil {
				t.Fatal(err)
			}
			if !tc.defined {
				if len(table.Rows) != 0 {
					t.Fatalf("unexpected rows: %+v", table.Rows)
				}
				return
			}
			r := table.RowForPC(0x1000)
			if len(table.Rows) != 1 || r == nil || !r.CFA.Defined || r.CFA.Reg != 0 || r.CFA.Offset != 0 {
				t.Fatalf("lost CFA r0+0: %+v", table.Rows)
			}
		})
	}
}

func TestFrameForwardCIE(t *testing.T) {
	data := append(frameTestDebugFDE(24, nil), frameTestDebugCIE([]byte{0x0c, 7, 8})...)
	f, err := ParseFrame(data, binary.LittleEndian, 8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 2 || f.Entries[0].Kind != FrameFDE || f.Entries[1].Kind != FrameCIE || f.FDEs[0].CIE != f.CIEs[0] || f.CIEs[0].Offset != 24 {
		t.Fatalf("incorrect entry order or CIE binding: %+v", f)
	}
	table, err := f.FDEs[0].UnwindTable()
	if err != nil {
		t.Fatal(err)
	}
	if r := table.RowForPC(0x1000); r == nil || r.CFA.Reg != 7 || r.CFA.Offset != 8 {
		t.Fatalf("wrong forward-CIE row: %+v", r)
	}
}

func TestFrameForwardDWARF64CIE(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
	}{
		{"little", binary.LittleEndian},
		{"big", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			word := func(dst []byte, n uint64) []byte {
				var b [8]byte
				tc.order.PutUint64(b[:], n)
				return append(dst, b[:]...)
			}
			entry := func(body []byte) []byte {
				for (len(body)+12)%8 != 0 {
					body = append(body, 0)
				}
				header := make([]byte, 12)
				tc.order.PutUint32(header, math.MaxUint32)
				tc.order.PutUint64(header[4:], uint64(len(body)))
				return append(header, body...)
			}
			fde := word(nil, 40)
			fde = word(fde, 0x1000)
			fde = word(fde, 0x20)
			cie := append(word(nil, math.MaxUint64), 4, 0, 8, 0, 1, 0x78, 16, 0x0c, 7, 8)
			f, err := ParseFrame(append(entry(fde), entry(cie)...), tc.order, 8, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.FDEs) != 1 || f.FDEs[0].CIE.Offset != 40 || !f.FDEs[0].IsDWARF64 || !f.CIEs[0].IsDWARF64 {
				t.Fatalf("incorrect DWARF64 binding: %+v", f)
			}
		})
	}
}

func TestFrameArchitectureSelection(t *testing.T) {
	data := append(frameTestDebugCIE([]byte{0x0c, 31, 0, 0x2d}), frameTestDebugFDE(0, []byte{0x44, 0x2d})...)
	f, err := ParseFrame(data, binary.LittleEndian, 8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.FDEs[0].UnwindTable(); err == nil {
		t.Fatal("generic unwinding accepted opcode 0x2d")
	}
	if _, err := f.UnwindTables(); err == nil {
		t.Fatal("generic frame tables accepted opcode 0x2d")
	}
	tables, err := f.UnwindTablesForArch(FrameArchAArch64)
	if err != nil {
		t.Fatal(err)
	}
	table := tables[f.FDEs[0].Offset]
	first, second := table.RowForPC(0x1000), table.RowForPC(0x1004)
	if first == nil || second == nil || !first.RAStateNegated || second.RAStateNegated {
		t.Fatalf("wrong AArch64 return-address state: %+v", table.Rows)
	}
}

func TestFrameRowAddressValidation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		start, align uint64
		cfi          CFI
	}{
		{"backward", 0x1000, 1, CFI{Kind: CFISetLoc, Args: []int64{0x800}}},
		{"equal", 0x1000, 1, CFI{Kind: CFISetLoc, Args: []int64{0x1000}}},
		{"addition", math.MaxUint64 - 1, 1, CFI{Kind: CFIAdvanceLoc, Args: []int64{2}}},
		{"multiplication", 0, math.MaxUint64, CFI{Kind: CFIAdvanceLoc1, Args: []int64{2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fde := &FDE{CIE: &CIE{CodeAlignmentFactor: tc.align}, InitialLocation: tc.start, FrameEntry: FrameEntry{CFIs: []CFI{tc.cfi}}}
			if _, err := fde.UnwindTable(); err == nil {
				t.Fatal("accepted invalid row address")
			}
		})
	}
}
