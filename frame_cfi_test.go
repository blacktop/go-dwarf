package dwarf

import (
	"encoding/binary"
	"testing"
)

// ehFrame is a minimal arm64 .eh_frame: a CIE, one FDE and a zero terminator.
var ehFrame = []byte{
	// CIE at 0x0: length, CIE id 0, version 1, "zR", code align 1,
	// data align -8, return address x30, augmentation data: pcrel|sdata4.
	0x10, 0, 0, 0, 0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 30, 1, 0x1b,
	// DW_CFA_def_cfa sp+0, DW_CFA_nop
	0x0c, 31, 0,
	// FDE at 0x14: length, CIE pointer (0x18 - 0x18 = CIE at 0x0),
	// initial location (pcrel to 0x1c: 0x1000 - 0x1c), address range 0x20,
	// augmentation length 0.
	0x18, 0, 0, 0, 0x18, 0, 0, 0, 0xe4, 0x0f, 0, 0, 0x20, 0, 0, 0, 0,
	// DW_CFA_advance_loc 4, DW_CFA_def_cfa x29+16, DW_CFA_offset x30 cfa-8,
	// DW_CFA_nop padding
	0x44, 0x0c, 29, 16, 0x9e, 1, 0, 0, 0, 0, 0,
	// terminator
	0, 0, 0, 0,
}

func TestParseEHFrame(t *testing.T) {
	f, err := ParseFrame(ehFrame, binary.LittleEndian, 8, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.CIEs) != 1 || len(f.FDEs) != 1 {
		t.Fatalf("got %d CIEs and %d FDEs, want 1 and 1", len(f.CIEs), len(f.FDEs))
	}

	fde := f.FDEs[0]
	if fde.Offset != 0x14 || fde.CIE.Offset != 0 {
		t.Errorf("FDE at %#x with CIE at %#x, want 0x14 and 0", fde.Offset, fde.CIE.Offset)
	}
	if fde.InitialLocation != 0x1000 || fde.AddressRange != 0x20 {
		t.Errorf("FDE covers %#x+%#x, want 0x1000+0x20", fde.InitialLocation, fde.AddressRange)
	}
	if f.FDEForPC(0x1010) != fde || f.FDEForPC(0x1020) != nil {
		t.Error("FDEForPC does not respect the FDE's address range")
	}

	table, err := fde.UnwindTable()
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 2 {
		t.Fatalf("got %d unwind rows, want 2", len(table.Rows))
	}
	if r := table.Rows[0]; r.PC != 0x1000 || r.CFA.Reg != 31 || r.CFA.Offset != 0 {
		t.Errorf("row 0: pc=%#x cfa=r%d%+d, want pc=0x1000 cfa=r31+0", r.PC, r.CFA.Reg, r.CFA.Offset)
	}
	r := table.RowForPC(0x1008)
	if r == nil || r.PC != 0x1004 || r.CFA.Reg != 29 || r.CFA.Offset != 16 {
		t.Fatalf("row for 0x1008: %+v, want pc=0x1004 cfa=r29+16", r)
	}
	if rule := r.Registers[30]; rule.Kind != RuleOffset || rule.Offset != -8 {
		t.Errorf("x30 rule: %s%+d, want offset-8", rule.Kind, rule.Offset)
	}
}

func TestParseFrameTruncated(t *testing.T) {
	if _, err := ParseFrame(ehFrame[:0x14+2], binary.LittleEndian, 8, 0, true); err == nil {
		t.Error("expected an error for a truncated entry header")
	}
}
