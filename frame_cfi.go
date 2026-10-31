// This file parses the DWARF Call Frame Information (CFI) of .debug_frame and .eh_frame sections.
// Format: https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Embedded/LSB-Embedded/ehframechpt.html
// Alternative Implementations:
// - https://llvm.org/doxygen/classllvm_1_1DWARFDebugFrame.html
// - https://github.com/eliben/pyelftools/blob/main/elftools/dwarf/callframe.py
//
// The parser does not depend on dwarf.Data; it only reuses the package's
// Offset type.
//
// The CIE/FDE and EH-frame layout follows the DWARF specification and the
// behavior of LLVM's DWARFDebugFrame implementation. In particular:
//
//   - .debug_frame identifies CIEs with DW_CIE_ID / DW64_CIE_ID.
//   - .eh_frame identifies CIEs with CIE id 0 and uses a backward-relative
//     CIE pointer in FDEs.
//   - EH augmentation strings support z, L, P, R, S, B and G.
//   - EH encoded pointers support absolute and PC-relative applications;
//     indirect personality and LSDA pointers retain their slot addresses.
//
// The CFI state machine produces PC-indexed unwind rows. Architecture-specific
// execution requires an explicit supported architecture.

package dwarf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

const (
	frameDWCIEID32 = 0xffffffff
	frameDWCIEID64 = 0xffffffffffffffff

	// Primary DW_CFA opcode classes.
	frameCFAAdvanceLoc = 0x40
	frameCFAOffset     = 0x80
	frameCFARestore    = 0xc0

	// Extended DW_CFA opcodes.
	frameCFANop              = 0x00
	frameCFASetLoc           = 0x01
	frameCFAAdvanceLoc1      = 0x02
	frameCFAAdvanceLoc2      = 0x03
	frameCFAAdvanceLoc4      = 0x04
	frameCFAOffsetExtended   = 0x05
	frameCFARestoreExtended  = 0x06
	frameCFAUndefined        = 0x07
	frameCFASameValue        = 0x08
	frameCFARegister         = 0x09
	frameCFARememberState    = 0x0a
	frameCFARestoreState     = 0x0b
	frameCFADefCFA           = 0x0c
	frameCFADefCFARegister   = 0x0d
	frameCFADefCFAOffset     = 0x0e
	frameCFADefCFAExpression = 0x0f
	frameCFAExpression       = 0x10
	frameCFAOffsetExtendedSF = 0x11
	frameCFADefCFASF         = 0x12
	frameCFADefCFAOffsetSF   = 0x13
	frameCFAValOffset        = 0x14
	frameCFAValOffsetSF      = 0x15
	frameCFAValExpression    = 0x16

	// GCC / architecture extensions.
	frameCFAMIPSAdvanceLoc8      = 0x1d
	frameCFAGNUWindowSave        = 0x2d
	frameCFAGNUArgsSize          = 0x2e
	frameCFAGNUNegativeOffsetExt = 0x2f

	// DW_EH_PE encodings.
	frameEHPAbsptr  = 0x00
	frameEHPULEB128 = 0x01
	frameEHPUData2  = 0x02
	frameEHPUData4  = 0x03
	frameEHPUData8  = 0x04
	frameEHPSLEB128 = 0x09
	frameEHPSData2  = 0x0a
	frameEHPSData4  = 0x0b
	frameEHPSData8  = 0x0c

	frameEHPPCRel    = 0x10
	frameEHPTextRel  = 0x20
	frameEHPDataRel  = 0x30
	frameEHPFuncrel  = 0x40
	frameEHPAligned  = 0x50
	frameEHPIndirect = 0x80
	frameEHPFixed    = 0xff
)

type FrameKind uint8

const (
	FrameCIE FrameKind = iota
	FrameFDE
)

func (k FrameKind) String() string {
	switch k {
	case FrameCIE:
		return "CIE"
	case FrameFDE:
		return "FDE"
	default:
		return "unknown"
	}
}

type CFIKind uint8

const (
	CFINop CFIKind = iota
	CFISetLoc
	CFIAdvanceLoc
	CFIAdvanceLoc1
	CFIAdvanceLoc2
	CFIAdvanceLoc4
	CFIMIPSAdvanceLoc8
	CFIOffset
	CFIOffsetExtended
	CFIOffsetExtendedSF
	CFIRestore
	CFIRestoreExtended
	CFIUndefined
	CFISameValue
	CFIRegister
	CFIRememberState
	CFIRestoreState
	CFIDefCFA
	CFIDefCFASF
	CFIDefCFARegister
	CFIDefCFAOffset
	CFIDefCFAOffsetSF
	CFIDefCFAExpression
	CFIExpression
	CFIValOffset
	CFIValOffsetSF
	CFIValExpression
	CFIGNUWindowSave
	CFIGNUArgsSize
	CFIGNUNegativeOffsetExtended
)

func (k CFIKind) String() string {
	switch k {
	case CFINop:
		return "DW_CFA_nop"
	case CFISetLoc:
		return "DW_CFA_set_loc"
	case CFIAdvanceLoc:
		return "DW_CFA_advance_loc"
	case CFIAdvanceLoc1:
		return "DW_CFA_advance_loc1"
	case CFIAdvanceLoc2:
		return "DW_CFA_advance_loc2"
	case CFIAdvanceLoc4:
		return "DW_CFA_advance_loc4"
	case CFIMIPSAdvanceLoc8:
		return "DW_CFA_MIPS_advance_loc8"
	case CFIOffset:
		return "DW_CFA_offset"
	case CFIOffsetExtended:
		return "DW_CFA_offset_extended"
	case CFIOffsetExtendedSF:
		return "DW_CFA_offset_extended_sf"
	case CFIRestore:
		return "DW_CFA_restore"
	case CFIRestoreExtended:
		return "DW_CFA_restore_extended"
	case CFIUndefined:
		return "DW_CFA_undefined"
	case CFISameValue:
		return "DW_CFA_same_value"
	case CFIRegister:
		return "DW_CFA_register"
	case CFIRememberState:
		return "DW_CFA_remember_state"
	case CFIRestoreState:
		return "DW_CFA_restore_state"
	case CFIDefCFA:
		return "DW_CFA_def_cfa"
	case CFIDefCFASF:
		return "DW_CFA_def_cfa_sf"
	case CFIDefCFARegister:
		return "DW_CFA_def_cfa_register"
	case CFIDefCFAOffset:
		return "DW_CFA_def_cfa_offset"
	case CFIDefCFAOffsetSF:
		return "DW_CFA_def_cfa_offset_sf"
	case CFIDefCFAExpression:
		return "DW_CFA_def_cfa_expression"
	case CFIExpression:
		return "DW_CFA_expression"
	case CFIValOffset:
		return "DW_CFA_val_offset"
	case CFIValOffsetSF:
		return "DW_CFA_val_offset_sf"
	case CFIValExpression:
		return "DW_CFA_val_expression"
	case CFIGNUWindowSave:
		return "DW_CFA_GNU_window_save"
	case CFIGNUArgsSize:
		return "DW_CFA_GNU_args_size"
	case CFIGNUNegativeOffsetExtended:
		return "DW_CFA_GNU_negative_offset_extended"
	default:
		return fmt.Sprintf("DW_CFA_%#02x", uint8(k))
	}
}

type CFI struct {
	Offset Offset
	Raw    byte
	Kind   CFIKind

	// Arguments as decoded from the instruction stream.
	Args []int64

	// Expression operands for DW_CFA_expression,
	// DW_CFA_val_expression and DW_CFA_def_cfa_expression.
	Expression []byte
}

type FrameEntry struct {
	Kind      FrameKind
	Offset    Offset
	Length    uint64
	IsDWARF64 bool
	CFIs      []CFI
}

type CIE struct {
	FrameEntry

	Version               uint8
	Augmentation          string
	AddressSize           uint8
	SegmentDescriptorSize uint8
	CodeAlignmentFactor   uint64
	DataAlignmentFactor   int64
	ReturnAddressRegister uint64

	AugmentationData []byte

	FDEPointerEncoding  uint8
	LSDAPointerEncoding uint8
	PersonalityEncoding *uint8
	// Personality is the decoded pointer address. When PersonalityEncoding
	// has DW_EH_PE_indirect (0x80) set, this is the address of the pointer slot.
	Personality *uint64

	// B is the AArch64 pointer-authentication augmentation.
	HasBKey bool

	// G says the stack frame contains MTE-tagged data.
	HasTaggedData bool

	// S says this is a signal trampoline.
	IsSignalFrame bool
}

type FDE struct {
	FrameEntry

	CIEPointer      uint64
	CIE             *CIE
	InitialLocation uint64
	AddressRange    uint64
	// LSDAAddress is nil for an omitted or encoded-null LSDA. Otherwise it is
	// the decoded pointer address. When CIE.LSDAPointerEncoding has
	// DW_EH_PE_indirect (0x80) set, this is the address of the pointer slot.
	LSDAAddress *uint64
}

type Frame struct {
	Entries []FrameEntry
	CIEs    []*CIE
	FDEs    []*FDE

	// SectionAddress is the VM address of the first byte of the frame section.
	// It is needed for DW_EH_PE_pcrel and related encodings.
	SectionAddress uint64

	// AddressSize is the default address size supplied by the caller.
	AddressSize int

	// EHFrame says this is an .eh_frame section rather than a .debug_frame
	// section.
	EHFrame bool
}

func (f *Frame) FDEForPC(pc uint64) *FDE {
	if len(f.FDEs) == 0 {
		return nil
	}
	i := sort.Search(len(f.FDEs), func(i int) bool {
		return f.FDEs[i].InitialLocation > pc
	})
	if i == 0 {
		return nil
	}
	fde := f.FDEs[i-1]
	if pc >= fde.InitialLocation && pc < fde.InitialLocation+fde.AddressRange {
		return fde
	}
	return nil
}

type RegisterRuleKind uint8

const (
	RuleUndefined RegisterRuleKind = iota
	RuleSameValue
	RuleOffset
	RuleValOffset
	RuleRegister
	RuleExpression
	RuleValExpression
)

func (k RegisterRuleKind) String() string {
	switch k {
	case RuleUndefined:
		return "undefined"
	case RuleSameValue:
		return "same_value"
	case RuleOffset:
		return "offset"
	case RuleValOffset:
		return "val_offset"
	case RuleRegister:
		return "register"
	case RuleExpression:
		return "expression"
	case RuleValExpression:
		return "val_expression"
	default:
		return "unknown"
	}
}

type RegisterRule struct {
	Kind   RegisterRuleKind
	Offset int64
	Reg    uint64
	Expr   []byte
}

type CFARule struct {
	// Defined distinguishes an explicit register-zero-plus-zero rule from an
	// unspecified CFA.
	Defined bool
	Reg     uint64
	Offset  int64
	Expr    []byte
	// Expression is true when Expr, rather than Reg+Offset, defines the CFA.
	Expression bool
}

type UnwindRow struct {
	PC        uint64
	CFA       CFARule
	Registers map[uint64]RegisterRule

	// Register order is useful for dumpers that want deterministic output.
	RegisterOrder []uint64

	// DW_CFA_GNU_args_size.
	ArgsSize uint64

	// AArch64 DW_CFA_AARCH64_negate_ra_state.
	RAStateNegated bool
}

type UnwindTable struct {
	Rows []UnwindRow
}

// FrameArchitecture selects the meaning of architecture-specific CFI opcodes.
type FrameArchitecture uint8

const (
	// FrameArchUnknown permits architecture-independent instructions only.
	FrameArchUnknown FrameArchitecture = iota
	FrameArchAArch64
)

func (t *UnwindTable) RowForPC(pc uint64) *UnwindRow {
	if len(t.Rows) == 0 {
		return nil
	}
	i := sort.Search(len(t.Rows), func(i int) bool {
		return t.Rows[i].PC > pc
	})
	if i == 0 {
		return nil
	}
	return &t.Rows[i-1]
}

type frameReader struct {
	data  []byte
	off   int
	order binary.ByteOrder
}

func newFrameReader(data []byte, order binary.ByteOrder) *frameReader {
	return &frameReader{data: data, order: order}
}

func (r *frameReader) remain() int {
	return len(r.data) - r.off
}

func (r *frameReader) pos() int {
	return r.off
}

func (r *frameReader) setPos(off int) error {
	if off < 0 || off > len(r.data) {
		return io.ErrUnexpectedEOF
	}
	r.off = off
	return nil
}

func (r *frameReader) u8() (uint8, error) {
	if r.off+1 > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.data[r.off]
	r.off++
	return v, nil
}

func (r *frameReader) bytes(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *frameReader) u16() (uint16, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return r.order.Uint16(b), nil
}

func (r *frameReader) u32() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return r.order.Uint32(b), nil
}

func (r *frameReader) u64() (uint64, error) {
	b, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return r.order.Uint64(b), nil
}

func (r *frameReader) addr(size int) (uint64, error) {
	switch size {
	case 1:
		v, err := r.u8()
		return uint64(v), err
	case 2:
		v, err := r.u16()
		return uint64(v), err
	case 4:
		v, err := r.u32()
		return uint64(v), err
	case 8:
		return r.u64()
	default:
		return 0, fmt.Errorf("invalid address size %d", size)
	}
}

func (r *frameReader) uleb() (uint64, error) {
	var v uint64
	var shift uint
	for {
		b, err := r.u8()
		if err != nil {
			return 0, err
		}
		if shift >= 64 && b&0x7f != 0 {
			return 0, errors.New("ULEB128 overflow")
		}
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}

func (r *frameReader) sleb() (int64, error) {
	var v int64
	var shift uint
	var b byte
	for {
		x, err := r.u8()
		if err != nil {
			return 0, err
		}
		b = x
		if shift >= 64 {
			return 0, errors.New("SLEB128 overflow")
		}
		v |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		v |= -1 << shift
	}
	return v, nil
}

func (r *frameReader) cstring() (string, error) {
	start := r.off
	for r.off < len(r.data) && r.data[r.off] != 0 {
		r.off++
	}
	if r.off >= len(r.data) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.data[start:r.off])
	r.off++
	return s, nil
}

type frameEntryHeader struct {
	start     int
	length    uint64
	isDWARF64 bool
	id        uint64
	bodyStart int
	dataStart int
	end       int
}

func readFrameHeader(r *frameReader, eh bool) (frameEntryHeader, error) {
	start := r.pos()

	v, err := r.u32()
	if err != nil {
		return frameEntryHeader{}, err
	}

	h := frameEntryHeader{start: start}

	switch v {
	case 0:
		// A zero-length entry has no ID; .eh_frame uses it as a terminator.
		h.bodyStart = r.pos()
		h.end = h.bodyStart
		return h, nil
	case 0xffffffff:
		h.isDWARF64 = true
		h.length, err = r.u64()
		if err != nil {
			return frameEntryHeader{}, err
		}
	default:
		if v >= 0xfffffff0 {
			return frameEntryHeader{}, fmt.Errorf("reserved DWARF initial length %#x at %#x", v, start)
		}
		h.length = uint64(v)
	}

	h.bodyStart = r.pos()
	if h.length > uint64(len(r.data)-h.bodyStart) {
		return frameEntryHeader{}, fmt.Errorf("frame entry at %#x extends past section", start)
	}

	h.end = h.bodyStart + int(h.length)

	// EH-frame FDE/CIE ids are always 4 bytes, even in a DWARF64 entry.
	// DWARF .debug_frame uses an 8-byte ID for DWARF64.
	idSize := 4
	if !eh && h.isDWARF64 {
		idSize = 8
	}
	if h.length < uint64(idSize) {
		return frameEntryHeader{}, fmt.Errorf("frame entry at %#x is shorter than its ID", start)
	}

	idBytes, err := r.bytes(idSize)
	if err != nil {
		return frameEntryHeader{}, err
	}
	if idSize == 4 {
		h.id = uint64(r.order.Uint32(idBytes))
	} else {
		h.id = r.order.Uint64(idBytes)
	}
	h.dataStart = r.pos()
	return h, nil
}

func getFrameCIEID(isDWARF64, eh bool) uint64 {
	if eh {
		return 0
	}
	if isDWARF64 {
		return frameDWCIEID64
	}
	return frameDWCIEID32
}

// ParseFrame parses a DWARF .debug_frame or .eh_frame section without using
// dwarf.Data.
//
// data is the complete frame section.
// order is the section's byte order.
// addressSize is the containing object's address size (4 or 8).
// sectionAddress is the VM address of data[0] and is used for PC-relative
// EH encodings.
// ehFrame selects .eh_frame semantics.
func ParseFrame(data []byte, order binary.ByteOrder, addressSize int, sectionAddress uint64, ehFrame bool) (*Frame, error) {
	if addressSize != 4 && addressSize != 8 {
		return nil, fmt.Errorf("unsupported address size %d", addressSize)
	}

	f := &Frame{
		SectionAddress: sectionAddress,
		AddressSize:    addressSize,
		EHFrame:        ehFrame,
	}

	r := newFrameReader(data, order)

	cieByOffset := make(map[int]*CIE)
	var headers []frameEntryHeader

	// Index every CIE before decoding FDEs: .debug_frame references are section
	// offsets and may point forward. Keep the headers to preserve entry order.
	for r.remain() > 0 {
		start := r.pos()
		h, err := readFrameHeader(r, ehFrame)
		if err != nil {
			return nil, fmt.Errorf("frame entry at %#x: %w", start, err)
		}

		// LLVM treats a zero-length .eh_frame record as a terminator.
		if h.length == 0 {
			if ehFrame {
				break
			}
			return nil, fmt.Errorf("zero-length .debug_frame entry at %#x", h.start)
		}
		headers = append(headers, h)

		if h.id == getFrameCIEID(h.isDWARF64, ehFrame) {
			entry := &frameReader{data: data[:h.end], off: h.dataStart, order: order}
			cie, err := parseCIE(entry, h, f)
			if err != nil {
				return nil, err
			}
			cieByOffset[h.start] = cie
			f.CIEs = append(f.CIEs, cie)
		}
		if err := r.setPos(h.end); err != nil {
			return nil, err
		}
	}

	for _, h := range headers {
		if cie := cieByOffset[h.start]; cie != nil {
			f.Entries = append(f.Entries, cie.FrameEntry)
			continue
		}
		entry := &frameReader{data: data[:h.end], off: h.dataStart, order: order}
		fde, err := parseFDE(entry, h, f, cieByOffset)
		if err != nil {
			return nil, err
		}
		f.FDEs = append(f.FDEs, fde)
		f.Entries = append(f.Entries, fde.FrameEntry)
	}

	sort.Slice(f.FDEs, func(i, j int) bool {
		return f.FDEs[i].InitialLocation < f.FDEs[j].InitialLocation
	})

	return f, nil
}

func parseCIE(r *frameReader, h frameEntryHeader, f *Frame) (*CIE, error) {
	version, err := r.u8()
	if err != nil {
		return nil, fmt.Errorf("CIE %#x: %w", h.start, err)
	}
	augmentation, err := r.cstring()
	if err != nil {
		return nil, fmt.Errorf("CIE %#x augmentation: %w", h.start, err)
	}

	addressSize := uint8(f.AddressSize)
	segmentSize := uint8(0)
	if version >= 4 {
		v, err := r.u8()
		if err != nil {
			return nil, fmt.Errorf("CIE %#x address size: %w", h.start, err)
		}
		addressSize = v
		v, err = r.u8()
		if err != nil {
			return nil, fmt.Errorf("CIE %#x segment descriptor size: %w", h.start, err)
		}
		segmentSize = v
	}

	codeAlign, err := r.uleb()
	if err != nil {
		return nil, fmt.Errorf("CIE %#x code alignment: %w", h.start, err)
	}
	dataAlign, err := r.sleb()
	if err != nil {
		return nil, fmt.Errorf("CIE %#x data alignment: %w", h.start, err)
	}

	var raReg uint64
	if version == 1 {
		v, err := r.u8()
		if err != nil {
			return nil, fmt.Errorf("CIE %#x return register: %w", h.start, err)
		}
		raReg = uint64(v)
	} else {
		raReg, err = r.uleb()
		if err != nil {
			return nil, fmt.Errorf("CIE %#x return register: %w", h.start, err)
		}
	}

	cie := &CIE{
		FrameEntry: FrameEntry{
			Kind:      FrameCIE,
			Offset:    Offset(h.start),
			Length:    h.length,
			IsDWARF64: h.isDWARF64,
			CFIs:      nil,
		},
		Version:               version,
		Augmentation:          augmentation,
		AddressSize:           addressSize,
		SegmentDescriptorSize: segmentSize,
		CodeAlignmentFactor:   codeAlign,
		DataAlignmentFactor:   dataAlign,
		ReturnAddressRegister: raReg,
		FDEPointerEncoding:    frameEHPAbsptr,
		LSDAPointerEncoding:   frameEHPFixed,
	}

	if f.EHFrame {
		if err := parseEHCAugmentation(r, f, h.start, cie); err != nil {
			return nil, err
		}
	}

	cie.FrameEntry.CFIs, err = parseCFI(r, h.end, cie, f)
	if err != nil {
		return nil, fmt.Errorf("CIE %#x CFI: %w", h.start, err)
	}

	return cie, nil
}

func parseEHCAugmentation(r *frameReader, f *Frame, entryStart int, cie *CIE) error {
	if cie.Augmentation == "" {
		return nil
	}

	if cie.Augmentation[0] != 'z' {
		return fmt.Errorf("CIE %#x: unsupported EH augmentation %q (z must be first)", entryStart, cie.Augmentation)
	}

	augLen, err := r.uleb()
	if err != nil {
		return fmt.Errorf("CIE %#x augmentation length: %w", entryStart, err)
	}

	augStart := r.pos()
	if augLen > uint64(r.remain()) {
		return fmt.Errorf("CIE %#x augmentation extends past entry", entryStart)
	}
	augEnd := augStart + int(augLen)

	for i := 0; i < len(cie.Augmentation); i++ {
		switch cie.Augmentation[i] {
		case 'z':
			if i != 0 {
				return fmt.Errorf("CIE %#x: z must be first in augmentation", entryStart)
			}
		case 'L':
			v, err := r.u8()
			if err != nil {
				return fmt.Errorf("CIE %#x: L augmentation: %w", entryStart, err)
			}
			cie.LSDAPointerEncoding = v
		case 'P':
			if cie.PersonalityEncoding != nil {
				return fmt.Errorf("CIE %#x: duplicate P augmentation", entryStart)
			}
			enc, err := r.u8()
			if err != nil {
				return fmt.Errorf("CIE %#x: personality encoding: %w", entryStart, err)
			}
			cie.PersonalityEncoding = &enc

			value, err := r.encodedPointerAddress(enc, f.SectionAddress+uint64(r.pos()), cie.AddressSize)
			if err != nil {
				return fmt.Errorf("CIE %#x: personality pointer: %w", entryStart, err)
			}
			cie.Personality = &value
		case 'R':
			v, err := r.u8()
			if err != nil {
				return fmt.Errorf("CIE %#x: R augmentation: %w", entryStart, err)
			}
			cie.FDEPointerEncoding = v
		case 'S':
			cie.IsSignalFrame = true
		case 'B':
			cie.HasBKey = true
		case 'G':
			cie.HasTaggedData = true
		default:
			return fmt.Errorf("CIE %#x: unknown EH augmentation character %q", entryStart, cie.Augmentation[i])
		}
	}

	if r.pos() != augEnd {
		return fmt.Errorf("CIE %#x: augmentation consumed %d bytes, expected %d", entryStart, r.pos()-augStart, augLen)
	}

	cie.AugmentationData = append([]byte(nil), r.data[augStart:augEnd]...)
	return nil
}

func parseFDE(r *frameReader, h frameEntryHeader, f *Frame, cieByOffset map[int]*CIE) (*FDE, error) {
	var cieOffset int
	if f.EHFrame {
		// The .eh_frame CIE pointer is relative to the CIE pointer field itself.
		if h.id > uint64(h.bodyStart) {
			return nil, fmt.Errorf("FDE %#x: CIE pointer precedes section", h.start)
		}
		cieOffset = h.bodyStart - int(h.id)
	} else {
		if h.id > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("FDE %#x: CIE pointer too large", h.start)
		}
		cieOffset = int(h.id)
	}

	cie := cieByOffset[cieOffset]
	if cie == nil {
		return nil, fmt.Errorf("FDE %#x: missing CIE at %#x", h.start, cieOffset)
	}

	initialFieldOffset := r.pos()
	initial, err := r.encodedPointer(cie.FDEPointerEncoding, f.SectionAddress+uint64(initialFieldOffset), cie.AddressSize)
	if err != nil {
		return nil, fmt.Errorf("FDE %#x initial location: %w", h.start, err)
	}

	// DW_EH_PE application modifiers are applied to the encoded initial
	// location. The address range uses the same low-nibble format but has no
	// relative application modifier, matching LLVM.
	rangeEncoding := cie.FDEPointerEncoding & 0x0f
	rng, err := r.encodedPointer(rangeEncoding, 0, cie.AddressSize)
	if err != nil {
		return nil, fmt.Errorf("FDE %#x address range: %w", h.start, err)
	}

	var lsda *uint64
	if f.EHFrame && cie.Augmentation != "" {
		augLen, err := r.uleb()
		if err != nil {
			return nil, fmt.Errorf("FDE %#x augmentation length: %w", h.start, err)
		}
		augStart := r.pos()
		if augLen > uint64(r.remain()) {
			return nil, fmt.Errorf("FDE %#x augmentation extends past entry", h.start)
		}
		augEnd := augStart + int(augLen)

		if cie.LSDAPointerEncoding != frameEHPFixed {
			base := f.SectionAddress + uint64(r.pos())
			raw, err := r.encodedPointerRaw(cie.LSDAPointerEncoding&0x0f, cie.AddressSize)
			if err != nil {
				return nil, fmt.Errorf("FDE %#x LSDA: %w", h.start, err)
			}
			// A raw zero means that this FDE has no LSDA, even when its CIE
			// advertises a relative or indirect LSDA encoding.
			if raw != 0 {
				value, err := framePointerAddress(raw, cie.LSDAPointerEncoding, base)
				if err != nil {
					return nil, fmt.Errorf("FDE %#x LSDA: %w", h.start, err)
				}
				lsda = &value
			}
		}

		if r.pos() != augEnd {
			return nil, fmt.Errorf("FDE %#x augmentation consumed %d bytes, expected %d", h.start, r.pos()-augStart, augLen)
		}
	}

	fde := &FDE{
		FrameEntry: FrameEntry{
			Kind:      FrameFDE,
			Offset:    Offset(h.start),
			Length:    h.length,
			IsDWARF64: h.isDWARF64,
		},
		CIEPointer:      h.id,
		CIE:             cie,
		InitialLocation: initial,
		AddressRange:    rng,
		LSDAAddress:     lsda,
	}

	cfis, err := parseCFI(r, h.end, cie, f)
	if err != nil {
		return nil, fmt.Errorf("FDE %#x CFI: %w", h.start, err)
	}
	fde.FrameEntry.CFIs = cfis
	return fde, nil
}

func (r *frameReader) encodedPointer(enc uint8, base uint64, addressSize uint8) (uint64, error) {
	if enc != frameEHPFixed && enc&frameEHPIndirect != 0 {
		return 0, errors.New("DW_EH_PE_indirect is not supported without a memory reader")
	}
	return r.encodedPointerAddress(enc, base, addressSize)
}

// encodedPointerAddress resolves the application bits while retaining the
// address of an indirect pointer slot. The caller keeps the encoding with it.
func (r *frameReader) encodedPointerAddress(enc uint8, base uint64, addressSize uint8) (uint64, error) {
	if enc == frameEHPFixed {
		return 0, errors.New("DW_EH_PE_omit")
	}

	raw, err := r.encodedPointerRaw(enc&0x0f, addressSize)
	if err != nil {
		return 0, err
	}
	return framePointerAddress(raw, enc, base)
}

// framePointerAddress applies the relative-address modifier to a value that
// has already been decoded. It leaves indirect pointers at their slot address.
func framePointerAddress(raw uint64, enc uint8, base uint64) (uint64, error) {
	app := enc & 0x70
	switch app {
	case frameEHPAbsptr:
		// raw as-is
	case frameEHPPCRel:
		raw = uint64(int64(raw) + int64(base))
	case frameEHPTextRel:
		return 0, errors.New("DW_EH_PE_textrel requires a text base")
	case frameEHPDataRel:
		return 0, errors.New("DW_EH_PE_datarel requires a data base")
	case frameEHPFuncrel:
		return 0, errors.New("DW_EH_PE_funcrel requires a function base")
	case frameEHPAligned:
		return 0, errors.New("DW_EH_PE_aligned is not supported in encoded pointer fields")
	default:
		return 0, fmt.Errorf("unsupported DW_EH_PE application %#x", app)
	}

	return raw, nil
}

func (r *frameReader) encodedPointerRaw(format uint8, addressSize uint8) (uint64, error) {
	switch format {
	case frameEHPAbsptr:
		return r.addr(int(addressSize))
	case frameEHPULEB128:
		return r.uleb()
	case frameEHPUData2:
		v, err := r.u16()
		return uint64(v), err
	case frameEHPUData4:
		v, err := r.u32()
		return uint64(v), err
	case frameEHPUData8:
		return r.u64()
	case frameEHPSLEB128:
		v, err := r.sleb()
		return uint64(v), err
	case frameEHPSData2:
		v, err := r.u16()
		return uint64(int64(int16(v))), err
	case frameEHPSData4:
		v, err := r.u32()
		return uint64(int64(int32(v))), err
	case frameEHPSData8:
		v, err := r.u64()
		return uint64(int64(v)), err
	default:
		return 0, fmt.Errorf("unsupported DW_EH_PE format %#x", format)
	}
}

func parseCFI(r *frameReader, end int, cie *CIE, f *Frame) ([]CFI, error) {
	if r.pos() > end || end > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}

	var out []CFI
	for r.pos() < end {
		off := Offset(r.pos())
		raw, err := r.u8()
		if err != nil {
			return nil, err
		}

		inst := CFI{
			Offset: off,
			Raw:    raw,
		}

		switch raw & 0xc0 {
		case frameCFAAdvanceLoc:
			inst.Kind = CFIAdvanceLoc
			inst.Args = []int64{int64(raw & 0x3f)}

		case frameCFAOffset:
			inst.Kind = CFIOffset
			reg := uint64(raw & 0x3f)
			v, err := r.uleb()
			if err != nil {
				return nil, err
			}
			inst.Args = []int64{int64(reg), int64(v)}

		case frameCFARestore:
			inst.Kind = CFIRestore
			inst.Args = []int64{int64(raw & 0x3f)}

		default:
			switch raw {
			case frameCFANop:
				inst.Kind = CFINop

			case frameCFASetLoc:
				inst.Kind = CFISetLoc
				encoding := uint8(frameEHPAbsptr)
				if f.EHFrame {
					encoding = cie.FDEPointerEncoding
				}
				v, err := r.encodedPointer(encoding, f.SectionAddress+uint64(r.pos()), cie.AddressSize)
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAAdvanceLoc1:
				inst.Kind = CFIAdvanceLoc1
				v, err := r.u8()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAAdvanceLoc2:
				inst.Kind = CFIAdvanceLoc2
				v, err := r.u16()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAAdvanceLoc4:
				inst.Kind = CFIAdvanceLoc4
				v, err := r.u32()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAMIPSAdvanceLoc8:
				inst.Kind = CFIMIPSAdvanceLoc8
				v, err := r.u64()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAOffsetExtended:
				inst.Kind = CFIOffsetExtended
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				v, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), int64(v)}

			case frameCFARestoreExtended:
				inst.Kind = CFIRestoreExtended
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}

			case frameCFAUndefined:
				inst.Kind = CFIUndefined
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}

			case frameCFASameValue:
				inst.Kind = CFISameValue
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}

			case frameCFARegister:
				inst.Kind = CFIRegister
				r1, err := r.uleb()
				if err != nil {
					return nil, err
				}
				r2, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(r1), int64(r2)}

			case frameCFARememberState:
				inst.Kind = CFIRememberState

			case frameCFARestoreState:
				inst.Kind = CFIRestoreState

			case frameCFADefCFA:
				inst.Kind = CFIDefCFA
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				off, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), int64(off)}

			case frameCFADefCFARegister:
				inst.Kind = CFIDefCFARegister
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}

			case frameCFADefCFAOffset:
				inst.Kind = CFIDefCFAOffset
				off, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(off)}

			case frameCFADefCFAExpression:
				inst.Kind = CFIDefCFAExpression
				expr, err := readBlock(r)
				if err != nil {
					return nil, err
				}
				inst.Expression = expr

			case frameCFAExpression:
				inst.Kind = CFIExpression
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				expr, err := readBlock(r)
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}
				inst.Expression = expr

			case frameCFAOffsetExtendedSF:
				inst.Kind = CFIOffsetExtendedSF
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				off, err := r.sleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), off}

			case frameCFADefCFASF:
				inst.Kind = CFIDefCFASF
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				off, err := r.sleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), off}

			case frameCFADefCFAOffsetSF:
				inst.Kind = CFIDefCFAOffsetSF
				off, err := r.sleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{off}

			case frameCFAValOffset:
				inst.Kind = CFIValOffset
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				off, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), int64(off)}

			case frameCFAValOffsetSF:
				inst.Kind = CFIValOffsetSF
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				off, err := r.sleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), off}

			case frameCFAValExpression:
				inst.Kind = CFIValExpression
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				expr, err := readBlock(r)
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg)}
				inst.Expression = expr

			case frameCFAGNUWindowSave:
				// Also DW_CFA_AARCH64_negate_ra_state on AArch64.
				inst.Kind = CFIGNUWindowSave

			case frameCFAGNUArgsSize:
				inst.Kind = CFIGNUArgsSize
				v, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(v)}

			case frameCFAGNUNegativeOffsetExt:
				inst.Kind = CFIGNUNegativeOffsetExtended
				reg, err := r.uleb()
				if err != nil {
					return nil, err
				}
				v, err := r.uleb()
				if err != nil {
					return nil, err
				}
				inst.Args = []int64{int64(reg), int64(v)}

			default:
				return nil, fmt.Errorf("unknown CFI opcode %#02x at %#x", raw, off)
			}
		}

		out = append(out, inst)
	}

	if r.pos() != end {
		return nil, fmt.Errorf("CFI parser stopped at %#x, expected %#x", r.pos(), end)
	}
	return out, nil
}

func readBlock(r *frameReader) ([]byte, error) {
	n, err := r.uleb()
	if err != nil {
		return nil, err
	}
	if n > uint64(r.remain()) {
		return nil, io.ErrUnexpectedEOF
	}
	return r.bytes(int(n))
}

// UnwindTable executes architecture-independent call frame instructions.
// Use UnwindTableForArch for architecture-specific instructions.
func (fde *FDE) UnwindTable() (*UnwindTable, error) {
	return fde.UnwindTableForArch(FrameArchUnknown)
}

// UnwindTableForArch executes call frame instructions for the selected
// architecture. Currently only the AArch64 interpretation of opcode 0x2d is
// supported; generic execution rejects that ambiguous opcode.
func (fde *FDE) UnwindTableForArch(arch FrameArchitecture) (*UnwindTable, error) {
	if fde == nil || fde.CIE == nil {
		return nil, errors.New("FDE has no CIE")
	}

	cieRows, err := executeCFI(
		fde.CIE.CFIs,
		fde.CIE,
		nil,
		fde.InitialLocation,
		true,
		arch,
	)
	if err != nil {
		return nil, err
	}

	var initial *UnwindRow
	if len(cieRows.Rows) != 0 {
		initial = &cieRows.Rows[len(cieRows.Rows)-1]
	}
	if initial == nil {
		initial = &UnwindRow{
			PC:        fde.InitialLocation,
			CFA:       CFARule{},
			Registers: make(map[uint64]RegisterRule),
		}
	} else {
		row := cloneUnwindRow(*initial)
		row.PC = fde.InitialLocation
		initial = &row
	}

	table, err := executeCFI(
		fde.CFIs,
		fde.CIE,
		initial,
		fde.InitialLocation,
		false,
		arch,
	)
	if err != nil {
		return nil, err
	}

	return table, nil
}

func (f *Frame) UnwindTables() (map[Offset]*UnwindTable, error) {
	return f.UnwindTablesForArch(FrameArchUnknown)
}

// UnwindTablesForArch builds all unwind tables using the selected architecture.
func (f *Frame) UnwindTablesForArch(arch FrameArchitecture) (map[Offset]*UnwindTable, error) {
	out := make(map[Offset]*UnwindTable, len(f.FDEs)+len(f.CIEs))
	for _, cie := range f.CIEs {
		t, err := executeCFI(cie.CFIs, cie, nil, 0, true, arch)
		if err != nil {
			return nil, fmt.Errorf("CIE %#x: %w", cie.Offset, err)
		}
		out[cie.Offset] = t
	}
	for _, fde := range f.FDEs {
		t, err := fde.UnwindTableForArch(arch)
		if err != nil {
			return nil, fmt.Errorf("FDE %#x: %w", fde.Offset, err)
		}
		out[fde.Offset] = t
	}
	return out, nil
}

func cloneUnwindRow(row UnwindRow) UnwindRow {
	cp := row
	cp.Registers = make(map[uint64]RegisterRule, len(row.Registers))
	for k, v := range row.Registers {
		if v.Expr != nil {
			v.Expr = append([]byte(nil), v.Expr...)
		}
		cp.Registers[k] = v
	}
	cp.RegisterOrder = append([]uint64(nil), row.RegisterOrder...)
	cp.CFA.Expr = append([]byte(nil), row.CFA.Expr...)
	return cp
}

func executeCFI(cfis []CFI, cie *CIE, initial *UnwindRow, startPC uint64, isCIE bool, arch FrameArchitecture) (*UnwindTable, error) {
	if arch != FrameArchUnknown && arch != FrameArchAArch64 {
		return nil, fmt.Errorf("unsupported frame architecture %d", arch)
	}
	row := UnwindRow{
		PC:        startPC,
		Registers: make(map[uint64]RegisterRule),
	}
	if initial != nil {
		row = cloneUnwindRow(*initial)
	}

	var initialRegisters map[uint64]RegisterRule
	if initial != nil {
		initialRegisters = cloneRules(initial.Registers)
	}

	addReg := func(reg uint64) {
		for _, x := range row.RegisterOrder {
			if x == reg {
				return
			}
		}
		row.RegisterOrder = append(row.RegisterOrder, reg)
	}

	var stack []UnwindRow
	table := make([]UnwindRow, 0, len(cfis)+1)

	appendRow := func() {
		table = append(table, cloneUnwindRow(row))
	}

	var codeAlign = cie.CodeAlignmentFactor
	var dataAlign = cie.DataAlignmentFactor

	for _, ins := range cfis {
		switch ins.Kind {
		case CFINop:
		case CFISetLoc:
			nextPC := uint64(ins.Args[0])
			if nextPC <= row.PC {
				return nil, fmt.Errorf("DW_CFA_set_loc address %#x must be greater than %#x", nextPC, row.PC)
			}
			appendRow()
			row.PC = nextPC

		case CFIAdvanceLoc, CFIAdvanceLoc1, CFIAdvanceLoc2, CFIAdvanceLoc4, CFIMIPSAdvanceLoc8:
			delta := uint64(ins.Args[0])
			if codeAlign != 0 && delta > (math.MaxUint64-row.PC)/codeAlign {
				return nil, fmt.Errorf("%s at %#x overflows the row address", ins.Kind, ins.Offset)
			}
			appendRow()
			row.PC += delta * codeAlign

		case CFIDefCFA:
			row.CFA = CFARule{Defined: true, Reg: uint64(ins.Args[0]), Offset: ins.Args[1]}

		case CFIDefCFASF:
			row.CFA = CFARule{Defined: true, Reg: uint64(ins.Args[0]), Offset: ins.Args[1] * dataAlign}

		case CFIDefCFARegister:
			row.CFA.Defined = true
			row.CFA.Reg = uint64(ins.Args[0])
			row.CFA.Expression = false

		case CFIDefCFAOffset:
			row.CFA.Defined = true
			row.CFA.Offset = ins.Args[0]
			row.CFA.Expression = false

		case CFIDefCFAOffsetSF:
			row.CFA.Defined = true
			row.CFA.Offset = ins.Args[0] * dataAlign
			row.CFA.Expression = false

		case CFIDefCFAExpression:
			row.CFA = CFARule{
				Defined:    true,
				Expr:       append([]byte(nil), ins.Expression...),
				Expression: true,
			}

		case CFIOffset, CFIOffsetExtended, CFIOffsetExtendedSF:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{
				Kind:   RuleOffset,
				Offset: ins.Args[1] * dataAlign,
			}

		case CFIValOffset, CFIValOffsetSF:
			reg := uint64(ins.Args[0])
			addReg(reg)
			off := ins.Args[1] * dataAlign
			row.Registers[reg] = RegisterRule{
				Kind:   RuleValOffset,
				Offset: off,
			}

		case CFIRegister:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{
				Kind: RuleRegister,
				Reg:  uint64(ins.Args[1]),
			}

		case CFIExpression:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{
				Kind: RuleExpression,
				Expr: append([]byte(nil), ins.Expression...),
			}

		case CFIValExpression:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{
				Kind: RuleValExpression,
				Expr: append([]byte(nil), ins.Expression...),
			}

		case CFIUndefined:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{Kind: RuleUndefined}

		case CFISameValue:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{Kind: RuleSameValue}

		case CFIRestore, CFIRestoreExtended:
			if isCIE {
				return nil, fmt.Errorf("%s is not valid in a CIE", ins.Kind)
			}
			reg := uint64(ins.Args[0])
			addReg(reg)
			if initialRegisters != nil {
				if rule, ok := initialRegisters[reg]; ok {
					row.Registers[reg] = rule
				} else {
					delete(row.Registers, reg)
				}
			}

		case CFIRememberState:
			stack = append(stack, cloneUnwindRow(row))

		case CFIRestoreState:
			if len(stack) == 0 {
				return nil, errors.New("DW_CFA_restore_state with empty state stack")
			}
			pc := row.PC
			row = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			row.PC = pc

		case CFIGNUArgsSize:
			row.ArgsSize = uint64(ins.Args[0])

		case CFIGNUNegativeOffsetExtended:
			reg := uint64(ins.Args[0])
			addReg(reg)
			row.Registers[reg] = RegisterRule{
				Kind:   RuleOffset,
				Offset: -int64(ins.Args[1]) * dataAlign,
			}

		case CFIGNUWindowSave:
			if arch != FrameArchAArch64 {
				return nil, errors.New("CFI opcode 0x2d requires an explicit supported architecture")
			}
			row.RAStateNegated = !row.RAStateNegated

		default:
			return nil, fmt.Errorf("unsupported CFI instruction %s", ins.Kind)
		}
	}

	// Once a row has been emitted, its successor must be kept even if all
	// rules or extension state were cleared. Otherwise lookup returns stale state.
	if len(table) != 0 || row.CFA.Defined || len(row.Registers) != 0 || row.RAStateNegated || row.ArgsSize != 0 {
		table = append(table, cloneUnwindRow(row))
	}

	return &UnwindTable{Rows: table}, nil
}

func cloneRules(in map[uint64]RegisterRule) map[uint64]RegisterRule {
	out := make(map[uint64]RegisterRule, len(in))
	for k, v := range in {
		if v.Expr != nil {
			v.Expr = append([]byte(nil), v.Expr...)
		}
		out[k] = v
	}
	return out
}

func (f *FDE) String() string {
	if f == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"FDE %#x %#x cie=%#x pc=%#x...%#x",
		f.Offset,
		f.Length,
		f.CIEPointer,
		f.InitialLocation,
		f.InitialLocation+f.AddressRange,
	)
}

func (c *CIE) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf(
		"CIE %#x %#x version=%d augmentation=%q code_align=%d data_align=%d ra=%d",
		c.Offset,
		c.Length,
		c.Version,
		c.Augmentation,
		c.CodeAlignmentFactor,
		c.DataAlignmentFactor,
		c.ReturnAddressRegister,
	)
}

func (i CFI) String() string {
	if len(i.Args) == 0 && len(i.Expression) == 0 {
		return i.Kind.String()
	}
	if len(i.Expression) != 0 {
		return fmt.Sprintf("%s args=%v expr=%x", i.Kind, i.Args, i.Expression)
	}
	return fmt.Sprintf("%s args=%v", i.Kind, i.Args)
}

func (f *Frame) String() string {
	return fmt.Sprintf("Frame{eh=%v address=%#x entries=%d}", f.EHFrame, f.SectionAddress, len(f.Entries))
}
