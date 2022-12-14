// Code generated by "stringer -type format -trimprefix=form"; DO NOT EDIT.

package dwarf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[formAddr-1]
	_ = x[formDwarfBlock2-3]
	_ = x[formDwarfBlock4-4]
	_ = x[formData2-5]
	_ = x[formData4-6]
	_ = x[formData8-7]
	_ = x[formString-8]
	_ = x[formDwarfBlock-9]
	_ = x[formDwarfBlock1-10]
	_ = x[formData1-11]
	_ = x[formFlag-12]
	_ = x[formSdata-13]
	_ = x[formStrp-14]
	_ = x[formUdata-15]
	_ = x[formRefAddr-16]
	_ = x[formRef1-17]
	_ = x[formRef2-18]
	_ = x[formRef4-19]
	_ = x[formRef8-20]
	_ = x[formRefUdata-21]
	_ = x[formIndirect-22]
	_ = x[formSecOffset-23]
	_ = x[formExprloc-24]
	_ = x[formFlagPresent-25]
	_ = x[formRefSig8-32]
	_ = x[formStrx-26]
	_ = x[formAddrx-27]
	_ = x[formRefSup4-28]
	_ = x[formStrpSup-29]
	_ = x[formData16-30]
	_ = x[formLineStrp-31]
	_ = x[formImplicitConst-33]
	_ = x[formLoclistx-34]
	_ = x[formRnglistx-35]
	_ = x[formRefSup8-36]
	_ = x[formStrx1-37]
	_ = x[formStrx2-38]
	_ = x[formStrx3-39]
	_ = x[formStrx4-40]
	_ = x[formAddrx1-41]
	_ = x[formAddrx2-42]
	_ = x[formAddrx3-43]
	_ = x[formAddrx4-44]
	_ = x[formGnuRefAlt-7968]
	_ = x[formGnuStrpAlt-7969]
	_ = x[formLlvmAddrxOffset-8193]
}

const (
	_format_name_0 = "Addr"
	_format_name_1 = "DwarfBlock2DwarfBlock4Data2Data4Data8StringDwarfBlockDwarfBlock1Data1FlagSdataStrpUdataRefAddrRef1Ref2Ref4Ref8RefUdataIndirectSecOffsetExprlocFlagPresentStrxAddrxRefSup4StrpSupData16LineStrpRefSig8ImplicitConstLoclistxRnglistxRefSup8Strx1Strx2Strx3Strx4Addrx1Addrx2Addrx3Addrx4"
	_format_name_2 = "GnuRefAltGnuStrpAlt"
	_format_name_3 = "LlvmAddrxOffset"
)

var (
	_format_index_1 = [...]uint16{0, 11, 22, 27, 32, 37, 43, 53, 64, 69, 73, 78, 82, 87, 94, 98, 102, 106, 110, 118, 126, 135, 142, 153, 157, 162, 169, 176, 182, 190, 197, 210, 218, 226, 233, 238, 243, 248, 253, 259, 265, 271, 277}
	_format_index_2 = [...]uint8{0, 9, 19}
)

func (i format) String() string {
	switch {
	case i == 1:
		return _format_name_0
	case 3 <= i && i <= 44:
		i -= 3
		return _format_name_1[_format_index_1[i]:_format_index_1[i+1]]
	case 7968 <= i && i <= 7969:
		i -= 7968
		return _format_name_2[_format_index_2[i]:_format_index_2[i+1]]
	case i == 8193:
		return _format_name_3
	default:
		return "format(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
