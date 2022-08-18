package dwarf

import (
	"bytes"
	"encoding/binary"
)

const magic = 0x48415348 // "HASH"

type hashFuncType uint16

const (
	HashFunctionDJB hashFuncType = 0 // Daniel J Bernstein hash function
)

type atomType uint16

const (
	AtomTypeNULL      atomType = 0
	AtomTypeDIEOffset atomType = 1 // DIE offset, check form for encoding
	AtomTypeCUOffset  atomType = 2 // DIE offset of the compiler unit header that contains the item in question
	AtomTypeTag       atomType = 3 // DW_TAG_xxx value, should be encoded as DW_FORM_data1 (if no tags exceed 255) or DW_FORM_data2
	AtomTypeNameFlags atomType = 4 // Flags from enum NameFlags
	AtomTypeTypeFlags atomType = 5 // Flags from enum TypeFlags
)

type header struct {
	Magic            uint32       // 'HASH' magic value to allow endian detection
	Version          uint16       // Version number
	HashFunction     hashFuncType // The hash function enumeration that was used
	BucketCount      uint32       // The number of buckets in this hash table
	HashesCount      uint32       // The total number of unique hash values and hash data offsets in this table
	HeaderDataLength uint32       // The bytes to skip to get to the hash indexes (buckets) for correct alignment
}

type Hash struct {
	header
	// Specifically the length of the following HeaderData field - this does not
	// include the size of the preceding fields
	HeaderData headerData // Implementation specific header data
	FixedTable FixedTable

	r *bytes.Reader
}

type FixedTable struct {
	Buckets []uint32 // [BucketCount]uint32 - An array of hash indexes into the "hashes[]" array below
	Hashes  []uint32 // [HashesCount]uint32 - Every unique 32 bit hash for the entire table is in this table
	Offsets []uint32 // [HashesCount]uint32 - An offset that corresponds to each item in the "hashes[]" array above
}

type headerData struct {
	DieOffsetBase uint32
	AtomCount     uint32
	Atoms         []atoms // AtomCount
}

type atoms struct {
	Type atomType
	Form uint16
}

func (d *Data) parseHashes(name string, hashes []byte) error {

	var h Hash

	h.r = bytes.NewReader(hashes)

	if err := binary.Read(h.r, binary.LittleEndian, &h.header); err != nil {
		return err
	}
	if h.Magic != magic {
		return DecodeError{name, 0, "invalid magic"}
	}
	if err := binary.Read(h.r, binary.LittleEndian, &h.HeaderData.DieOffsetBase); err != nil {
		return err
	}
	if err := binary.Read(h.r, binary.LittleEndian, &h.HeaderData.AtomCount); err != nil {
		return err
	}
	h.HeaderData.Atoms = make([]atoms, h.HeaderData.AtomCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.HeaderData.Atoms); err != nil {
		return err
	}
	h.FixedTable.Buckets = make([]uint32, h.BucketCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.FixedTable.Buckets); err != nil {
		return err
	}
	h.FixedTable.Hashes = make([]uint32, h.HashesCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.FixedTable.Hashes); err != nil {
		return err
	}
	h.FixedTable.Offsets = make([]uint32, h.HashesCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.FixedTable.Offsets); err != nil {
		return err
	}

	d.hashes[name] = &h

	return nil
}

func djbHash(s []byte) uint64 {
	var hash uint64 = 538
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint64(c)
	}
	return hash
}
