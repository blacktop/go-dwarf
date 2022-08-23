package dwarf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	magic              = 0x48415348 // "HASH"
	emptyBucket        = 0xFFFFFFFF
	anonymousNamespace = "(anonymous namespace)" // used for .apple_namespaces with DW_TAG_namespace DIEs with no name
)

type atomType uint16

const (
	AtomTypeNULL         atomType = 0 // a termination atom that specifies the end of the atom list
	AtomTypeDIEOffset    atomType = 1 // DIE offset, check form for encoding (an offset into the .debug_info section for the DWARF DIE for this name)
	AtomTypeCUOffset     atomType = 2 // DIE offset of the compiler unit header that contains the item in question (an offset into the .debug_info section for the CU that contains the DIE)
	AtomTypeTag          atomType = 3 // DW_TAG_xxx value, should be encoded as DW_FORM_data1 (if no tags exceed 255) or DW_FORM_data2 (so you don't have to parse the DWARF to see what it is)
	AtomTypeNameFlags    atomType = 4 // Flags from enum NameFlags (for functions and global variables (isFunction, isInlined, isExternal...))
	AtomTypeTypeFlags    atomType = 5 // Flags from enum TypeFlags (for types (isCXXClass, isObjCClass, ...))
	AtomTypeQualNameHash atomType = 6 // A 32 bit hash of the full qualified name (since all hash entries are
	// basename only) For example a type like "std::vector<int>::iterator"
	// would have a name of "iterator" and a 32 bit hash for
	// "std::vector<int>::iterator" to allow us to not have to pull in debug
	// info for a type when we know the fully qualified name.
)

type atomFlag uint8

const (
	FlagClassIsImplementation atomFlag = 1 << 1 // Always set for C++, only set for ObjC if this is the @implementation for class.
)

type hashFuncType uint16

const (
	HashFunctionDJB hashFuncType = 0 // Daniel J Bernstein hash function
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
	headerData // Implementation specific header data
	fixedTable

	r         *bytes.Reader
	dataStart int64
	entryType any
}

type fixedTable struct {
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
	Form format
}

type chunk struct {
	StrOffset     uint32 // KeyType
	HashDataCount uint32
	HashData      []any // array of DIE offsets
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
	if err := binary.Read(h.r, binary.LittleEndian, &h.DieOffsetBase); err != nil {
		return err
	}
	if err := binary.Read(h.r, binary.LittleEndian, &h.AtomCount); err != nil {
		return err
	}
	h.Atoms = make([]atoms, h.AtomCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.Atoms); err != nil {
		return err
	}
	h.Buckets = make([]uint32, h.BucketCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.Buckets); err != nil {
		return err
	}
	h.Hashes = make([]uint32, h.HashesCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.Hashes); err != nil {
		return err
	}
	h.Offsets = make([]uint32, h.HashesCount)
	if err := binary.Read(h.r, binary.LittleEndian, &h.Offsets); err != nil {
		return err
	}

	// mark beginning of data
	h.dataStart, _ = h.r.Seek(0, io.SeekCurrent)

	d.hashes[name] = &h

	if h.AtomCount == 1 {
		h.entryType = &NameEntry{}
	} else {
		h.entryType = &TypeEntry{}
	}

	return nil
}

type Entries []chunk

type NameEntry struct {
	Offset Offset
}

type TypeEntry struct {
	Offset       Offset
	Tag          Tag
	Flags        atomFlag
	QualNameHash uint32
}

func (h *Hash) lookup(name string) (Offset, error) {

	nameHash := djbHash([]byte(name))
	bucketIndex := nameHash % h.BucketCount
	hashIndex := h.Buckets[bucketIndex]

	if hashIndex > h.HashesCount {
		return 0, fmt.Errorf("hash index greater than hash count")
	}

	for ; hashIndex < h.HashesCount; hashIndex++ {
		if h.Hashes[hashIndex] == nameHash {
			dataOffset := h.Offsets[hashIndex]

			if dataOffset == 0 {
				return 0, fmt.Errorf("failed to find offset for %s", name)
			}

			h.r.Seek(int64(dataOffset), io.SeekStart)

			var c chunk
			for {
				if err := binary.Read(h.r, binary.LittleEndian, &c.StrOffset); err != nil {
					return 0, err
				}
				if c.StrOffset == 0 { // bucket contents are done
					break
				} // FIXME: what should we do for hash collitions?
				if err := binary.Read(h.r, binary.LittleEndian, &c.HashDataCount); err != nil {
					return 0, err
				}
				for i := uint32(0); i < c.HashDataCount; i++ {
					if err := binary.Read(h.r, binary.LittleEndian, h.entryType); err != nil {
						return 0, err
					}
					c.HashData = append(c.HashData, h.entryType)
				}
			}

			switch v := h.entryType.(type) {
			case *NameEntry:
				return c.HashData[0].(*NameEntry).Offset, nil
			case *TypeEntry:
				return c.HashData[0].(*TypeEntry).Offset, nil
			default:
				return 0, fmt.Errorf("unknown entry type: %T", v)
			}
		}

		if (h.Hashes[hashIndex] % h.BucketCount) != bucketIndex {
			break
		}
	}

	return 0, fmt.Errorf("failed to find offset for %s", name)
}

func (h *Hash) dump() (Entries, error) {
	var ents Entries
	for _, off := range h.Offsets {
		if off == math.MaxUint32 {
			continue
		}

		h.r.Seek(int64(off), io.SeekStart)

		var c chunk
		if err := binary.Read(h.r, binary.LittleEndian, &c.StrOffset); err != nil {
			return nil, err
		}
		if c.StrOffset == 0 { // bucket contents are done
			break
		}
		if err := binary.Read(h.r, binary.LittleEndian, &c.HashDataCount); err != nil {
			return nil, err
		}
		for i := uint32(0); i < c.HashDataCount; i++ {
			if err := binary.Read(h.r, binary.LittleEndian, h.entryType); err != nil {
				return nil, err
			}
			// for _, atom := range h.Atoms { // TODO: this is more correct and less prone to breakage
			// 	switch atom.Type {
			// 	case AtomTypeDIEOffset:
			// 		if err := binary.Read(h.r, binary.LittleEndian, &tentry.DIEOffset); err != nil {
			// 			return nil, err
			// 		}
			// 	case AtomTypeTag:
			// 		if err := binary.Read(h.r, binary.LittleEndian, &tentry.Tag); err != nil {
			// 			return nil, err
			// 		}
			// 	case AtomTypeTypeFlags:
			// 		if err := binary.Read(h.r, binary.LittleEndian, &tentry.Flags); err != nil {
			// 			return nil, err
			// 		}
			// 	case AtomTypeQualNameHash:
			// 		if err := binary.Read(h.r, binary.LittleEndian, &tentry.QualNameHash); err != nil {
			// 			return nil, err
			// 		}
			// 	}
			// }
			c.HashData = append(c.HashData, h.entryType)
		}

		ents = append(ents, c)
	}

	return ents, nil
}

func djbHash(s []byte) uint32 {
	var hash uint32 = 5381
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}
