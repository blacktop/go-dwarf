# go-dwarf

[![Go](https://github.com/blacktop/go-dwarf/workflows/Go/badge.svg?branch=master)](https://github.com/blacktop/go-dwarf/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/blacktop/go-dwarf.svg)](https://pkg.go.dev/github.com/blacktop/go-dwarf) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

> Package dwarf provides access to DWARF debugging information loaded from executable files, as defined in the DWARF 2.0 Standard at http://dwarfstd.org/doc/dwarf-2.0.0.pdf

---

## Why 🤔

This package goes beyond the Go's `debug/dwarf` to:

- Add support for apple HASH tables
- Add convinience methods for reading/displaying DWARF data

## Install

```bash
$ go get github.com/blacktop/go-dwarf
```

## License

- MIT Copyright (c) 2022 **blacktop**
- Copyright (c) 2009 The Go Authors
