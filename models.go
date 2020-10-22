package proip

import "math/big"

// Meta - model for meta information about database
type Meta struct {
	//public members
	StructVersion uint32 // struct version
	BuildVersion  uint32 // version of build
	CountV4       uint32 // amount of ip v4 addresses
	CountV6       uint32 // amount of ip v6 addresses

	// private members
	contentPtr   uint32
	regionPtr    uint32
	cityPtr      uint32
	ispPtr       uint32
	hashV4Pos    uint32
	hashV4Min    uint32
	hashV4Max    uint32
	hashV4Step   uint32
	hashV6Pos    uint32
	hashV6Min    *big.Int
	hashV6Max    *big.Int
	hashV6Step   *big.Int
	hashV4PtrPos uint32
	hashV6PtrPos uint32
}

// Leaf - model for database output structure
type Leaf struct {
	CountryCode string // 2 letter country code
	Country     string // country name
	Region      string // region name
	City        string // city
	ISP         string // ISP
}
