package proip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
)

// ---------------- PUBLIC BLOCK ----------------

// NewGDBCClient - factory method for db client
func NewGDBCClient(filename string) (*gdbcClient, error) {
	var err error
	client := &gdbcClient{}
	client.file, err = newDBStream(filename, true)
	if err != nil {
		return nil, err
	}
	client.Meta, err = newMeta(client.file)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetRecord - method for getting actual record using ip address
func (client *gdbcClient) GetRecord(ip net.IP) (*Leaf, error) {
	if ip.To4() != nil {
		return client.getRecordV4(ip)
	}
	return client.getRecordV6(ip)
}

// Close - method for closing db
func (client *gdbcClient) Close() {
	client.file.close()
}

// ---------------- PRIVATE BLOCK ----------------

func newMeta(file *dbStream) (*Meta, error) {
	length := getMetaLength() + 4
	file.seekPos(0, io.SeekStart)
	buf, err := file.readCount(length)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(buf[0:4], []byte("GDBC")) {
		return nil, errors.New("Invalid meta header")
	}
	meta := &Meta{}
	meta.StructVersion = binary.LittleEndian.Uint32(buf[4:8])
	meta.BuildVersion = binary.LittleEndian.Uint32(buf[8:12])
	meta.CountV4 = binary.LittleEndian.Uint32(buf[12:16])
	meta.CountV6 = binary.LittleEndian.Uint32(buf[16:20])
	meta.contentPtr = binary.LittleEndian.Uint32(buf[20:24])
	meta.regionPtr = binary.LittleEndian.Uint32(buf[24:28])
	meta.cityPtr = binary.LittleEndian.Uint32(buf[28:32])
	meta.ispPtr = binary.LittleEndian.Uint32(buf[32:36])
	meta.hashV4Pos = binary.LittleEndian.Uint32(buf[36:40])
	meta.hashV4Min = binary.LittleEndian.Uint32(buf[40:44])
	meta.hashV4Max = binary.LittleEndian.Uint32(buf[44:48])
	meta.hashV4Step = binary.LittleEndian.Uint32(buf[48:52])
	meta.hashV6Pos = binary.LittleEndian.Uint32(buf[52:56])
	meta.hashV6Min = &big.Int{}
	meta.hashV6Max = &big.Int{}
	meta.hashV6Step = &big.Int{}
	meta.hashV6Min.SetBytes(buf[56:72])
	meta.hashV6Max.SetBytes(buf[72:88])
	meta.hashV6Step.SetBytes(buf[88:104])
	meta.hashV4PtrPos = binary.LittleEndian.Uint32(buf[104:108])
	meta.hashV6PtrPos = binary.LittleEndian.Uint32(buf[108:112])
	return meta, nil
}

func (client *gdbcClient) hashFuncV4(val uint32) uint32 {
	//Usually this shouldn't be so but just in case add this check
	if val > client.Meta.hashV4Max {
		val = client.Meta.hashV4Max
	}
	return uint32(math.Floor(float64(val-client.Meta.hashV4Min) / float64(client.Meta.hashV4Step)))
}

type gdbcClient struct {
	file *dbStream
	Meta *Meta
}

func getMetaLength() uint32 {
	result := 4 + //STRUCT_VERSION_POS
		4 + //BUILD_VERSION_POS
		4 + //COUNT_V4_POS
		4 + //COUNT_V6_POS
		4 + //CONTENT_PTR_POS
		4 + //REGION_PTR_POS
		4 + //CITY_PTR_POS
		4 + //ISP_PTR_POS
		4 + //HASH_V4_POS
		4 + //HASH_V4_MIN
		4 + //HASH_V4_MAX
		4 + //HASH_V4_STEP
		4 + //HASH_V6_POS
		16 + //HASH_V6_MIN
		16 + //HASH_V6_MAX
		16 + //HASH_V6_STEP4
		4 + //HASH_V4_PTR_POS
		4 //HASH_V6_PTR_POS
	return uint32(result)
}

func (client *gdbcClient) hashFuncV6(val *big.Int) uint32 {
	tmpRes := &big.Int{}
	//Usually this shouldn't be so but just in case add this check
	if val.Cmp(client.Meta.hashV6Max) > 0 {
		tmpRes.Set(client.Meta.hashV6Max)
	} else {
		tmpRes.Set(val)
	}
	tmpRes.Sub(tmpRes, client.Meta.hashV6Min)
	tmpRes.Div(tmpRes, client.Meta.hashV6Step)
	return uint32(tmpRes.Uint64())
}

func (client *gdbcClient) getHashValsV4(buf []byte, pos uint32) (start uint32, end uint32, ptr uint32) {
	startPtr := pos * 12
	start = binary.LittleEndian.Uint32(buf[startPtr : startPtr+4])
	end = binary.LittleEndian.Uint32(buf[startPtr+4 : startPtr+8])
	ptr = binary.LittleEndian.Uint32(buf[startPtr+8 : startPtr+12])
	return
}

func (client *gdbcClient) getLeafPtrV4(buf []byte, searchIPInt uint32) (uint32, bool) {
	low, high := uint32(0), uint32(len(buf)/12-1)
	lowStart, lowEnd, lowPtrs := client.getHashValsV4(buf, low)
	if lowStart <= searchIPInt && searchIPInt <= lowEnd {
		return lowPtrs, true
	}
	if high == low || searchIPInt < lowStart {
		return 0, false
	}
	highStart, highEnd, highPtrs := client.getHashValsV4(buf, high)
	if highStart <= searchIPInt && searchIPInt <= highEnd {
		return highPtrs, true
	}
	if highEnd < searchIPInt {
		return 0, false
	}
	for {
		nextApprox := low + (high-low)*(searchIPInt-lowEnd)/(highStart-lowEnd)
		if nextApprox == low {
			nextApprox = low + 1
		}
		if nextApprox == high {
			nextApprox = high - 1
		}
		curStart, curEnd, curPtrs := client.getHashValsV4(buf, nextApprox)
		if curStart <= searchIPInt && searchIPInt <= curEnd {
			return curPtrs, true
		} else if searchIPInt > curEnd {
			low = nextApprox
		} else if searchIPInt < curStart {
			high = nextApprox
		}
		if high <= low+1 {
			break
		}
	}
	return 0, false
}

func (client *gdbcClient) getHashListV4(searchIPInt uint32) ([]byte, error) {
	buf := []byte{}
	block := client.hashFuncV4(searchIPInt)
	hashAddrPos := client.Meta.hashV4PtrPos + block*4
	client.file.seekPos(hashAddrPos, io.SeekStart)
	hashListPtr, err := client.file.readUint32()
	if err != nil {
		return buf, err
	}
	client.file.seekPos(client.Meta.hashV4Pos+hashListPtr, io.SeekStart)
	hashLen, err := client.file.readUint32()
	if err != nil {
		return buf, err
	}
	if hashLen == 0 {
		return buf, nil
	}
	buf, err = client.file.readCount(hashLen)
	if err != nil {
		return buf, err
	}
	return buf, nil
}

func (client *gdbcClient) readDic(ptr uint32) (string, error) {
	client.file.seekPos(ptr, io.SeekStart)
	buf, err := client.file.readCount(256)
	if err != nil {
		return "", err
	}
	return string(buf[1:(buf[0] + 1)]), nil
}

func (client *gdbcClient) getLeaf(ptr uint32) (*Leaf, error) {
	client.file.seekPos(client.Meta.contentPtr+ptr, io.SeekStart)
	leaf := &Leaf{}
	countyCode, err := client.file.readCount(2)
	if err != nil {
		return nil, err
	}
	leaf.CountryCode = string(countyCode)
	regionPtr, err := client.file.readUint32()
	if err != nil {
		return nil, err
	}
	pos := client.file.getCurrentPos()
	leaf.Region, err = client.readDic(client.Meta.regionPtr + regionPtr)
	if err != nil {
		return nil, err
	}
	client.file.seekPos(pos, io.SeekStart)
	cityPtr, err := client.file.readUint32()
	if err != nil {
		return nil, err
	}
	pos = client.file.getCurrentPos()
	leaf.City, err = client.readDic(client.Meta.cityPtr + cityPtr)
	if err != nil {
		return nil, err
	}
	client.file.seekPos(pos, io.SeekStart)
	ispPtr, err := client.file.readUint32()
	if err != nil {
		return nil, err
	}
	pos = client.file.getCurrentPos()
	leaf.ISP, err = client.readDic(client.Meta.ispPtr + ispPtr)
	if err != nil {
		return nil, err
	}
	client.file.seekPos(pos, io.SeekStart)
	return leaf, nil
}

func (client *gdbcClient) getRecordV4(ip net.IP) (*Leaf, error) {
	searchIPInt := ipV4ToInt(ip)
	if searchIPInt < client.Meta.hashV4Min || client.Meta.hashV4Max < searchIPInt {
		return nil, nil
	}
	buf, err := client.getHashListV4(searchIPInt)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}
	leafPtr, found := client.getLeafPtrV4(buf, searchIPInt)
	if !found {
		return nil, nil
	}
	return client.getLeaf(leafPtr)
}

func (client *gdbcClient) getRecordV6(ip net.IP) (*Leaf, error) {
	searchIPInt := ipV6ToInt(ip)
	if searchIPInt.Cmp(client.Meta.hashV6Min) < 0 || client.Meta.hashV6Max.Cmp(searchIPInt) < 0 {
		return nil, nil
	}
	buf, err := client.getHashListV6(searchIPInt)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}
	leafPtr, found := client.getLeafPtrV6(buf, searchIPInt)
	if !found {
		return nil, nil
	}
	return client.getLeaf(leafPtr)
}

func (client *gdbcClient) getHashValsV6(buf []byte, pos uint32) (start *big.Int, end *big.Int, ptr uint32) {
	startPtr := pos * 36
	start = &big.Int{}
	end = &big.Int{}
	start.SetBytes(buf[startPtr : startPtr+16])
	end.SetBytes(buf[startPtr+16 : startPtr+32])
	ptr = binary.LittleEndian.Uint32(buf[startPtr+32 : startPtr+36])
	return
}

func (client *gdbcClient) getLeafPtrV6(buf []byte, searchIPInt *big.Int) (uint32, bool) {
	low, high := uint32(0), uint32(len(buf)/36-1)
	lowStart, lowEnd, lowPtrs := client.getHashValsV6(buf, low)
	if lowStart.Cmp(searchIPInt) <= 0 && searchIPInt.Cmp(lowEnd) <= 0 {
		return lowPtrs, true
	}
	if high == low || searchIPInt.Cmp(lowStart) < 0 {
		return 0, false
	}
	highStart, highEnd, highPtrs := client.getHashValsV6(buf, high)
	if highStart.Cmp(searchIPInt) <= 0 && searchIPInt.Cmp(highEnd) <= 0 {
		return highPtrs, true
	}
	if highEnd.Cmp(searchIPInt) < 0 {
		return 0, false
	}
	for {
		//low + (high-low)*(searchIPInt-lowEnd)/(highStart-lowEnd)
		nextApproxBig := &big.Int{}
		fullInterval := &big.Int{}
		fullBlocks := &big.Int{}
		lowBig := &big.Int{}
		nextApproxBig.Set(searchIPInt)
		fullInterval.Set(highStart)
		fullInterval.Sub(fullInterval, lowEnd)
		fullBlocks.SetUint64(uint64(high - low))
		lowBig.SetUint64(uint64(low))
		nextApproxBig.Sub(nextApproxBig, lowEnd)
		nextApproxBig.Mul(nextApproxBig, fullBlocks)
		nextApproxBig.Quo(nextApproxBig, fullInterval)
		nextApproxBig.Add(nextApproxBig, lowBig)
		nextApprox := uint32(nextApproxBig.Uint64())
		if nextApprox == low {
			nextApprox = low + 1
		}
		if nextApprox == high {
			nextApprox = high - 1
		}
		curStart, curEnd, curPtrs := client.getHashValsV6(buf, nextApprox)
		if curStart.Cmp(searchIPInt) <= 0 && searchIPInt.Cmp(curEnd) <= 0 {
			return curPtrs, true
		} else if searchIPInt.Cmp(curEnd) > 0 {
			low = nextApprox
		} else if searchIPInt.Cmp(curStart) < 0 {
			high = nextApprox
		}
		if high <= low+1 {
			break
		}
	}
	return 0, false
}

func (client *gdbcClient) getHashListV6(searchIPInt *big.Int) ([]byte, error) {
	buf := []byte{}
	block := client.hashFuncV6(searchIPInt)
	hashAddrPos := client.Meta.hashV6PtrPos + block*4
	client.file.seekPos(hashAddrPos, io.SeekStart)
	hashListPtr, err := client.file.readUint32()
	if err != nil {
		return buf, err
	}
	client.file.seekPos(client.Meta.hashV6Pos+hashListPtr, io.SeekStart)
	hashLen, err := client.file.readUint32()
	if err != nil {
		return buf, err
	}
	if hashLen == 0 {
		return buf, nil
	}
	buf, err = client.file.readCount(hashLen)
	if err != nil {
		return buf, err
	}
	return buf, nil
}
