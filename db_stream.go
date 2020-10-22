package proip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
)

type dbStream struct {
	file     *os.File
	readOnly bool
	int32Buf []byte
}

func newDBStream(filename string, readOnly bool) (*dbStream, error) {
	var (
		err error
		dir string
	)
	stream := &dbStream{
		readOnly: readOnly,
		int32Buf: make([]byte, 4),
	}
	if readOnly {
		stream.file, err = os.Open(filename)
	} else {
		dir, err = filepath.Abs(filepath.Dir(filename))
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, 0744)
			if err != nil {
				panic(err)
			}
		}
		stream.file, err = os.Create(filename)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	}
	return stream, err
}

func (stream *dbStream) writeBuf(buf []byte) error {
	if stream.readOnly {
		return errors.New("read only file write attempt")
	}
	_, err := stream.file.Write(buf)
	return err
}

func (stream *dbStream) readCount(count uint32) ([]byte, error) {
	buf := make([]byte, count)
	n, err := stream.readBuf(buf)
	if uint32(n) != count {
		msg := fmt.Sprintf("Tried to read %d bytes but got %d", count, n)
		return buf, errors.New(msg)
	}
	return buf, err
}

func (stream *dbStream) readBuf(buf []byte) (int, error) {
	return stream.file.Read(buf)
}

func (stream *dbStream) getCurrentPos() uint32 {
	ptrPos, err := stream.file.Seek(0, io.SeekCurrent)
	if err != nil {
		panic("Failed to fseek")
	}
	return uint32(ptrPos)
}

func (stream *dbStream) seekPos(pos uint32, whence int) {
	_, err := stream.file.Seek(int64(pos), whence)
	if err != nil {
		panic("Failed to fseek")
	}
}

func (stream *dbStream) close() {
	err := stream.file.Close()
	if err != nil {
		panic(err)
	}
}

func (stream *dbStream) getLength() uint32 {
	stream.seekPos(0, io.SeekEnd)
	return stream.getCurrentPos()
}

func (stream *dbStream) writeUInt32(val uint32) error {
	binary.LittleEndian.PutUint32(stream.int32Buf, val)
	return stream.writeBuf(stream.int32Buf)
}

func (stream *dbStream) readUint32() (uint32, error) {
	n, err := stream.readBuf(stream.int32Buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		msg := fmt.Sprintf("Tried to read IPV4 but only %d bytes read", n)
		return 0, errors.New(msg)
	}
	return binary.LittleEndian.Uint32(stream.int32Buf), nil
}

func (stream *dbStream) readUint32FromPosition(pos uint32) (uint32, error) {
	stream.seekPos(pos, io.SeekStart)
	return stream.readUint32()
}

func (stream *dbStream) writeIPV6(val net.IP) error {
	if len(val) != 16 {
		return errors.New("Invalid IP v6")
	}
	return stream.writeBuf(val)
}

func (stream *dbStream) readIPV6() (net.IP, error) {
	result := make(net.IP, 16)
	n, err := stream.readBuf(result)
	if err != nil {
		return nil, err
	}
	if n < 16 {
		msg := fmt.Sprintf("Tried to read IPV6 but only %d bytes read", n)
		return nil, errors.New(msg)
	}
	return result, nil
}

func (stream *dbStream) readIPV6FromPosition(pos uint32) (net.IP, error) {
	stream.seekPos(pos, io.SeekStart)
	return stream.readIPV6()
}

func (stream *dbStream) appendFile(fileToAppend *dbStream) error {
	stream.seekPos(0, io.SeekEnd)
	fileToAppend.seekPos(0, io.SeekStart)
	buf := make([]byte, 1024*1024*16)
	for {
		n, err := fileToAppend.readBuf(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if err := stream.writeBuf(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}
