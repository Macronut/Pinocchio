
package dns

import (
	"encoding/binary"
)

type Header struct {
	ID      uint16
	Flag    uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	ClassIN   = 1
	ClassCS   = 2
	ClassCH   = 3
	ClassHS   = 4
)

type Question struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

func UnpackHeader(buf []byte) (Header, int) {
	header := Header{
		binary.BigEndian.Uint16(buf[:2]),
		binary.BigEndian.Uint16(buf[2:4]),
		binary.BigEndian.Uint16(buf[4:6]),
		binary.BigEndian.Uint16(buf[6:8]),
		binary.BigEndian.Uint16(buf[8:10]),
		binary.BigEndian.Uint16(buf[10:12]),
	}
	return header, 12
}

func UnpackQuestion(buf []byte) (Question, int) {
	off := 0
	//QName := make([]byte, 256)
	for {
		length := buf[off]
		off++
		if length == 0x00 {
			break
		}
		end := off + int(length)
		/*
			if off > 1 {
				QName[off-2] = '.'
			}
			copy(QName[off-1:], buf[off:end])
		*/
		off = end
	}

	question := Question{
		//string(QName),
		buf[:off],
		binary.BigEndian.Uint16(buf[off : off+2]),
		binary.BigEndian.Uint16(buf[off+2 : off+4]),
	}
	off += 4
	return question, off
}
