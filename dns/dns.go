package dns

import (
	"encoding/binary"
	//"log"
	"net"
	"strings"
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
	TypeNone  = 0
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeANY   = 255
	ClassIN   = 1
	ClassCS   = 2
	ClassCH   = 3
	ClassHS   = 4
)

const (
	ADDRESS = 0
	UDP     = 1
	TCP     = 2
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

func PackQName(name string) []byte {
	length := strings.Count(name, "")
	QName := make([]byte, length+1)
	copy(QName[1:], []byte(name))
	o, l := 0, 0
	for i := 1; i < length; i++ {
		if QName[i] == '.' {
			QName[o] = byte(l)
			l = 0
			o = i
		} else {
			l++
		}
	}
	QName[o] = byte(l)

	return QName
}

type Resource struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type Answers struct {
	ANCount uint16
	NSCount uint16
	ARCount uint16
	Answers []byte
}

func PackAnswers(IPList []net.IP) Answers {
	answers := make([]byte, 1024)
	length := 0
	for _, ip := range IPList {
		if ip[0] == 0x00 {
			//A
			answer := []byte{0xC0, 0x0C, 0x00, byte(TypeA),
				0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
				ip[12], ip[13], ip[14], ip[15]}
			copy(answers[length:], answer)
			length += 16
		} else {
			answer := []byte{0xC0, 0x0C, 0x00, byte(TypeAAAA),
				0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x10}
			copy(answers[length:], answer)
			length += 12
			copy(answers[length:], ip)
			length += 16
		}
	}
	return Answers{uint16(len(IPList)), 0, 0, answers[:length]}
}

func PackResponse(Request []byte, answers Answers) []byte {
	length := len(Request)
	Response := make([]byte, 1024)
	copy(Response, Request)
	Response[2] = 0x81
	Response[3] = 0x80
	Response[7] = byte(answers.ANCount)
	Response[9] = byte(answers.NSCount)
	Response[11] = byte(answers.ARCount)
	if answers.ANCount > 0 {
		copy(Response[length:], answers.Answers)
		length += len(answers.Answers)
	}

	return Response[:length]
}
