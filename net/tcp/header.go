package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	HeaderLen    = 20 // header length without extension headers
	maxHeaderLen = 60 // sensible default, revisit if later RFCs define new usage of version and header length fields
)

const (
	FlagNS  = 0x100
	FlagCWR = 0x80
	FlagECE = 0x40
	FlagURG = 0x20
	FlagACK = 0x10
	FlagPSH = 0x08
	FlagRST = 0x04
	FlagSYN = 0x02
	FlagFIN = 0x01
)

// A Header represents an IPv4 header.
type Header struct {
	SPort      uint16 // Source port
	DPort      uint16 // Destination port
	SeqNum     uint32 // Sequence number
	AckNum     uint32 // Acknowledgment number (if ACK set)
	Offset     uint8  // Data offset
	Flags      uint16 // Flags NS|CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
	WinSize    uint16 // Window Size
	Checksum   uint16 // Checksum
	UrgPointer uint16 // Urgent pointer (if URG set)
	Options    []byte // options, extension headers
}

type PseudoHeader struct {
	Src      net.IP // source address
	Dst      net.IP // destination address
	Protocol uint16 // next protocol
	Len      uint16 // header length
}

func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("sport=%d dport=%d seqnum=%d acknum=%d offset=%d flags=%#x winsize=%d checksum=%d urgpointer=%d", h.SPort, h.DPort, h.SeqNum, h.AckNum, h.Offset, h.Flags, h.WinSize, h.Checksum, h.UrgPointer)
}

// Marshal returns the binary encoding of h.
func (h *Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	hdrlen := HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)
	binary.BigEndian.PutUint16(b[0:2], h.SPort)
	binary.BigEndian.PutUint16(b[2:4], h.DPort)
	binary.BigEndian.PutUint32(b[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(b[8:12], h.AckNum)
	b[12] = byte(int(h.Offset<<4) | int(h.Flags>>8))
	b[13] = byte(h.Flags & 0xff)
	binary.BigEndian.PutUint16(b[14:16], h.WinSize)
	binary.BigEndian.PutUint16(b[16:18], h.Checksum)
	binary.BigEndian.PutUint16(b[18:20], h.UrgPointer)
	if len(h.Options) > 0 {
		copy(b[HeaderLen:], h.Options)
	}
	return b, nil
}

func (h *PseudoHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	ipv4 := h.Src.To4()
	if ipv4 != nil {
		b := make([]byte, 12)
		copy(b[0:4], ipv4[:net.IPv4len])
		if ip := h.Dst.To4(); ip != nil {
			copy(b[4:8], ip[:net.IPv4len])
		} else {
			return nil, errMissingAddress
		}
		binary.BigEndian.PutUint16(b[8:10], h.Protocol)
		binary.BigEndian.PutUint16(b[10:12], h.Len)
		return b, nil
	} else {
		b := make([]byte, 40)
		copy(b[0:16], h.Src[:net.IPv6len])
		copy(b[16:32], h.Dst[:net.IPv6len])
		binary.BigEndian.PutUint16(b[34:36], h.Len)
		binary.BigEndian.PutUint16(b[38:40], h.Protocol)
		return b, nil
	}
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

func (h *Header) MarshalWithData(ipheader []byte, data []byte) ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	if len(ipheader) == 12 {
		hdrlen := 12 + HeaderLen + len(h.Options)
		b := make([]byte, hdrlen+len(data))
		copy(b[:12], ipheader)
		binary.BigEndian.PutUint16(b[12:14], h.SPort)
		binary.BigEndian.PutUint16(b[14:16], h.DPort)
		binary.BigEndian.PutUint32(b[16:20], h.SeqNum)
		binary.BigEndian.PutUint32(b[20:24], h.AckNum)
		b[24] = byte(int(h.Offset<<4) | int(h.Flags>>8))
		b[25] = byte(h.Flags & 0xff)
		binary.BigEndian.PutUint16(b[26:28], h.WinSize)
		binary.BigEndian.PutUint16(b[28:30], 0)
		binary.BigEndian.PutUint16(b[30:32], h.UrgPointer)
		if len(h.Options) > 0 {
			copy(b[12+HeaderLen:], h.Options)
		}
		copy(b[hdrlen:], data)
		binary.BigEndian.PutUint16(b[28:30], CheckSum(b))
		return b[12:], nil
	} else {
		hdrlen := 40 + HeaderLen + len(h.Options)
		b := make([]byte, hdrlen+len(data))
		copy(b[:40], ipheader)
		binary.BigEndian.PutUint16(b[40:42], h.SPort)
		binary.BigEndian.PutUint16(b[42:44], h.DPort)
		binary.BigEndian.PutUint32(b[44:48], h.SeqNum)
		binary.BigEndian.PutUint32(b[48:52], h.AckNum)
		b[52] = byte(int(h.Offset<<4) | int(h.Flags>>8))
		b[53] = byte(h.Flags & 0xff)
		binary.BigEndian.PutUint16(b[54:56], h.WinSize)
		binary.BigEndian.PutUint16(b[56:58], 0)
		binary.BigEndian.PutUint16(b[58:60], h.UrgPointer)
		if len(h.Options) > 0 {
			copy(b[40+HeaderLen:], h.Options)
		}
		copy(b[hdrlen:], data)
		binary.BigEndian.PutUint16(b[56:58], CheckSum(b))
		return b[40:], nil
	}
}

// Parse parses b as an IPv4 header and sotres the result in h.
func (h *Header) Parse(b []byte) error {
	if h == nil || len(b) < HeaderLen {
		return errHeaderTooShort
	}
	h.SPort = binary.BigEndian.Uint16(b[0:2])
	h.DPort = binary.BigEndian.Uint16(b[2:4])
	h.SeqNum = binary.BigEndian.Uint32(b[4:8])
	h.AckNum = binary.BigEndian.Uint32(b[8:12])
	h.Offset = b[12] >> 4
	h.Flags = uint16(b[13]) | (uint16(b[12]&0x1) << 8)
	h.WinSize = binary.BigEndian.Uint16(b[14:16])
	h.Checksum = binary.BigEndian.Uint16(b[16:18])
	h.UrgPointer = binary.BigEndian.Uint16(b[18:20])
	return nil
}

// ParseHeader parses b as an IPv4 header.
func ParseHeader(b []byte) (*Header, error) {
	h := new(Header)
	if err := h.Parse(b); err != nil {
		return nil, err
	}
	return h, nil
}
