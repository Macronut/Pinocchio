// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	Version   = 6  // protocol version
	HeaderLen = 40 // header length
)

// A Header represents an IPv6 base header.
type Header struct {
	Version      int    // protocol version
	TrafficClass int    // traffic class
	FlowLabel    int    // flow label
	PayloadLen   int    // payload length
	NextHeader   int    // next header
	HopLimit     int    // hop limit
	Src          net.IP // source address
	Dst          net.IP // destination address
}

func (h *Header) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ver=%d tclass=%#x flowlbl=%#x payloadlen=%d nxthdr=%d hoplim=%d src=%v dst=%v", h.Version, h.TrafficClass, h.FlowLabel, h.PayloadLen, h.NextHeader, h.HopLimit, h.Src, h.Dst)
}

// Marshal returns the binary encoding of h.
func (h *Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	b := make([]byte, 64)
	b[0] = byte(Version<<4 | h.TrafficClass>>4)
	b[1] = byte((h.TrafficClass&0x0f)<<4 | (h.FlowLabel >> 16))
	binary.BigEndian.PutUint16(b[2:4], uint16(h.FlowLabel&0xffff))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.PayloadLen))
	b[6] = byte(h.NextHeader)
	b[7] = byte(h.HopLimit)
	if ip := h.Src.To16(); ip != nil {
		copy(b[8:24], ip[:net.IPv6len])
	}
	if ip := h.Dst.To16(); ip != nil {
		copy(b[24:40], ip[:net.IPv6len])
	} else {
		return nil, errMissingAddress
	}
	return b, nil
}

// ParseHeader parses b as an IPv6 base header.
func ParseHeader(b []byte) (*Header, error) {
	if len(b) < HeaderLen {
		return nil, errHeaderTooShort
	}
	h := &Header{
		Version:      int(b[0]) >> 4,
		TrafficClass: int(b[0]&0x0f)<<4 | int(b[1])>>4,
		FlowLabel:    int(b[1]&0x0f)<<16 | int(b[2])<<8 | int(b[3]),
		PayloadLen:   int(binary.BigEndian.Uint16(b[4:6])),
		NextHeader:   int(b[6]),
		HopLimit:     int(b[7]),
	}
	h.Src = make(net.IP, net.IPv6len)
	copy(h.Src, b[8:24])
	h.Dst = make(net.IP, net.IPv6len)
	copy(h.Dst, b[24:40])
	return h, nil
}
