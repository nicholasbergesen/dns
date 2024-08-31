package main

import (
	"encoding/binary"
	"strings"
)

type DNSHeader struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCODE   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func ParseHeader(data []byte) DNSHeader {
	header := DNSHeader{}
	header.ID = binary.BigEndian.Uint16(data[0:2])

	flags := binary.BigEndian.Uint16(data[2:4])
	header.QR = (flags & 0x8000) != 0
	header.Opcode = uint8((flags >> 11) & 0x0F)
	header.AA = (flags & 0x0400) != 0
	header.TC = (flags & 0x0200) != 0
	header.RD = (flags & 0x0100) != 0
	header.RA = (flags & 0x0080) != 0
	header.Z = uint8((flags >> 4) & 0x7)
	header.RCODE = uint8(flags & 0x0F)

	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])

	return header
}

func (h *DNSHeader) ToBytes() []byte {
	data := make([]byte, HEADER_LENGTH)

	binary.BigEndian.PutUint16(data[0:2], h.ID)

	var flags uint16
	if h.QR {
		flags |= 0x8000
	}
	flags |= (uint16(h.Opcode) & 0x0F) << 11
	if h.AA {
		flags |= 0x0400
	}
	if h.TC {
		flags |= 0x0200
	}
	if h.RD {
		flags |= 0x0100
	}
	if h.RA {
		flags |= 0x0080
	}
	flags |= (uint16(h.Z) & 0x7) << 4
	flags |= uint16(h.RCODE) & 0x0F

	binary.BigEndian.PutUint16(data[2:4], flags)
	binary.BigEndian.PutUint16(data[4:6], h.QDCount)
	binary.BigEndian.PutUint16(data[6:8], h.ANCount)
	binary.BigEndian.PutUint16(data[8:10], h.NSCount)
	binary.BigEndian.PutUint16(data[10:12], h.ARCount)

	return data
}

func ParseQuestion(data []byte, offset int) (DNSQuestion, int) {
	question := DNSQuestion{}
	startOffset := offset
	var qnameParts []string
	for {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		offset++
		qnameParts = append(qnameParts, string(data[offset:offset+length]))
		offset += length
	}
	question.QNameLength = offset - startOffset
	question.QName = strings.Join(qnameParts, ".")

	question.QType = binary.BigEndian.Uint16(data[offset : offset+2])
	question.QClass = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	return question, offset
}
