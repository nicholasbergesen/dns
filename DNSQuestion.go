package main

import (
	"encoding/binary"
	"strings"
)

type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

func ParseQuestion(data []byte, offset *int) DNSQuestion {
	question := DNSQuestion{}
	var qnameParts []string
	for {
		length := int(data[*offset])
		if length == 0 {
			*offset++
			break
		}
		*offset++
		qnameParts = append(qnameParts, string(data[*offset:*offset+length]))
		*offset += length
	}

	question.QName = strings.Join(qnameParts, ".")

	question.QType = binary.BigEndian.Uint16(data[*offset : *offset+2])
	question.QClass = binary.BigEndian.Uint16(data[*offset+2 : *offset+4])
	*offset += 4

	return question
}

func (q *DNSQuestion) ToBytes() []byte {
	data := []byte{}

	for _, part := range strings.Split(q.QName, ".") {
		if part == "" {
			continue
		}
		data = append(data, byte(len(part)))
		data = append(data, []byte(part)...)
	}
	data = append(data, 0)

	qType := make([]byte, 2)
	qClass := make([]byte, 2)
	binary.BigEndian.PutUint16(qType, q.QType)
	binary.BigEndian.PutUint16(qClass, q.QClass)

	data = append(data, qType...)
	data = append(data, qClass...)

	return data
}
