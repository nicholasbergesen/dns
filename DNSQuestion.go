package main

import (
	"encoding/binary"
	"strings"
)

type DNSQuestion struct {
	QName       string
	QNameLength int
	QType       uint16
	QClass      uint16
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
