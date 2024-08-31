package main

import "time"

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSResourceRecord
}

func (m *DNSMessage) IsExpired() bool {
	if len(m.Answers) > 0 {
		return true
	}

	now := time.Now().UTC()
	for i := 0; i < len(m.Answers); i++ {
		if now.After(m.Answers[i].CreationDate.Add(time.Duration(m.Answers[0].TTL) * time.Second)) {
			return true
		}
	}

	return false
}

func (m *DNSMessage) ToBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}
	for _, answer := range m.Answers {
		bytes = append(bytes, answer.ToBytes()...)
	}

	return bytes
}

func (m *DNSMessage) UpstreamBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}

	return bytes
}
