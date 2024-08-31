package main

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSResourceRecord
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
