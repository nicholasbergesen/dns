package dns

import "time"

type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

const HEADER_LENGTH = 12

func (m *Message) IsExpired() bool {
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

func (m *Message) ToBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}
	for _, answer := range m.Answers {
		bytes = append(bytes, answer.ToBytes()...)
	}

	return bytes
}

func (m *Message) UpstreamBytes() []byte {
	bytes := m.Header.ToBytes()
	for _, question := range m.Questions {
		bytes = append(bytes, question.ToBytes()...)
	}

	return bytes
}
