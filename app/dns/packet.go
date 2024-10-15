package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type Packet struct {
	Header     Header
	Question   Question
	Answer     []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

type Header struct {
	ID              uint16
	QR              bool
	OpCode          uint8
	AA              bool
	TC              bool
	RD              bool
	RA              bool
	Z               uint8
	ResponseCode    uint8
	QuestionCount   uint16
	AnswerCount     uint16
	AuthorityCount  uint16
	AdditionalCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func (p *Packet) Serialize() ([]byte, error) {
	var buf []byte

	// Serialize Header
	headerBytes := make([]byte, 12)
	binary.BigEndian.PutUint16(headerBytes[0:2], p.Header.ID)
	
	flags := uint16(0)
	if p.Header.QR {
		flags |= 1 << 15
	}
	flags |= uint16(p.Header.OpCode) << 11
	if p.Header.AA {
		flags |= 1 << 10
	}
	if p.Header.TC {
		flags |= 1 << 9
	}
	if p.Header.RD {
		flags |= 1 << 8
	}
	if p.Header.RA {
		flags |= 1 << 7
	}
	flags |= uint16(p.Header.Z) << 4
	flags |= uint16(p.Header.ResponseCode)
	
	binary.BigEndian.PutUint16(headerBytes[2:4], flags)
	binary.BigEndian.PutUint16(headerBytes[4:6], p.Header.QuestionCount)
	binary.BigEndian.PutUint16(headerBytes[6:8], p.Header.AnswerCount)
	binary.BigEndian.PutUint16(headerBytes[8:10], p.Header.AuthorityCount)
	binary.BigEndian.PutUint16(headerBytes[10:12], p.Header.AdditionalCount)
	
	buf = append(buf, headerBytes...)

	// Serialize Question
	questionBytes, err := serializeQuestion(p.Question)
	if err != nil {
		return nil, err
	}
	buf = append(buf, questionBytes...)

	// Serialize Answer, Authority, and Additional sections
	for _, rr := range p.Answer {
		rrBytes, err := serializeResourceRecord(rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, rrBytes...)
	}

	for _, rr := range p.Authority {
		rrBytes, err := serializeResourceRecord(rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, rrBytes...)
	}

	for _, rr := range p.Additional {
		rrBytes, err := serializeResourceRecord(rr)
		if err != nil {
			return nil, err
		}
		buf = append(buf, rrBytes...)
	}

	return buf, nil
}

func serializeQuestion(q Question) ([]byte, error) {
	var buf []byte

	// Serialize Name
	nameBytes, err := encodeDomainName(q.Name)
	if err != nil {
		return nil, err
	}
	buf = append(buf, nameBytes...)

	// Serialize Type and Class
	typeClassBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(typeClassBytes[0:2], q.Type)
	binary.BigEndian.PutUint16(typeClassBytes[2:4], q.Class)
	buf = append(buf, typeClassBytes...)

	return buf, nil
}

func serializeResourceRecord(rr ResourceRecord) ([]byte, error) {
	var buf []byte

	// Serialize Name
	nameBytes, err := encodeDomainName(rr.Name)
	if err != nil {
		return nil, err
	}
	buf = append(buf, nameBytes...)

	// Serialize Type, Class, TTL, and RDLength
	rrBytes := make([]byte, 10)
	binary.BigEndian.PutUint16(rrBytes[0:2], rr.Type)
	binary.BigEndian.PutUint16(rrBytes[2:4], rr.Class)
	binary.BigEndian.PutUint32(rrBytes[4:8], rr.TTL)
	binary.BigEndian.PutUint16(rrBytes[8:10], rr.RDLength)
	buf = append(buf, rrBytes...)

	// Serialize RData
	buf = append(buf, rr.RData...)

	return buf, nil
}

func encodeDomainName(name string) ([]byte, error) {
	var buf []byte
	labels := strings.Split(name, ".")

	for _, label := range labels {
		if len(label) > 63 {
			return nil, errors.New("label too long")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0) // terminating zero byte

	return buf, nil
}

func (p *Packet) Deserialize(data []byte) error {
	if len(data) < 12 {
		return errors.New("packet too short")
	}

	// Deserialize Header
	p.Header.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	p.Header.QR = (flags & 0x8000) != 0
	p.Header.OpCode = uint8((flags >> 11) & 0xF)
	p.Header.AA = (flags & 0x0400) != 0
	p.Header.TC = (flags & 0x0200) != 0
	p.Header.RD = (flags & 0x0100) != 0
	p.Header.RA = (flags & 0x0080) != 0
	p.Header.Z = uint8((flags >> 4) & 0x7)
	p.Header.ResponseCode = uint8(flags & 0xF)
	p.Header.QuestionCount = binary.BigEndian.Uint16(data[4:6])
	p.Header.AnswerCount = binary.BigEndian.Uint16(data[6:8])
	p.Header.AuthorityCount = binary.BigEndian.Uint16(data[8:10])
	p.Header.AdditionalCount = binary.BigEndian.Uint16(data[10:12])

	offset := 12

	// Deserialize Question
	var err error
	offset, err = deserializeQuestion(data, offset, &p.Question)
	if err != nil {
		return err
	}

	// Deserialize Answer section
	p.Answer = make([]ResourceRecord, p.Header.AnswerCount)
	for i := uint16(0); i < p.Header.AnswerCount; i++ {
		offset, err = deserializeResourceRecord(data, offset, &p.Answer[i])
		if err != nil {
			return err
		}
	}

	// Deserialize Authority section
	p.Authority = make([]ResourceRecord, p.Header.AuthorityCount)
	for i := uint16(0); i < p.Header.AuthorityCount; i++ {
		offset, err = deserializeResourceRecord(data, offset, &p.Authority[i])
		if err != nil {
			return err
		}
	}

	// Deserialize Additional section
	p.Additional = make([]ResourceRecord, p.Header.AdditionalCount)
	for i := uint16(0); i < p.Header.AdditionalCount; i++ {
		offset, err = deserializeResourceRecord(data, offset, &p.Additional[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func deserializeQuestion(data []byte, offset int, q *Question) (int, error) {
	var err error
	q.Name, offset, err = decodeDomainName(data, offset)
	if err != nil {
		return 0, err
	}

	if offset+4 > len(data) {
		return 0, errors.New("packet too short")
	}

	q.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	q.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4

	return offset, nil
}

func deserializeResourceRecord(data []byte, offset int, rr *ResourceRecord) (int, error) {
	var err error
	rr.Name, offset, err = decodeDomainName(data, offset)
	if err != nil {
		return 0, err
	}

	if offset+10 > len(data) {
		return 0, errors.New("packet too short")
	}

	rr.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	rr.Class = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	rr.TTL = binary.BigEndian.Uint32(data[offset+4 : offset+8])
	rr.RDLength = binary.BigEndian.Uint16(data[offset+8 : offset+10])
	offset += 10

	if offset+int(rr.RDLength) > len(data) {
		return 0, errors.New("packet too short")
	}

	rr.RData = data[offset : offset+int(rr.RDLength)]
	offset += int(rr.RDLength)

	return offset, nil
}

func decodeDomainName(data []byte, offset int) (string, int, error) {
	var name strings.Builder
	var jumped bool
	maxJumps := 5
	jumps := 0

	for {
		if jumps > maxJumps {
			return "", 0, errors.New("too many jumps")
		}

		if offset >= len(data) {
			return "", 0, errors.New("buffer overflow")
		}

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, errors.New("buffer overflow")
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			if !jumped {
				offset += 2
			}
			jumped = true
			offset = pointer
			jumps++
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", 0, errors.New("buffer overflow")
		}

		name.WriteString(string(data[offset : offset+length]))
		name.WriteByte('.')
		offset += length
	}

	if name.Len() > 0 {
		return name.String()[:name.Len()-1], offset, nil
	}
	return ".", offset, nil
}

func (p *Packet) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("ID: %d\n", p.Header.ID))
	sb.WriteString(fmt.Sprintf("QR: %v\n", p.Header.QR))
	sb.WriteString(fmt.Sprintf("OpCode: %d\n", p.Header.OpCode))
	sb.WriteString(fmt.Sprintf("AA: %v\n", p.Header.AA))
	sb.WriteString(fmt.Sprintf("TC: %v\n", p.Header.TC))
	sb.WriteString(fmt.Sprintf("RD: %v\n", p.Header.RD))
	sb.WriteString(fmt.Sprintf("RA: %v\n", p.Header.RA))
	sb.WriteString(fmt.Sprintf("Z: %d\n", p.Header.Z))
	sb.WriteString(fmt.Sprintf("ResponseCode: %d\n", p.Header.ResponseCode))
	sb.WriteString(fmt.Sprintf("QuestionCount: %d\n", p.Header.QuestionCount))
	sb.WriteString(fmt.Sprintf("AnswerCount: %d\n", p.Header.AnswerCount))
	sb.WriteString(fmt.Sprintf("AuthorityCount: %d\n", p.Header.AuthorityCount))
	sb.WriteString(fmt.Sprintf("AdditionalCount: %d\n", p.Header.AdditionalCount))

	sb.WriteString(fmt.Sprintf("Question: %s (Type: %d, Class: %d)\n", p.Question.Name, p.Question.Type, p.Question.Class))

	sb.WriteString("Answer Section:\n")
	for _, rr := range p.Answer {
		sb.WriteString(fmt.Sprintf("  %s\n", formatResourceRecord(rr)))
	}

	sb.WriteString("Authority Section:\n")
	for _, rr := range p.Authority {
		sb.WriteString(fmt.Sprintf("  %s\n", formatResourceRecord(rr)))
	}

	sb.WriteString("Additional Section:\n")
	for _, rr := range p.Additional {
		sb.WriteString(fmt.Sprintf("  %s\n", formatResourceRecord(rr)))
	}

	return sb.String()
}

func formatResourceRecord(rr ResourceRecord) string {
	return fmt.Sprintf("%s (Type: %d, Class: %d, TTL: %d, RDLength: %d, RData: %v)",
		rr.Name, rr.Type, rr.Class, rr.TTL, rr.RDLength, rr.RData)
}
