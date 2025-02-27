package rfc8291

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	BASE_HEADER_LEN = 21
)

type Payload struct {
	RS         uint32
	Salt       []byte
	KeyId      []byte
	CipherText []byte
}

func Marshal(p Payload) (data []byte) {
	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, p.RS)
	return bytes.Join([][]byte{
		p.Salt,
		rs,
		{uint8(len(p.KeyId))},
		p.KeyId,
		p.CipherText,
	}, []byte{})
}

func Unmarshal(data []byte) (p Payload, err error) {
	err = errors.New("data is too short")

	if len(data) < BASE_HEADER_LEN {
		return p, err
	}

	p.Salt = data[:16]
	p.RS = binary.BigEndian.Uint32(data[16:20])

	idlen := int(data[20])
	if len(data) < BASE_HEADER_LEN+idlen {
		return p, err
	}

	if idlen > 0 {
		p.KeyId = data[BASE_HEADER_LEN : BASE_HEADER_LEN+idlen]
	}

	p.CipherText = data[BASE_HEADER_LEN+idlen:]

	return p, nil
}
