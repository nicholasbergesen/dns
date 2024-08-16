package main

import (
	"testing"
)

func testReadDomainName(t *testing.T) {
	offset := 117
	bytes := []byte("24aa81800001000b000000000269620561646e787303636f6d0000010001c00c0005000100004b8b00200b78616e64722d672d67656f0e747261666669636d616e61676572036e657400c02a0005000100000de200130269620473696e310867656f61646e7873c015c056000100010000009d0004672b5a15c056000100010000009d0004672b5ab2c056000100010000009d0004672b5a75c056000100010000009d0004672b5ab3c056000100010000009d0004672b5a13c056000100010000009d0004672b5a36c056000100010000009d0004672b5a72c056000100010000009d0004672b5a35c056000100010000009d0004672b59040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	domainName, _ := readDomainName(bytes, offset)
	t.Log(domainName)
}
