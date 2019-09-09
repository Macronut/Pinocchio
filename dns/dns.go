package dns

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type Header struct {
	ID      uint16
	Flag    uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const (
	TypeNone  = 0
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeANY   = 255
	ClassIN   = 1
	ClassCS   = 2
	ClassCH   = 3
	ClassHS   = 4
)

const (
	UDP = iota
	TCP
	MYTCP
	HTTP
	HTTPS
	DOH

	TYPE_COUNT
)

var TypeList [TYPE_COUNT]string = [TYPE_COUNT]string{
	"UDP",
	"TCP",
	"MYTCP",
	"HTTP",
	"HTTPS",
	"DOH",
}

type Question struct {
	QName  string
	QType  uint16
	QClass uint16
}

func UnpackHeader(buf []byte) (Header, int) {
	header := Header{
		binary.BigEndian.Uint16(buf[:2]),
		binary.BigEndian.Uint16(buf[2:4]),
		binary.BigEndian.Uint16(buf[4:6]),
		binary.BigEndian.Uint16(buf[6:8]),
		binary.BigEndian.Uint16(buf[8:10]),
		binary.BigEndian.Uint16(buf[10:12]),
	}
	return header, 12
}

func UnpackQuestion(buf []byte) (Question, int, bool) {
	isdomain := false
	off := 0
	n := len(buf)
	for i := 0; off < n; i++ {
		length := buf[off]
		off++
		if length == 0x00 {
			isdomain = i > 1
			break
		}
		end := off + int(length)
		off = end
	}

	if off+4 > n {
		return Question{"", 0, 0}, 0, false
	}

	qname := UnPackQName(buf[:off])
	question := Question{
		qname,
		binary.BigEndian.Uint16(buf[off : off+2]),
		binary.BigEndian.Uint16(buf[off+2 : off+4]),
	}
	off += 4
	return question, off, isdomain
}

func PackQName(name string) []byte {
	length := strings.Count(name, "")
	QName := make([]byte, length+1)
	copy(QName[1:], []byte(name))
	o, l := 0, 0
	for i := 1; i < length; i++ {
		if QName[i] == '.' {
			QName[o] = byte(l)
			l = 0
			o = i
		} else {
			l++
		}
	}
	QName[o] = byte(l)

	return QName
}

func UnPackQName(qname []byte) string {
	if qname[0] == 0x00 {
		return ""
	}
	Name := make([]byte, len(qname)-2)
	length := qname[0]
	off := 1
	end := off + int(length)
	copy(Name[off-1:], qname[off:end])
	for {
		off = end
		length := qname[off]
		if length == 0x00 {
			break
		}
		Name[off-1] = '.'
		off++
		end = off + int(length)
		copy(Name[off-1:], qname[off:end])
	}

	return string(Name)
}

func UnPackAnswers(answers []byte, count int) []net.TCPAddr {
	IPList := make([]net.TCPAddr, 0)
	offset := 0
	for i := 0; i < count; i++ {
		for {
			length := binary.BigEndian.Uint16(answers[offset : offset+2])
			offset += 2
			if length > 0 && length < 63 {
				offset += int(length)
				if offset > len(answers)-2 {
					return nil
				}
			} else {
				break
			}
		}
		AType := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 4
		ttl := binary.BigEndian.Uint32(answers[offset : offset+4])
		offset += 4
		DataLength := binary.BigEndian.Uint16(answers[offset : offset+2])
		offset += 2

		if AType == TypeA {
			data := make([]byte, 4)
			copy(data, answers[offset:offset+4])
			TCPAddr := &net.TCPAddr{data, int(ttl), ""}
			IPList = append(IPList, *TCPAddr)
		} else if AType == TypeAAAA {
			data := make([]byte, 16)
			copy(data, answers[offset:offset+16])
			TCPAddr := &net.TCPAddr{data, int(ttl), ""}
			IPList = append(IPList, *TCPAddr)
		}
		offset += int(DataLength)
	}

	return IPList
}

type Resource struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type Answers struct {
	Expires int64
	ANCount uint16
	NSCount uint16
	ARCount uint16
	Answers []byte
}

var MaxExpires int64 = 0x7FFFFFFFFFFFFFFF
var NoAnswer Answers = Answers{MaxExpires, 0, 0, 0, nil}

func PackAnswers(IPList []net.IP) Answers {
	answers := make([]byte, 1024)
	length := 0
	for _, ip := range IPList {
		ip4 := ip.To4()
		if ip4 != nil {
			//A
			answer := []byte{0xC0, 0x0C, 0x00, byte(TypeA),
				0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
				ip4[0], ip4[1], ip4[2], ip4[3]}
			copy(answers[length:], answer)
			length += 16
		} else {
			answer := []byte{0xC0, 0x0C, 0x00, byte(TypeAAAA),
				0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x10}
			copy(answers[length:], answer)
			length += 12
			copy(answers[length:], ip)
			length += 16
		}
	}
	return Answers{MaxExpires, uint16(len(IPList)), 0, 0, answers[:length]}
}

func PackAnswersTTL(IPList []net.TCPAddr) Answers {
	answers := make([]byte, 1024)
	length := 0
	minttl := 0x7FFFFFFF
	for _, addr := range IPList {
		ttl := addr.Port
		if minttl > addr.Port {
			minttl = addr.Port
		}
		ip4 := addr.IP.To4()
		if ip4 != nil {
			answer := []byte{
				0xC0, 0x0C,
				0x00, byte(TypeA),
				0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x04,
				ip4[0], ip4[1], ip4[2], ip4[3]}
			binary.BigEndian.PutUint32(answer[6:], uint32(ttl))
			copy(answers[length:], answer)
			length += 16
		} else {
			answer := []byte{
				0xC0, 0x0C,
				0x00, byte(TypeAAAA),
				0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x10}
			binary.BigEndian.PutUint32(answer[6:], uint32(ttl))
			copy(answers[length:], answer)
			length += 12
			copy(answers[length:], addr.IP)
			length += 16
		}
	}
	return Answers{time.Now().Unix() + int64(minttl), uint16(len(IPList)), 0, 0, answers[:length]}
}

func BuildLie(ID int, Type uint16) Answers {
	answers := make([]byte, 1024)
	length := 0
	if Type == TypeA {
		answer := []byte{0xC0, 0x0C, 0x00, byte(TypeA),
			0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04,
			7, 0}
		copy(answers[length:], answer)
		length += 14
		binary.BigEndian.PutUint16(answers[length:], uint16(ID))
		length += 2
	} else if Type == TypeAAAA {
		answer := []byte{0xC0, 0x0C, 0x00, byte(TypeAAAA),
			0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10,
			0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00}
		copy(answers[length:], answer)
		length += 24
		binary.BigEndian.PutUint32(answers[length:], uint32(ID))
		length += 4
	}
	return Answers{MaxExpires, 1, 0, 0, answers[:length]}
}

func QuickResponse(Request []byte, answers Answers) []byte {
	length := len(Request)
	Response := make([]byte, 1024)
	copy(Response, Request)
	Response[2] = 0x81
	Response[3] = 0x80
	Response[7] = byte(answers.ANCount)
	Response[9] = byte(answers.NSCount)
	Response[11] = byte(answers.ARCount)
	if answers.ANCount > 0 {
		copy(Response[length:], answers.Answers)
		length += len(answers.Answers)
	}

	return Response[:length]
}

func PackRequest(header Header, question Question) []byte {
	Request := make([]byte, 512)
	binary.BigEndian.PutUint16(Request[:], header.ID)
	binary.BigEndian.PutUint16(Request[2:], header.Flag)
	//Request[2] = 0x81
	//Request[3] = 0x80
	binary.BigEndian.PutUint16(Request[4:], header.QDCount)
	binary.BigEndian.PutUint16(Request[6:], header.ANCount)
	binary.BigEndian.PutUint16(Request[8:], header.NSCount)
	binary.BigEndian.PutUint16(Request[10:], header.ARCount)
	qname := PackQName(question.QName)
	length := len(qname)
	copy(Request[12:], qname)
	length += 12
	binary.BigEndian.PutUint16(Request[length:], question.QType)
	length += 2
	binary.BigEndian.PutUint16(Request[length:], question.QClass)
	length += 2

	return Request[:length]
}

func PackResponse(header Header, question Question, answers Answers) []byte {
	Response := make([]byte, 1024)
	binary.BigEndian.PutUint16(Response[:], header.ID)
	Response[2] = 0x81
	Response[3] = 0x80
	binary.BigEndian.PutUint16(Response[4:], header.QDCount)
	binary.BigEndian.PutUint16(Response[6:], answers.ANCount)
	binary.BigEndian.PutUint16(Response[8:], answers.NSCount)
	binary.BigEndian.PutUint16(Response[10:], answers.ARCount)
	qname := PackQName(question.QName)
	length := len(qname)
	copy(Response[12:], qname)
	length += 12
	binary.BigEndian.PutUint16(Response[length:], question.QType)
	length += 2
	binary.BigEndian.PutUint16(Response[length:], question.QClass)
	length += 2
	if answers.ANCount > 0 {
		copy(Response[length:], answers.Answers)
		length += len(answers.Answers)
	}

	return Response[:length]
}

func TCPLookup(request []byte, address string) ([]byte, error) {
	server, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	data := make([]byte, 4096)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	_, err = server.Write(data[:len(request)+2])
	if err != nil {
		return nil, err
	}

	length := 0
	recvlen := 0
	for {
		n, err := server.Read(data[length:])
		if err != nil {
			return nil, err
		}
		if length == 0 {
			length = int(binary.BigEndian.Uint16(data[:2]) + 2)
		}
		recvlen += n
		if recvlen >= length {
			return data[2:recvlen], nil
		}
	}

	return nil, nil
}

func HTTPSLookup(qname string, qtype uint16, url string) ([]net.TCPAddr, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpsClient := &http.Client{
		Transport: tr,
	}
	url = strings.Replace(url, "[NAME]", qname, 1)

	switch qtype {
	case TypeA:
		url = strings.Replace(url, "[TYPE]", "A", 1)
	case TypeAAAA:
		url = strings.Replace(url, "[TYPE]", "AAAA", 1)
	default:
		return nil, nil
	}

	resp, err := httpsClient.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type Answer struct {
		Name string `json:"name"`
		Type uint16 `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	}

	type DNSHTTP struct {
		Answer []Answer
	}

	var HTTPAnswer = new(DNSHTTP)
	err = json.Unmarshal(body, &HTTPAnswer)
	if err != nil {
		return nil, err
	}

	//IPList := []net.IP{}
	IPList := make([]net.TCPAddr, 0)
	for _, ans := range HTTPAnswer.Answer {
		if ans.Type == TypeA || ans.Type == TypeAAAA {
			//var ip net.IP = net.ParseIP(ans.Data)
			IPList = append(IPList, net.TCPAddr{net.ParseIP(ans.Data), ans.TTL, ""})
		}
	}
	return IPList, nil
}

func DoHLookup(request []byte, host string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpsClient := &http.Client{
		Transport: tr,
	}
	url := host + base64.URLEncoding.EncodeToString(request)

	resp, err := httpsClient.Get(url)
	if err != nil {
		return nil, err
	}
	response, err := ioutil.ReadAll(resp.Body)
	copy(response[:], request[:2])
	return response, nil
}
