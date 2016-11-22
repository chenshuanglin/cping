package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"
)

type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
}

type Cping struct {
	Icmp ICMP
	Src  *net.IPAddr
	Dst  *net.IPAddr
}

var usage = `Usage: cping [option...] <url>


option:
    -s    Src ip or rand, Default is 0.0.0.0
    -d    Dst ip or rand
    -c    Number of requests to run. Default is 0
`

var (
	s = flag.String("s", "0.0.0.0", "Src ip")
	d = flag.String("d", "", "Dst ip is need")
	c = flag.Int("c", 0, "Number of requests to run")
)

var (
	reqs = make(chan struct{})
	stop = make(chan os.Signal, 1)
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}
	flag.Parse()
	signal.Notify(stop, os.Interrupt)

	go PrintMessage()

	if *c == 0 {
		for {
			Ping()
		}
	} else {
		for i := 0; i < *c; i++ {
			Ping()
		}
	}
}

func PrintMessage() {
	number := 0
	for {
		select {
		case <-stop:
			log.Fatalln("中断运行")
		case <-reqs:
			number++
			fmt.Printf("第%d次发送数据\n", number)
		}
	}
}

//获取cping对象，并每隔500ms，ping一次
func Ping() {
	cping := GetCping()
	cping.Send()
	time.Sleep(500 * time.Millisecond)
}

//获取连接，发送数据
func (cping *Cping) Send() {
	conn, err := net.DialIP("ip4:icmp", cping.Src, cping.Dst)
	if err != nil {
		ErrorMessage(fmt.Sprintf("Conn ipv4 icmp err: %v\n", err))
		return
	}
	defer conn.Close()
	var buffer bytes.Buffer
	//用大端的模式，把icmp包写到buffer中。
	binary.Write(&buffer, binary.BigEndian, cping.Icmp)
	if _, err := conn.Write(buffer.Bytes()); err != nil {
		ErrorMessage(fmt.Sprintf("Write buffer error : %v\n", err))
		return
	}
	reqs <- struct{}{}
}

//计算校验和
func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}

func ErrorMessage(s string) {
	fmt.Fprint(os.Stderr, s)
}

//返回一个随机ip，go可以直接返回局部变量的指针
func GetRandIp() *net.IPAddr {
	ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1)
	return &net.IPAddr{IP: net.ParseIP(ip)}
}

//根据命令参数获取ip，会判断是否是随机
func GetIP(str string) *net.IPAddr {
	var ip *net.IPAddr
	if strings.EqualFold(str, "rand") {
		ip = GetRandIp()
	} else {
		ip = &net.IPAddr{IP: net.ParseIP(str)}
	}
	return ip
}

//获取一个Cping的对象
func GetCping() *Cping {
	var icmp ICMP
	var buffer bytes.Buffer

	icmp.Type = 8
	icmp.Code = 0
	icmp.Identifier = 0
	icmp.SequenceNum = 0
	binary.Write(&buffer, binary.BigEndian, icmp)
	icmp.Checksum = CheckSum(buffer.Bytes())

	return &Cping{
		Icmp: icmp,
		Src:  GetIP(*s),
		Dst:  GetIP(*d),
	}
}
