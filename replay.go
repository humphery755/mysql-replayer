package main

import (
	"encoding/binary"
	"regexp"
	"bytes"
	"flag"
	"fmt"
	"strings"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"math/rand"
	"os"
	"strconv"
	/*
	"context"
	
	"os/signal"*/

	"mysql-replayer/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ngaut/log"
)

var (
	transfer	   string
	username       string
	password       string
	host           string
	port           int
	pcapPort        string
	dbname         string
	sourcePcapFile string
	speed      int
	concurrent int
	qcount     int64

	workers        map[string]chan []byte
	reassemble_map map[string][]byte
	dsn            string
	deletes         chan string
)

var wg sync.WaitGroup

func init() {
	flag.StringVar(&transfer, "x", ":3306-127.0.0.1:3306", "use <transfer,> to specify the IPs and ports of the source and target. The format of <transfer,> could be as follow: 'sourceIP:sourcePort-targetIP:targetPort,...'. Most of the time, sourceIP could be omitted and thus <transfer,> could also be: sourcePort-targetIP:targetPort,...'.")
	flag.StringVar(&username, "u", "dmdb", "username of target database")
	flag.StringVar(&password, "p", "dmdb", "password of target database")
	flag.StringVar(&dbname, "db", "dmdb", "db name of target database")
	flag.StringVar(&sourcePcapFile, "i", "./147.pcap", "input-dir of source pcap files")
	flag.IntVar(&speed, "s", 1, "the bench speed")
	flag.IntVar(&concurrent, "c", 1, "the bench concurrent")
}

func mysql_packet_extract_sql(raw_packet []byte) string {
        sql := raw_packet[5:]
        in_str := false
        escape := false
        for i, _ := range sql {
                if sql[i] == '\'' && !escape {
                        in_str = !in_str
                } else if in_str && !escape && sql[i] == '\\' {
                        escape = true
                } else if in_str && escape {
                        sql[i] = '\\'
                        escape = false
                } else if in_str && sql[i] != '\'' {
                        sql[i] = 'M'
                        escape = false
                } else {
                        escape = false
                }
        }

        if true {
                pattern := regexp.MustCompile("'.*?'")
                ret := pattern.ReplaceAllFunc(sql, func(matches []byte) []byte {
                        //log.Debug("size %d", len(matches))
                        str_size := len(matches) - 2 - bytes.Count(matches, []byte("\\"))
                        return []byte(fmt.Sprintf("'char(%d)'", str_size))
                })
                return string(ret)
        }
        //return "a sql"
        return string(sql)
}

func worker_for_some_ip(key string, ch chan []byte) {
	wg.Add(1)
	defer func() {
		deletes <- key
		wg.Done()
	}()
	var seq_id byte = 0
	var stmt_id uint32 = 0
	var cmd byte
	
Retry:
	mysqlConn, err := mysql.Open(dsn)
	if err != nil {
		log.Errorf("open database err %v", err)
		num := time.Duration(rand.Int63n(1000))
		time.Sleep(num*time.Millisecond)
		goto Retry
	}
	defer mysqlConn.Close()

	log.Infof("new connection for %s", key)
	for {
		select {
		case packet, ok := <-ch:
			if !ok {
				log.Infof("workder %s done", key)
				return
			}
			
			packet = mysql_packet_set_seq_id(packet, seq_id)
			cmd = mysql_packet_get_cmd(packet)

			if cmd == mysql.COM_STMT_EXECUTE || cmd == mysql.COM_STMT_CLOSE {
				if stmt_id == 0 {
					log.Errorf("stmt_id is not initialized! stmt_id=%d, skip for %s!", stmt_id,key)
					continue
				}
				//log.Warnf("modify stmt_id = %d", stmt_id)
				packet = mysql_packet_set_stmt_id(packet, stmt_id)
			}
			n, err := mysqlConn.NetConn.Write(packet)
			if err == io.EOF {
				log.Errorf("write packet error %v", err)
				mysqlConn, _ = mysql.Open(dsn)
				packet = mysql_packet_set_seq_id(packet, seq_id)
				n, err = mysqlConn.NetConn.Write(packet)
			} else if err != nil {
				log.Errorf("write packet error %v", err)
			}
			if mysql_packet_get_cmd(packet) == mysql.COM_STMT_CLOSE {
				stmt_id = 0
			}
			mysqlConn.NetConn.SetReadDeadline(time.Now().Add(2*time.Second))
			buf := make([]byte, 65535)
			n, err = mysqlConn.NetConn.Read(buf)
			for  err != nil {
                log.Errorf("unkown %s", err)
				return
			}
			if cmd == mysql.COM_STMT_PREPARE {
				buf = buf[:n]
				if int(buf[4]) == 0 {
					stmt_id = binary.LittleEndian.Uint32(buf[5:9])
					//log.Warnf("prepare reply, set stmt_id=%d", stmt_id)
				} else {
					log.Errorf("prepare stmt error. packet => %s", string(buf[13:]))
				}
			}
			atomic.AddInt64(&qcount, 1)
		}
	}
}
//mysql-replay -host 172.20.11.106 -port 8865 -dbname dmdb -username dmdb -password dmdb -pcap-file ./147.pcap
func main() {
	flag.Parse()
	rand.Seed(time.Now().UnixNano())
	transferList := strings.Split(transfer, "-")
	if len(transferList) <= 1 {
		log.Errorf("address is invalid or not set: %s", transfer)
		os.Exit(1)
	}
	addr := strings.Split(transferList[0], ":")
	if len(addr) <= 1 {
		log.Errorf("src address is invalid or not set: %s", transferList[0])
		os.Exit(1)
	}
	pcapPort = addr[1]
	addr = strings.Split(transferList[1], ":")
	if len(addr) <= 1 {
		log.Errorf("dst address is invalid or not set: %s", transferList[1])
		os.Exit(1)
	}
	host = addr[0]
	port,_ = strconv.Atoi(addr[1])

	log.Infof("src pcap-file: %s :%s => %s:%d",sourcePcapFile,pcapPort,host,port)
	
	dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", username, password, host, port, dbname)
	log.Infof("mysql backend: %s",dsn)
	var handle *pcap.Handle
	var err error

	workers = make(map[string]chan []byte)
	reassemble_map = make(map[string][]byte)
	deletes = make(chan string, 256)

	if err != nil {
		panic(err)
	}

	if handle, err = pcap.OpenOffline(sourcePcapFile); err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	start := int64(time.Now().Unix())

	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}

	log.Info("send packets to goroutines over")

	//time.Sleep(655360*time.Millisecond)

	// wait goroutines to finish
	for _, worker_ch := range workers {
		close(worker_ch)
	}

	
	wg.Wait()
	/*
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	go func() {
		<-ch
		cancel()
	}()

	//os.Exit(int(subcommands.Execute(ctx)))
	*/
	end := int64(time.Now().Unix())
	delta := end - start

	// Avoid integer divide by zero
	if delta == 0 {
		delta = 1
	}
	count := atomic.LoadInt64(&qcount)
	fmt.Printf("Process %d request in %d seconds, QPS: %d\n", count, end-start, count/delta)
	
	log.Info("end play!!")
}

func mysql_packet_get_cmd(raw_packet []byte) byte {
	return raw_packet[4]
}

func mysql_packet_set_seq_id(raw_packet []byte, new_id byte) []byte {
	raw_packet[3] = new_id
	return raw_packet
}

func mysql_packet_set_stmt_id(raw_packet []byte, stmt_id uint32) []byte {
	if mysql_packet_get_cmd(raw_packet) == mysql.COM_STMT_EXECUTE || mysql_packet_get_cmd(raw_packet) == mysql.COM_STMT_CLOSE {
		binary.LittleEndian.PutUint32(raw_packet[5:9], stmt_id)
	}
	return raw_packet
}

func mysql_packet_get_payload_length(raw_packet []byte) int {
	return int(raw_packet[0]) + int(raw_packet[1])<<8 + int(raw_packet[2])<<16
}

func handlePacket(packet gopacket.Packet) {
	select {
	case key := <- deletes:
		delete(workers, key)
	default:
	}
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	key := fmt.Sprintf("%v:%d->%v:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	port1 := fmt.Sprintf("%d", tcp.DstPort)
	if port1 != pcapPort {
		key = fmt.Sprintf("%v:%d->%v:%d", ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)
	}
	//log.Debugf("%s",key);
	if tcp.FIN || tcp.RST {
		delete(reassemble_map, key)
		if ch, ok := workers[key]; ok {
			close(ch)
			delete(workers, key)
		}
		return
	}
	if len(tcp.Payload) == 0 || port1 != pcapPort {
		/*
		port1 := fmt.Sprintf("%d", tcp.SrcPort)
		if port1 != pcapPort {
			log.Errorf("%s nofound pcapPort: %s", key,pcapPort)
		}*/
		return
	}

	data := tcp.Payload
	if old_data, ok := reassemble_map[key]; ok {
		data = append(old_data, data...)
	}

	payload_length := mysql_packet_get_payload_length(data)
	cmd := mysql_packet_get_cmd(data)

	payload := data[4:]

	//log.Debugf("%s: got mysql packet cmd=%d len=%d pkt_len=%d",key, cmd, payload_length, len(payload))
	if payload_length > len(payload) {
		reassemble_map[key] = data
		log.Info("skip and wait for reassemble")
		return
	} else {
		delete(reassemble_map, key)
	}

	switch cmd {
	case mysql.COM_SLEEP, mysql.COM_QUIT, mysql.COM_PING, mysql.COM_FIELD_LIST, 133, 141:
	default:
		if ch, ok := workers[key]; ok {
			ch <- data
		} else {
			new_ch := make(chan []byte, 102400)
			//go worker_for_some_ip(key, new_ch)
			staticWorker(key, new_ch)
			workers[key] = new_ch
			new_ch <- data
		}
	}
}

func staticWorker(key string, ch chan []byte) {
	for i := 0; i < concurrent; i++ {
		go func() {
			worker_for_some_ip(key, ch)
		}()
	}
}