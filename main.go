package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var ethernet = flag.String("i", "", "interface")
var number = flag.Int("n", 3, "Number of RST packets sent")
var host = flag.String("host", "", "host")
var port = flag.Int("port", 0, "port")
var srcHost = flag.String("shost", "", "src host")
var dstHost = flag.String("dhost", "", "dst host")
var srcPort = flag.Int("sport", 0, "src port")
var dstPort = flag.Int("dport", 0, "dst port")
var timeout = flag.Int("timeout", 0, "timeout")

func init() {
	flag.Parse()
	if len(*ethernet) == 0 {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		if len(devs) == 0 {
			log.Fatal("interface is not found,please select the interface manually.")
		}
		*ethernet = devs[0].Name
	}
}

func wall() error {

	fmt.Printf("tcpwall linsten on %v\r\n", *ethernet)

	var handle *pcap.Handle
	var err error
	if handle, err = pcap.OpenLive(*ethernet, int32(65535), true, -1*time.Second); err != nil {
		return err
	}
	defer handle.Close()

	var filters []string

	if len(*host) > 0 {
		filters = append(filters, "host "+*host)
	}

	if *port > 0 && *port <= 65535 {
		filters = append(filters, "port "+strconv.Itoa(*port))
	}

	if len(*srcHost) > 0 {
		filters = append(filters, "src host "+*srcHost)
	}

	if *srcPort > 0 && *srcPort <= 65535 {
		filters = append(filters, "src port "+strconv.Itoa(*srcPort))
	}

	if len(*dstHost) > 0 {
		filters = append(filters, "dst host "+*dstHost)
	}

	if *dstPort > 0 && *dstPort <= 65535 {
		filters = append(filters, "dst port "+strconv.Itoa(*dstPort))
	}

	if len(filters) == 0 {
		log.Fatal("you entered the wrong parameters.")
	}

	filter := strings.Join(filters, " and ")

	if err := handle.SetBPFFilter(filter); err != nil {
		return err
	}

	if len(*srcHost) > 0 && len(*dstHost) > 0 && *srcPort > 0 && *srcPort <= 65535 && *dstPort > 0 && *dstPort <= 65535 {
		go func() {
			var seq uint32 = 10010
			if err := SendSYN(net.ParseIP(*srcHost), net.ParseIP(*dstHost), layers.TCPPort(*srcPort), layers.TCPPort(*dstPort), seq, handle); err != nil {
				log.Fatal(err)
			}

			if err := SendSYN(net.ParseIP(*dstHost), net.ParseIP(*srcHost), layers.TCPPort(*dstPort), layers.TCPPort(*srcPort), seq, handle); err != nil {
				log.Fatal(err)
			}
		}()
	}

	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	if *timeout > 0 {
		go func() {
			if err := capture(packetSource, handle); err != nil {
				log.Fatal(err)
			}
		}()

		time.Sleep(time.Duration(*timeout) * time.Second)
	} else {
		if err := capture(packetSource, handle); err != nil {
			return err
		}
	}

	return nil
}

func capture(packetSource *gopacket.PacketSource, handle *pcap.Handle) error {
	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer == nil {
			continue
		}
		ip := ipv4Layer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		if tcp.SYN || tcp.FIN || tcp.RST {
			continue
		}

		for i := 0; i < *number; i++ {

			seq := tcp.Ack + uint32(i)*uint32(tcp.Window)

			err := SendRST(eth.DstMAC, eth.SrcMAC, ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort, seq, handle)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func SendSYN(srcIp, dstIp net.IP, srcPort, dstPort layers.TCPPort, seq uint32, handle *pcap.Handle) error {
	log.Printf("send %v:%v > %v:%v [SYN] seq %v", srcIp.String(), srcPort.String(), dstIp.String(), dstPort.String(), seq)
	iPv4 := layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		SYN:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&iPv4); err != nil {
		return err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options, &tcp); err != nil {
		return err
	}

	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func SendRST(srcMac, dstMac net.HardwareAddr, srcIp, dstIp net.IP, srcPort, dstPort layers.TCPPort, seq uint32, handle *pcap.Handle) error {
	log.Printf("send %v:%v > %v:%v [RST] seq %v", srcIp.String(), srcPort.String(), dstIp.String(), dstPort.String(), seq)

	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	iPv4 := layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		RST:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&iPv4); err != nil {
		return err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options, &eth, &iPv4, &tcp); err != nil {
		return err
	}

	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func main() {
	if err := wall(); err != nil {
		log.Fatal(err)
	}
}
