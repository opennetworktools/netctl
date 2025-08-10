package crafter

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func SendTCPSYN(handle *pcap.Handle, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort, ttl int) error {
	SrcMAC, err := net.ParseMAC(srcMAC)
	if err != nil {
		return err
	}
	DstMAC, err := net.ParseMAC(dstMAC)
	if err != nil {
		return err
	}
	SrcIP := net.ParseIP(srcIP).To4()
	DstIP := net.ParseIP(dstIP).To4()
	SrcPort := layers.TCPPort(srcPort)
	DstPort := layers.TCPPort(dstPort)

	eth := layers.Ethernet{
		SrcMAC:       SrcMAC,
		DstMAC:       DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      uint8(ttl),
		Protocol: layers.IPProtocolTCP,
		SrcIP:    SrcIP,
		DstIP:    DstIP,
	}

	tcp := layers.TCP{
		SrcPort: SrcPort,
		DstPort: DstPort,
		SYN:     true,
		Seq:     12345678,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp); err != nil {
		return err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	fmt.Printf("SYN sent to %v:%v\n", DstIP, DstPort)
	return nil
}

func ListenForTCPSYNACKOrRST(handle *pcap.Handle, expectedSrcIP, expectedDstIP string, expectedSrcPort, expectedDstPort int) error {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	timeout := time.After(5 * time.Second)

	for {
		select {
		case packet := <-packets:
			if packet == nil {
				continue
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			if ip.SrcIP.String() == expectedDstIP &&
				ip.DstIP.String() == expectedSrcIP &&
				int(tcp.SrcPort) == expectedDstPort &&
				int(tcp.DstPort) == expectedSrcPort {

				if tcp.SYN && tcp.ACK {
					fmt.Printf("SYN-ACK received from %s:%d\n", ip.SrcIP, tcp.SrcPort)
					return nil
				}

				if tcp.RST && tcp.ACK {
					fmt.Printf("RST-ACK received from %s:%d\n", ip.SrcIP, tcp.SrcPort)
					return nil
				}
			}

		case <-timeout:
			return fmt.Errorf("timed out waiting for SYN-ACK or RST-ACK")
		}
	}
}
