package crafter

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Sends ICMP Echo Request
func SendICMPEcho(handle *pcap.Handle, srcMAC, dstMAC, srcIP, dstIP string, id, seq uint16) error {
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

	eth := layers.Ethernet{
		SrcMAC:       SrcMAC,
		DstMAC:       DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    SrcIP,
		DstIP:    DstIP,
	}

	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       id,
		Seq:      seq,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buffer, opts, &eth, &ip, &icmp)
	if err != nil {
		return err
	}

	return handle.WritePacketData(buffer.Bytes())
}

// Listens for ICMP Echo Reply
func ListenForICMPEchoReply(handle *pcap.Handle, dstIP string, id, seq uint16) error {
	DstIP := net.ParseIP(dstIP).To4()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(5 * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			// Step 2: Check source IP inside the loop
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip := ipLayer.(*layers.IPv4)
			if !ip.SrcIP.Equal(DstIP) {
				continue
			}

			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv4)

			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply &&
				icmp.Id == id && icmp.Seq == seq {
				return nil
			}

		case <-timeout:
			return fmt.Errorf("Timeout: no ICMP Echo Reply received.")
		}
	}
}
