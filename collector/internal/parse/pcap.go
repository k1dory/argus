package parse

import (
	"encoding/binary"
	"errors"
	"io"
)

// PcapPayloads читает классический pcap (libpcap) и отдаёт UDP/TCP-полезную
// нагрузку каждого пакета: syslog/CEF, записанный tcpdump'ом на порту 514,
// можно прогнать через коллектор без живых источников. Linktype: Ethernet (1)
// и Linux cooked (113); IPv4; VLAN 802.1Q снимается.
func PcapPayloads(r io.Reader, fn func(payload []byte, srcIP string, dstPort uint16)) error {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(hdr[0:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.BigEndian
	default:
		return errors.New("pcap: неизвестная сигнатура (pcapng не поддерживается — сконвертируйте: tshark -F pcap)")
	}
	linktype := order.Uint32(hdr[20:24])
	rec := make([]byte, 16)
	for {
		if _, err := io.ReadFull(r, rec); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		capLen := order.Uint32(rec[8:12])
		if capLen > 256*1024 {
			return errors.New("pcap: слишком большой пакет")
		}
		pkt := make([]byte, capLen)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return err
		}
		var ip []byte
		switch linktype {
		case 1: // Ethernet
			if len(pkt) < 14 {
				continue
			}
			etype := binary.BigEndian.Uint16(pkt[12:14])
			off := 14
			for etype == 0x8100 || etype == 0x88a8 { // VLAN
				if len(pkt) < off+4 {
					break
				}
				etype = binary.BigEndian.Uint16(pkt[off+2 : off+4])
				off += 4
			}
			if etype != 0x0800 {
				continue
			}
			ip = pkt[off:]
		case 113: // Linux cooked
			if len(pkt) < 16 || binary.BigEndian.Uint16(pkt[14:16]) != 0x0800 {
				continue
			}
			ip = pkt[16:]
		case 101: // raw IP
			ip = pkt
		default:
			continue
		}
		if len(ip) < 20 || ip[0]>>4 != 4 {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+8 {
			continue
		}
		proto := ip[9]
		src := ipv4(ip[12:16])
		l4 := ip[ihl:]
		switch proto {
		case 17: // UDP: заголовок 8 байт
			dport := binary.BigEndian.Uint16(l4[2:4])
			if len(l4) > 8 {
				fn(l4[8:], src, dport)
			}
		case 6: // TCP: заголовок минимум 20 байт, data offset — в 12-м
			if len(l4) < 20 {
				continue
			}
			doff := int(l4[12]>>4) * 4
			if doff < 20 || len(l4) <= doff {
				continue
			}
			fn(l4[doff:], src, binary.BigEndian.Uint16(l4[2:4]))
		}
	}
}

func ipv4(b []byte) string {
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}
