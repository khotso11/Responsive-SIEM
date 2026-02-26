package netflowv5

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	nf5HeaderLen = 24
	nf5RecordLen = 48
)

type header struct {
	Version      uint16
	Count        uint16
	SysUptimeMs  uint32
	UnixSecs     uint32
	UnixNSecs    uint32
	FlowSequence uint32
}

type record struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	Proto    uint8
	Packets  uint32
	Bytes    uint32
	FirstMs  uint32
	LastMs   uint32
	Raw      []byte
}

func parsePacket(data []byte) (header, []record, error) {
	if len(data) < nf5HeaderLen {
		return header{}, nil, fmt.Errorf("short netflow header: %d", len(data))
	}
	h := header{
		Version:      binary.BigEndian.Uint16(data[0:2]),
		Count:        binary.BigEndian.Uint16(data[2:4]),
		SysUptimeMs:  binary.BigEndian.Uint32(data[4:8]),
		UnixSecs:     binary.BigEndian.Uint32(data[8:12]),
		UnixNSecs:    binary.BigEndian.Uint32(data[12:16]),
		FlowSequence: binary.BigEndian.Uint32(data[16:20]),
	}
	if h.Version != 5 {
		return header{}, nil, fmt.Errorf("unsupported netflow version: %d", h.Version)
	}
	expected := nf5HeaderLen + int(h.Count)*nf5RecordLen
	if len(data) < expected {
		return header{}, nil, fmt.Errorf("short netflow packet: count=%d len=%d expected>=%d", h.Count, len(data), expected)
	}
	recs := make([]record, 0, h.Count)
	off := nf5HeaderLen
	for i := 0; i < int(h.Count); i++ {
		raw := make([]byte, nf5RecordLen)
		copy(raw, data[off:off+nf5RecordLen])
		src := net.IP(data[off : off+4]).String()
		dst := net.IP(data[off+4 : off+8]).String()
		recs = append(recs, record{
			SrcIP:    src,
			DstIP:    dst,
			Packets:  binary.BigEndian.Uint32(data[off+16 : off+20]),
			Bytes:    binary.BigEndian.Uint32(data[off+20 : off+24]),
			FirstMs:  binary.BigEndian.Uint32(data[off+24 : off+28]),
			LastMs:   binary.BigEndian.Uint32(data[off+28 : off+32]),
			SrcPort:  binary.BigEndian.Uint16(data[off+32 : off+34]),
			DstPort:  binary.BigEndian.Uint16(data[off+34 : off+36]),
			TCPFlags: data[off+37],
			Proto:    data[off+38],
			Raw:      raw,
		})
		off += nf5RecordLen
	}
	return h, recs, nil
}

func deriveEventTSUnixMs(h header, r record, recvTsUnixMs int64) int64 {
	exportMs := int64(h.UnixSecs)*1000 + int64(h.UnixNSecs)/1_000_000
	if exportMs <= 0 {
		exportMs = recvTsUnixMs
	}
	if h.SysUptimeMs == 0 {
		return exportMs
	}
	if r.LastMs > h.SysUptimeMs {
		return exportMs
	}
	delta := int64(h.SysUptimeMs - r.LastMs)
	eventMs := exportMs - delta
	if eventMs <= 0 {
		return exportMs
	}
	return eventMs
}
