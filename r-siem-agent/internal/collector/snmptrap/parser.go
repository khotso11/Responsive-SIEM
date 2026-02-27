package snmptrap

import "bytes"

func guessCommunity(payload []byte) string {
	lower := bytes.ToLower(payload)
	if bytes.Contains(lower, []byte("public")) {
		return "public"
	}
	if bytes.Contains(lower, []byte("private")) {
		return "private"
	}
	return ""
}

func guessVersion(payload []byte) string {
	// Best-effort only: scan early bytes for ASN.1 INTEGER version marker.
	max := len(payload)
	if max > 32 {
		max = 32
	}
	for i := 0; i+2 < max; i++ {
		if payload[i] == 0x02 && payload[i+1] == 0x01 {
			switch payload[i+2] {
			case 0:
				return "1"
			case 1:
				return "2c"
			case 3:
				return "3"
			}
		}
	}
	return ""
}
