package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"unicode"

	"github.com/nats-io/nats.go"
)

func main() {
	natsURL := flag.String("nats-url", "nats://127.0.0.1:4222", "NATS JetStream URL")
	stream := flag.String("stream", "RSIEM", "Stream name")
	count := flag.Uint64("count", 10, "Number of most recent messages to fetch")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nc, err := nats.Connect(*natsURL, nats.Name("r-siem-master-inspect"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		fmt.Fprintf(os.Stderr, "jetstream: %v\n", err)
		os.Exit(1)
	}

	info, err := js.StreamInfo(*stream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stream info: %v\n", err)
		os.Exit(1)
	}

	state := info.State
	fmt.Printf("Stream %s: msgs=%d bytes=%d first_seq=%d last_seq=%d\n",
		*stream, state.Msgs, state.Bytes, state.FirstSeq, state.LastSeq)

	if state.LastSeq == 0 || *count == 0 {
		return
	}

	start := state.LastSeq + 1 - min(*count, state.LastSeq)
	for seq := start; seq <= state.LastSeq; seq++ {
		msg, err := js.GetMsg(*stream, seq, nats.Context(ctx))
		if err != nil {
			fmt.Fprintf(os.Stderr, "get msg %d: %v\n", seq, err)
			continue
		}

		preview := payloadPreview(msg.Data, 80)
		fmt.Printf("seq=%d subject=%s size=%d data=%s\n", msg.Sequence, msg.Subject, len(msg.Data), preview)
	}
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func payloadPreview(data []byte, limit int) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) > limit {
		data = data[:limit]
	}
	printable := true
	for _, b := range data {
		if !unicode.IsPrint(rune(b)) && b != '\n' && b != '\r' && b != '\t' {
			printable = false
			break
		}
	}
	if printable {
		return fmt.Sprintf("%q", string(data))
	}
	return hex.EncodeToString(data)
}
