package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const frameHeaderSize = 4

// BatchMsg represents a batch notification sent from the agent.
type BatchMsg struct {
	Lane      string `json:"lane"`
	BatchSize int    `json:"batch_size"`
	MaxOffset uint64 `json:"max_offset"`
	FirstSeq  uint64 `json:"first_seq"`
	LastSeq   uint64 `json:"last_seq"`
}

// AckMsg represents an acknowledgement from the master.
type AckMsg struct {
	Lane      string `json:"lane"`
	MaxOffset uint64 `json:"max_offset"`
	BatchSize int    `json:"batch_size"`
}

// WriteFrame encodes v as JSON and writes it with a uint32 length prefix.
func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}

	if len(payload) == 0 {
		return fmt.Errorf("empty frame payload")
	}

	if len(payload) > int(^uint32(0)) {
		return fmt.Errorf("frame too large: %d bytes", len(payload))
	}

	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}

	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}

	return nil
}

// ReadFrame reads a length-prefixed JSON frame into v.
func ReadFrame(r io.Reader, v any) error {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}

	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return fmt.Errorf("invalid frame length: 0")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("read frame payload: %w", err)
	}

	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("unmarshal frame: %w", err)
	}

	return nil
}
