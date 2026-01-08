package wal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"r-siem-agent/internal/event"
)

// WAL implements a simple length-prefixed JSON write-ahead log.
type WAL struct {
	mu         sync.Mutex
	file       *os.File
	path       string
	commitPath string
	fsync      bool
	nextOffset uint64
	committed  uint64
}

// Open initializes or resumes a WAL at the provided path.
func Open(path string, fsync bool) (*WAL, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create wal directory: %w", err)
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open wal: %w", err)
	}

	w := &WAL{
		file:       file,
		path:       path,
		commitPath: path + ".commit",
		fsync:      fsync,
	}

	if err := w.loadCommitted(); err != nil {
		file.Close()
		return nil, err
	}

	count, err := w.countExisting()
	if err != nil {
		file.Close()
		return nil, err
	}
	w.nextOffset = count + 1

	return w, nil
}

func (w *WAL) countExisting() (uint64, error) {
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek wal: %w", err)
	}

	var count uint64
	for {
		var length uint32
		if err := binary.Read(w.file, binary.BigEndian, &length); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, fmt.Errorf("read wal length: %w", err)
		}

		if length == 0 {
			return 0, fmt.Errorf("invalid wal record length 0")
		}

		if _, err := w.file.Seek(int64(length), io.SeekCurrent); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, fmt.Errorf("truncated wal record")
			}
			return 0, fmt.Errorf("skip wal record: %w", err)
		}

		count++
	}

	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return 0, fmt.Errorf("seek wal end: %w", err)
	}

	return count, nil
}

// Append writes an event to the WAL and returns its offset.
func (w *WAL) Append(evt event.Event) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	offset := w.nextOffset
	evt.WALOffset = offset

	data, err := json.Marshal(evt)
	if err != nil {
		return 0, fmt.Errorf("encode wal record: %w", err)
	}

	if len(data) == 0 {
		return 0, fmt.Errorf("empty wal event")
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(data))); err != nil {
		return 0, fmt.Errorf("encode wal length: %w", err)
	}
	if _, err := buf.Write(data); err != nil {
		return 0, fmt.Errorf("buffer wal record: %w", err)
	}

	if _, err := w.file.Write(buf.Bytes()); err != nil {
		return 0, fmt.Errorf("write wal record: %w", err)
	}

	if w.fsync {
		if err := w.file.Sync(); err != nil {
			return 0, fmt.Errorf("fsync wal: %w", err)
		}
	}

	w.nextOffset++
	return offset, nil
}

// ReplayUncommitted iterates over all records and invokes fn per event.
func (w *WAL) ReplayUncommitted(fn func(event.Event) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek wal: %w", err)
	}

	offset := uint64(1)
	for {
		var length uint32
		if err := binary.Read(w.file, binary.BigEndian, &length); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read wal length: %w", err)
		}

		if length == 0 {
			return fmt.Errorf("invalid wal record length 0")
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(w.file, payload); err != nil {
			return fmt.Errorf("read wal payload: %w", err)
		}

		if offset <= w.committed {
			offset++
			continue
		}

		var evt event.Event
		if err := json.Unmarshal(payload, &evt); err != nil {
			return fmt.Errorf("decode wal payload: %w", err)
		}

		if evt.WALOffset == 0 {
			evt.WALOffset = offset
		}

		if err := fn(evt); err != nil {
			return err
		}

		offset++
	}

	if _, err := w.file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek wal end: %w", err)
	}

	return nil
}

func (w *WAL) MarkCommittedUpTo(offset uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if offset <= w.committed {
		return nil
	}

	if err := w.writeCommitFile(offset); err != nil {
		return err
	}

	w.committed = offset
	return nil
}

// Close flushes and closes the underlying WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

func (w *WAL) loadCommitted() error {
	data, err := os.ReadFile(w.commitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read wal commit: %w", err)
	}

	str := strings.TrimSpace(string(data))
	if str == "" {
		return nil
	}

	val, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return fmt.Errorf("parse wal commit: %w", err)
	}

	w.committed = val
	return nil
}

func (w *WAL) writeCommitFile(offset uint64) error {
	f, err := os.OpenFile(w.commitPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open wal commit: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%d\n", offset); err != nil {
		return fmt.Errorf("write wal commit: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync wal commit: %w", err)
	}

	return nil
}
