package common

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type queuedMessage struct {
	Seq     uint64 `json:"seq"`
	EventID string `json:"event_id"`
	DataB64 string `json:"data_b64"`
}

type messageSpool struct {
	mu         sync.Mutex
	file       *os.File
	path       string
	commitPath string
	fsync      bool
	nextSeq    uint64
	committed  uint64
}

func openMessageSpool(path string, fsync bool) (*messageSpool, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create spool directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	spool := &messageSpool{
		file:       file,
		path:       path,
		commitPath: path + ".commit",
		fsync:      fsync,
		nextSeq:    1,
	}
	if err := spool.loadCommitted(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := spool.loadNextSeq(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return spool, nil
}

func (s *messageSpool) loadCommitted() error {
	data, err := os.ReadFile(s.commitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read spool commit: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return nil
	}
	seq, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("parse spool commit: %w", err)
	}
	s.committed = seq
	return nil
}

func (s *messageSpool) loadNextSeq() error {
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek spool: %w", err)
	}
	defer s.file.Seek(0, 2)

	reader := bufio.NewReader(s.file)
	var maxSeq uint64
	var (
		offset         int64
		lastGoodOffset int64
		lineNumber     int
	)
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("scan spool: %w", err)
		}
		if len(lineBytes) == 0 && errors.Is(err, io.EOF) {
			break
		}

		lineNumber++
		nextOffset := offset + int64(len(lineBytes))
		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			offset = nextOffset
			lastGoodOffset = nextOffset
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}
		var msg queuedMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			if repairErr := s.repairCorruptTail(lastGoodOffset, lineNumber, err); repairErr != nil {
				return repairErr
			}
			break
		}
		if msg.Seq > maxSeq {
			maxSeq = msg.Seq
		}
		offset = nextOffset
		lastGoodOffset = nextOffset
		if errors.Is(err, io.EOF) {
			break
		}
	}

	s.nextSeq = maxSeq + 1
	if s.committed >= maxSeq {
		s.nextSeq = s.committed + 1
	}
	if s.nextSeq == 0 {
		s.nextSeq = 1
	}
	return nil
}

func (s *messageSpool) repairCorruptTail(lastGoodOffset int64, lineNumber int, decodeErr error) error {
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek spool for repair: %w", err)
	}
	backupPath := fmt.Sprintf("%s.corrupt.%d", s.path, time.Now().UnixNano())
	backup, err := os.OpenFile(backupPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("backup corrupt spool: %w", err)
	}
	if _, err := io.Copy(backup, s.file); err != nil {
		_ = backup.Close()
		return fmt.Errorf("copy corrupt spool backup: %w", err)
	}
	if err := backup.Close(); err != nil {
		return fmt.Errorf("close corrupt spool backup: %w", err)
	}
	if err := s.file.Truncate(lastGoodOffset); err != nil {
		return fmt.Errorf("truncate corrupt spool after backup: %w", err)
	}
	if _, err := s.file.Seek(lastGoodOffset, 0); err != nil {
		return fmt.Errorf("seek repaired spool: %w", err)
	}
	return nil
}

func (s *messageSpool) Append(eventID string, data []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.nextSeq
	rec := queuedMessage{Seq: seq, EventID: strings.TrimSpace(eventID), DataB64: base64.StdEncoding.EncodeToString(data)}
	line, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("encode spool record: %w", err)
	}
	if _, err := s.file.Write(append(line, '\n')); err != nil {
		return 0, fmt.Errorf("write spool record: %w", err)
	}
	if s.fsync {
		if err := s.file.Sync(); err != nil {
			return 0, fmt.Errorf("fsync spool: %w", err)
		}
	}
	s.nextSeq++
	return seq, nil
}

func (s *messageSpool) ReplayUncommitted(fn func(seq uint64, eventID string, data []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek spool start: %w", err)
	}
	defer s.file.Seek(0, 2)
	scanner := bufio.NewScanner(s.file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg queuedMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			return fmt.Errorf("decode spool record: %w", err)
		}
		if msg.Seq <= s.committed {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(msg.DataB64)
		if err != nil {
			return fmt.Errorf("decode spool payload: %w", err)
		}
		if err := fn(msg.Seq, msg.EventID, data); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan spool: %w", err)
	}
	return nil
}

func (s *messageSpool) MarkCommittedUpTo(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.committed {
		return nil
	}
	file, err := os.OpenFile(s.commitPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open spool commit: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%d\n", seq); err != nil {
		_ = file.Close()
		return fmt.Errorf("write spool commit: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("fsync spool commit: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close spool commit: %w", err)
	}
	s.committed = seq
	return nil
}

func (s *messageSpool) HasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.committed+1 < s.nextSeq
}

func (s *messageSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
