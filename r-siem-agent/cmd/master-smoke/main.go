package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"r-siem-agent/internal/proto/pb"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7777", "Master address")
	ca := flag.String("ca", "configs/certs/ca.pem", "CA certificate path")
	cert := flag.String("cert", "configs/certs/agent.pem", "Client certificate path")
	key := flag.String("key", "configs/certs/agent-key.pem", "Client private key path")
	serverName := flag.String("server-name", "master.local", "Expected master server name")
	flag.Parse()

	creds, err := clientCredentials(*ca, *cert, *key, *serverName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls setup: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial master: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewIngestClient(conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open stream: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UnixMilli()
	payload1, err := json.Marshal(map[string]any{
		"ts_unix_ms": now,
		"type":       "process",
		"severity":   "medium",
		"host":       "win10-lab",
		"user":       "bob",
		"process":    "powershell.exe",
		"src_ip":     "10.0.0.12",
		"dst_ip":     "10.0.0.5",
		"message":    "smoke process burst 1",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal batch 1: %v\n", err)
		os.Exit(1)
	}
	payload2, err := json.Marshal(map[string]any{
		"ts_unix_ms": now + 1,
		"type":       "process",
		"severity":   "medium",
		"host":       "win10-lab",
		"user":       "bob",
		"process":    "powershell.exe",
		"src_ip":     "10.0.0.12",
		"dst_ip":     "10.0.0.5",
		"message":    "smoke process burst 2",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal batch 2: %v\n", err)
		os.Exit(1)
	}
	payload3, err := json.Marshal(map[string]any{
		"ts_unix_ms": now + 2,
		"type":       "process",
		"severity":   "medium",
		"host":       "win10-lab",
		"user":       "bob",
		"process":    "powershell.exe",
		"src_ip":     "10.0.0.12",
		"dst_ip":     "10.0.0.5",
		"message":    "smoke process burst 3",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal batch 3: %v\n", err)
		os.Exit(1)
	}
	payload4, err := json.Marshal(map[string]any{
		"ts_unix_ms": now + 3,
		"type":       "network",
		"severity":   "high",
		"host":       "win10-lab",
		"src_ip":     "10.0.0.12",
		"dst_ip":     "8.8.8.8",
		"message":    "smoke network after process",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal batch 4: %v\n", err)
		os.Exit(1)
	}
	payload5, err := json.Marshal(map[string]any{
		"ts_unix_ms": now + 4,
		"type":       "network",
		"severity":   "low",
		"host":       "edge-fw",
		"src_ip":     "10.0.0.12",
		"dst_ip":     "8.8.8.8",
		"message":    "smoke network join",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal batch 5: %v\n", err)
		os.Exit(1)
	}

	batches := []*pb.Batch{
		{
			TenantId:   "tenant-1",
			ProducerId: "smoke-client",
			StreamId:   "stream-1",
			Lane:       "STANDARD",
			SeqStart:   1,
			SeqEnd:     1,
			Payload:    payload1,
		},
		{
			TenantId:   "tenant-1",
			ProducerId: "smoke-client",
			StreamId:   "stream-1",
			Lane:       "FAST",
			SeqStart:   2,
			SeqEnd:     2,
			Payload:    payload2,
		},
		{
			TenantId:   "tenant-1",
			ProducerId: "smoke-client",
			StreamId:   "stream-1",
			Lane:       "FAST",
			SeqStart:   3,
			SeqEnd:     3,
			Payload:    payload3,
		},
		{
			TenantId:   "tenant-1",
			ProducerId: "smoke-client",
			StreamId:   "stream-1",
			Lane:       "STANDARD",
			SeqStart:   4,
			SeqEnd:     4,
			Payload:    payload4,
		},
		{
			TenantId:   "tenant-1",
			ProducerId: "smoke-client",
			StreamId:   "stream-1",
			Lane:       "STANDARD",
			SeqStart:   5,
			SeqEnd:     5,
			Payload:    payload5,
		},
	}

	for _, batch := range batches {
		if err := stream.Send(batch); err != nil {
			fmt.Fprintf(os.Stderr, "send batch: %v\n", err)
			os.Exit(1)
		}

		ack, err := stream.Recv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "receive ack: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("ACK lane=%s seq_end=%d js_seq=%d\n", ack.GetLane(), ack.GetSeqEnd(), ack.GetJsSeq())
	}
}

func clientCredentials(caPath, certPath, keyPath, serverName string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("append ca failed")
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}), nil
}
