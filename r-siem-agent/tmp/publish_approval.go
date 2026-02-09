package main

import (
	"fmt"
	"os"

	"github.com/nats-io/nats.go"
)

func main() {
	runID := os.Getenv("RUN_ID")
	if runID == "" {
		fmt.Fprintln(os.Stderr, "RUN_ID is required")
		os.Exit(1)
	}
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = nats.DefaultURL
	}

	payload := fmt.Sprintf(`{"run_id":"%s","decision":"approve","actor":"khotso"}`, runID)

	nc, err := nats.Connect(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect failed:", err)
		os.Exit(1)
	}
	defer nc.Drain()

	subj := "rsiem.response.approvals"
	if err := nc.Publish(subj, []byte(payload)); err != nil {
		fmt.Fprintln(os.Stderr, "publish failed:", err)
		os.Exit(1)
	}
	nc.Flush()

	fmt.Println("OK published approval:", payload)
}
