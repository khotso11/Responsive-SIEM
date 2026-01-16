package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nats-io/nats.go"

	"r-siem-agent/internal/config"
	"r-siem-agent/internal/logging"
)

type commandRequest struct {
	RunID  string         `json:"run_id"`
	StepID string         `json:"step_id"`
	Lane   string         `json:"lane"`
	Params map[string]any `json:"params"`
}

type commandReply struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func main() {
	configPath := flag.String("config", "configs/master.yaml", "Path to master config")
	flag.Parse()

	baseCfg, err := config.LoadMaster(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.NewLogger(baseCfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}

	subject := strings.TrimSpace(os.Getenv("RSIEM_AGENT_CMD_SUBJECT"))
	if subject == "" {
		subject = "rsiem.agent.command"
	}

	nc, err := nats.Connect(baseCfg.JetStream.URL, nats.Name("r-siem-agent-sim"))
	if err != nil {
		logger.Error("nats_connect_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer nc.Close()

	_, err = nc.Subscribe(subject, func(msg *nats.Msg) {
		if msg.Reply == "" {
			return
		}
		var req commandRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			return
		}
		status := "ok"
		if force := stringParam(req.Params, "force"); force != "" {
			switch strings.ToLower(force) {
			case "safe":
				status = "fail_safe"
			case "transient":
				status = "fail_transient"
			}
		}
		reply := commandReply{Status: status}
		data, err := json.Marshal(reply)
		if err != nil {
			return
		}
		_ = nc.Publish(msg.Reply, data)
		logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_sim_reply",
			slog.String("run_id", strings.TrimSpace(req.RunID)),
			slog.String("step_id", strings.TrimSpace(req.StepID)),
			slog.String("status", status),
		)
	})
	if err != nil {
		logger.Error("agent_sim_subscribe_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if err := nc.Flush(); err != nil {
		logger.Error("agent_sim_flush_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "agent_sim_listening",
		slog.String("subject", subject),
	)

	ctx, cancel := signalContext()
	defer cancel()
	<-ctx.Done()
}

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	val, ok := params[key]
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()
	return ctx, cancel
}
