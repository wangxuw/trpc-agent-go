//
// Tencent is pleased to support the open source community by making
// trpc-agent-go available.
//
// Copyright (C) 2026 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package e2b

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"trpc.group/trpc-go/trpc-agent-go/codeexecutor"
	ci "trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/codeinterpreter"
	"trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/envdprocess"
)

const (
	defaultInteractiveMaxLines  = 20_000
	defaultInteractiveIOTimeout = 5 * time.Second
)

var errInteractiveTTYUnsupported = errors.New(
	"e2b: interactive TTY is not supported",
)

type interactiveSession struct {
	id      string
	process *envdprocess.Process
	started time.Time
	done    chan struct{}

	mu            sync.Mutex
	result        envdprocess.Result
	waitErr       error
	finished      bool
	finishedAt    time.Time
	closed        bool
	observedBytes int
	lineBase      int
	lines         []string
	partial       string
	pollCursor    int
	maxLines      int
	closeOnce     sync.Once
}

func newInteractiveSession(
	process *envdprocess.Process,
) *interactiveSession {
	return &interactiveSession{
		id:       uuid.NewString(),
		process:  process,
		started:  time.Now(),
		done:     make(chan struct{}),
		maxLines: defaultInteractiveMaxLines,
	}
}

func (s *interactiveSession) ID() string { return s.id }

func (s *interactiveSession) Poll(
	limit *int,
) codeexecutor.ProgramPoll {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()

	start := s.pollCursor
	if start < s.lineBase {
		start = s.lineBase
		s.pollCursor = start
	}
	end := s.lineBase + len(s.lines)
	if limit != nil && *limit > 0 {
		if want := start + *limit; want < end {
			end = want
		}
	}
	output := s.outputLocked(start, end)
	s.pollCursor = end

	poll := codeexecutor.ProgramPoll{
		Status:     codeexecutor.ProgramStatusRunning,
		Output:     output,
		Offset:     start,
		NextOffset: end,
	}
	if s.finished {
		poll.Status = codeexecutor.ProgramStatusExited
		exitCode := s.exitCodeLocked()
		poll.ExitCode = &exitCode
	}
	return poll
}

func (s *interactiveSession) Log(
	offset *int,
	limit *int,
) codeexecutor.ProgramLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()

	start := s.lineBase
	end := s.lineBase + len(s.lines)
	if offset != nil {
		start = *offset
	}
	if start < s.lineBase {
		start = s.lineBase
	}
	if start > end {
		start = end
	}
	if limit != nil && *limit > 0 {
		if want := start + *limit; want < end {
			end = want
		}
	}
	return codeexecutor.ProgramLog{
		Output:     s.outputLocked(start, end),
		Offset:     start,
		NextOffset: end,
	}
}

func (s *interactiveSession) Write(
	data string,
	newline bool,
) error {
	if data == "" && !newline {
		return nil
	}
	s.mu.Lock()
	s.refreshLocked()
	running := !s.finished && !s.closed
	s.mu.Unlock()
	if !running {
		return errors.New("session is not running")
	}
	if newline {
		data += "\n"
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), defaultInteractiveIOTimeout,
	)
	defer cancel()
	return s.process.SendInput(ctx, []byte(data))
}

func (s *interactiveSession) Kill(grace time.Duration) error {
	s.mu.Lock()
	s.refreshLocked()
	finished := s.finished
	s.mu.Unlock()
	if finished {
		return nil
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), defaultInteractiveIOTimeout,
	)
	terminated, termErr := s.process.Terminate(ctx)
	cancel()
	if termErr == nil && !terminated {
		return nil
	}

	if termErr == nil && grace > 0 {
		timer := time.NewTimer(grace)
		select {
		case <-s.done:
			timer.Stop()
			return termErr
		case <-timer.C:
		}
	}

	ctx, cancel = context.WithTimeout(
		context.Background(), defaultInteractiveIOTimeout,
	)
	defer cancel()
	_, killErr := s.process.Kill(ctx)
	if killErr == nil {
		return nil
	}
	return errors.Join(termErr, killErr)
}

func (s *interactiveSession) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.process.Disconnect()
	})
	return nil
}

func (s *interactiveSession) State() codeexecutor.ProgramState {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	state := codeexecutor.ProgramState{
		Status: codeexecutor.ProgramStatusRunning,
	}
	if s.finished {
		state.Status = codeexecutor.ProgramStatusExited
		exitCode := s.exitCodeLocked()
		state.ExitCode = &exitCode
	}
	return state
}

func (s *interactiveSession) RunResult() codeexecutor.RunResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	result := codeexecutor.RunResult{
		Stdout:   s.result.Stdout,
		Stderr:   s.result.Stderr,
		TimedOut: s.result.TimedOut,
	}
	if s.finished {
		result.ExitCode = s.exitCodeLocked()
		result.Duration = s.finishedAt.Sub(s.started)
	}
	return result
}

func (s *interactiveSession) wait() {
	result, err := s.process.Wait(context.Background())

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if err != nil && !closed {
		ctx, cancel := context.WithTimeout(
			context.Background(), defaultInteractiveIOTimeout,
		)
		_, _ = s.process.Kill(ctx)
		cancel()
	}

	s.mu.Lock()
	s.applyResultLocked(result)
	s.waitErr = err
	s.finished = true
	s.finishedAt = time.Now()
	if s.partial != "" {
		s.lines = append(s.lines, s.partial)
		s.partial = ""
		s.trimLocked()
	}
	close(s.done)
	s.mu.Unlock()
	s.process.Disconnect()
}

func (s *interactiveSession) refreshLocked() {
	if s.finished {
		return
	}
	result, _, _ := s.process.Snapshot()
	s.applyResultLocked(result)
}

func (s *interactiveSession) applyResultLocked(
	result envdprocess.Result,
) {
	s.result = result
	if len(result.Output) <= s.observedBytes {
		return
	}
	s.appendOutputLocked(result.Output[s.observedBytes:])
	s.observedBytes = len(result.Output)
}

func (s *interactiveSession) appendOutputLocked(chunk string) {
	text := strings.ReplaceAll(chunk, "\r\n", "\n")
	text = s.partial + text
	parts := strings.Split(text, "\n")
	s.partial = parts[len(parts)-1]
	s.lines = append(s.lines, parts[:len(parts)-1]...)
	s.trimLocked()
}

func (s *interactiveSession) trimLocked() {
	if s.maxLines <= 0 || len(s.lines) <= s.maxLines {
		return
	}
	drop := len(s.lines) - s.maxLines
	s.lines = s.lines[drop:]
	s.lineBase += drop
	if s.pollCursor < s.lineBase {
		s.pollCursor = s.lineBase
	}
}

func (s *interactiveSession) outputLocked(start, end int) string {
	from := start - s.lineBase
	to := end - s.lineBase
	output := strings.Join(s.lines[from:to], "\n")
	if end == s.lineBase+len(s.lines) && s.partial != "" {
		if output != "" {
			output += "\n"
		}
		output += s.partial
	}
	return output
}

func (s *interactiveSession) exitCodeLocked() int {
	if s.waitErr != nil || s.result.TimedOut {
		return -1
	}
	return s.result.ExitCode
}

// StartProgram starts a non-PTY program and returns a session that exposes
// incremental output and lifecycle control.
func (r *workspaceRuntime) StartProgram(
	ctx context.Context,
	ws codeexecutor.Workspace,
	spec codeexecutor.InteractiveProgramSpec,
) (codeexecutor.ProgramSession, error) {
	if spec.TTY {
		return nil, errInteractiveTTYUnsupported
	}
	req, err := programRequest(ws, spec.RunProgramSpec, true)
	if err != nil {
		return nil, err
	}
	if r.ce == nil {
		return nil, errors.New("e2b: sandbox not initialized")
	}
	r.ce.mu.Lock()
	sbx := r.ce.sbx
	r.ce.mu.Unlock()
	process, err := ci.StartProcess(ctx, sbx, req)
	if err != nil {
		if process != nil {
			cleanupCtx, cancel := context.WithTimeout(
				context.Background(), defaultInteractiveIOTimeout,
			)
			_, killErr := process.Kill(cleanupCtx)
			cancel()
			process.Disconnect()
			err = errors.Join(err, killErr)
		}
		return nil, fmt.Errorf("e2b: start interactive program: %w", err)
	}
	session := newInteractiveSession(process)
	go session.wait()
	return session, nil
}
