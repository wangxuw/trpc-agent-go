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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"trpc.group/trpc-go/trpc-agent-go/codeexecutor"
	process "trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/envdprocess/spec"
)

func TestStartProgramInteractivePipes(t *testing.T) {
	srv := newMockE2BServer(t, nil)
	defer srv.close()

	input := make(chan string, 1)
	srv.process.input = func(req *process.SendInputRequest) {
		input <- string(req.Input.GetStdin())
	}
	srv.process.start = func(
		ctx context.Context,
		_ *connect.Request[process.StartRequest],
		stream *connect.ServerStream[process.StartResponse],
	) error {
		if err := sendWorkspaceStart(stream, 1); err != nil {
			return err
		}
		if err := stream.Send(&process.StartResponse{
			Event: &process.ProcessEvent{
				Event: &process.ProcessEvent_Data{
					Data: &process.ProcessEvent_DataEvent{
						Output: &process.ProcessEvent_DataEvent_Stdout{
							Stdout: []byte("ready\n"),
						},
					},
				},
			},
		}); err != nil {
			return err
		}
		select {
		case value := <-input:
			return sendWorkspaceResult(
				stream,
				"out:"+value,
				"err:"+value,
				0,
			)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	executor := newMockedExecutor(t, srv)
	runner, ok := executor.Engine().Runner().(codeexecutor.InteractiveProgramRunner)
	require.True(t, ok)
	session, err := runner.StartProgram(
		context.Background(),
		codeexecutor.Workspace{Path: "/tmp/ws"},
		codeexecutor.InteractiveProgramSpec{
			RunProgramSpec: codeexecutor.RunProgramSpec{
				Cmd:     "sh",
				Args:    []string{"-c", "read value"},
				Timeout: 2 * time.Second,
			},
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = session.Kill(0)
		_ = session.Close()
	})

	require.Eventually(t, func() bool {
		return strings.Contains(session.Poll(nil).Output, "ready")
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, session.Write("hello", true))

	var observed strings.Builder
	require.Eventually(t, func() bool {
		poll := session.Poll(nil)
		if poll.Output != "" {
			if observed.Len() > 0 {
				observed.WriteByte('\n')
			}
			observed.WriteString(poll.Output)
		}
		return poll.Status == codeexecutor.ProgramStatusExited
	}, time.Second, 10*time.Millisecond)
	assert.Contains(t, observed.String(), "out:hello")
	assert.Contains(t, observed.String(), "err:hello")

	resultProvider, ok := session.(codeexecutor.ProgramResultProvider)
	require.True(t, ok)
	result := resultProvider.RunResult()
	assert.Equal(t, "ready\nout:hello\n", result.Stdout)
	assert.Equal(t, "err:hello\n", result.Stderr)
	assert.Equal(t, 0, result.ExitCode)
	assert.False(t, result.TimedOut)
	assert.Positive(t, result.Duration)

	srv.process.mu.Lock()
	require.Len(t, srv.process.requests, 1)
	request := srv.process.requests[0]
	srv.process.mu.Unlock()
	assert.True(t, request.GetStdin())
	assert.NotContains(t, request.Process.Args[1], "/dev/null")
}

func TestStartProgramRejectsTTY(t *testing.T) {
	srv := newMockE2BServer(t, nil)
	defer srv.close()
	executor := newMockedExecutor(t, srv)
	runner := executor.Engine().Runner().(codeexecutor.InteractiveProgramRunner)

	session, err := runner.StartProgram(
		context.Background(),
		codeexecutor.Workspace{Path: "/tmp/ws"},
		codeexecutor.InteractiveProgramSpec{
			RunProgramSpec: codeexecutor.RunProgramSpec{Cmd: "true"},
			TTY:            true,
		},
	)

	require.ErrorIs(t, err, errInteractiveTTYUnsupported)
	assert.Nil(t, session)
	assert.Empty(t, srv.process.requests)
}

func TestStartProgramKillUsesGraceThenSIGKILL(t *testing.T) {
	srv := newMockE2BServer(t, nil)
	defer srv.close()
	signals := make(chan process.Signal, 2)
	srv.process.signal = func(req *process.SendSignalRequest) {
		signals <- req.Signal
	}
	srv.process.start = func(
		ctx context.Context,
		_ *connect.Request[process.StartRequest],
		stream *connect.ServerStream[process.StartResponse],
	) error {
		if err := sendWorkspaceStart(stream, 1); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}

	executor := newMockedExecutor(t, srv)
	runner := executor.Engine().Runner().(codeexecutor.InteractiveProgramRunner)
	session, err := runner.StartProgram(
		context.Background(),
		codeexecutor.Workspace{Path: "/tmp/ws"},
		codeexecutor.InteractiveProgramSpec{
			RunProgramSpec: codeexecutor.RunProgramSpec{
				Cmd:     "sleep",
				Args:    []string{"60"},
				Timeout: time.Minute,
			},
		},
	)
	require.NoError(t, err)
	require.NoError(t, session.Kill(10*time.Millisecond))
	assert.Equal(t, process.Signal_SIGNAL_SIGTERM, <-signals)
	assert.Equal(t, process.Signal_SIGNAL_SIGKILL, <-signals)
	require.NoError(t, session.Close())
}

func TestStartProgramCallerCancellationKillsRemoteProcess(t *testing.T) {
	srv := newMockE2BServer(t, nil)
	defer srv.close()
	killed := make(chan process.Signal, 1)
	srv.process.signal = func(req *process.SendSignalRequest) {
		killed <- req.Signal
	}
	started := make(chan struct{})
	srv.process.start = func(
		ctx context.Context,
		_ *connect.Request[process.StartRequest],
		stream *connect.ServerStream[process.StartResponse],
	) error {
		if err := sendWorkspaceStart(stream, 1); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}

	executor := newMockedExecutor(t, srv)
	runner := executor.Engine().Runner().(codeexecutor.InteractiveProgramRunner)
	ctx, cancel := context.WithCancel(context.Background())
	session, err := runner.StartProgram(
		ctx,
		codeexecutor.Workspace{Path: "/tmp/ws"},
		codeexecutor.InteractiveProgramSpec{
			RunProgramSpec: codeexecutor.RunProgramSpec{
				Cmd:     "sleep",
				Args:    []string{"60"},
				Timeout: time.Minute,
			},
		},
	)
	require.NoError(t, err)
	<-started
	cancel()

	select {
	case signal := <-killed:
		assert.Equal(t, process.Signal_SIGNAL_SIGKILL, signal)
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not kill the remote process")
	}
	require.Eventually(t, func() bool {
		state := session.(codeexecutor.ProgramStateProvider).State()
		return state.Status == codeexecutor.ProgramStatusExited &&
			state.ExitCode != nil && *state.ExitCode == -1
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, session.Close())
}
