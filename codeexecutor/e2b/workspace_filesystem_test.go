//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2026 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package e2b

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"trpc.group/trpc-go/trpc-agent-go/codeexecutor"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"
	filesystem "trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/envdfs/spec"
	"trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/envdfs/spec/filesystemconnect"
	process "trpc.group/trpc-go/trpc-agent-go/codeexecutor/e2b/internal/envdprocess/spec"
)

// workspaceFilesystemHandler serves the pinned envd wire protocol over a
// temporary filesystem. Only explicit localRoot tests share paths with bash.
type workspaceFilesystemHandler struct {
	filesystemconnect.UnimplementedFilesystemHandler
	root, localRoot   string
	moveErr, writeErr error
}

func (h *workspaceFilesystemHandler) resolve(p string) string {
	if h.localRoot != "" && pathUnder(filepath.Clean(p), h.localRoot) {
		return p
	}
	return filepath.Join(h.root, filepath.Clean("/"+p))
}
func (h *workspaceFilesystemHandler) put(t *testing.T, p string, b []byte) {
	t.Helper()
	p = h.resolve(p)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
	require.NoError(t, os.WriteFile(p, b, 0600))
}
func filesystemTestError(err error) error {
	if err == nil {
		return nil
	}
	code := connect.CodeInternal
	if errors.Is(err, os.ErrNotExist) {
		code = connect.CodeNotFound
	}
	if errors.Is(err, os.ErrExist) {
		code = connect.CodeAlreadyExists
	}
	return connect.NewError(code, err)
}
func (h *workspaceFilesystemHandler) Stat(_ context.Context, r *connect.Request[filesystem.StatRequest]) (*connect.Response[filesystem.StatResponse], error) {
	p := h.resolve(r.Msg.Path)
	st, err := os.Lstat(p)
	if err != nil {
		return nil, filesystemTestError(err)
	}
	e := &filesystem.EntryInfo{Path: r.Msg.Path, Size: st.Size(), Mode: uint32(st.Mode().Perm()), Permissions: st.Mode().String(), Type: filesystem.FileType_FILE_TYPE_FILE}
	if st.IsDir() {
		e.Type = filesystem.FileType_FILE_TYPE_DIRECTORY
	}
	if st.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(p)
		if err != nil {
			return nil, err
		}
		e.SymlinkTarget = &target
	}
	return connect.NewResponse(&filesystem.StatResponse{Entry: e}), nil
}
func (h *workspaceFilesystemHandler) MakeDir(_ context.Context, r *connect.Request[filesystem.MakeDirRequest]) (*connect.Response[filesystem.MakeDirResponse], error) {
	p := h.resolve(r.Msg.Path)
	if _, err := os.Lstat(p); err == nil {
		return nil, filesystemTestError(os.ErrExist)
	}
	if err := os.MkdirAll(p, 0755); err != nil {
		return nil, filesystemTestError(err)
	}
	return connect.NewResponse(&filesystem.MakeDirResponse{}), nil
}
func (h *workspaceFilesystemHandler) Remove(_ context.Context, r *connect.Request[filesystem.RemoveRequest]) (*connect.Response[filesystem.RemoveResponse], error) {
	if err := os.RemoveAll(h.resolve(r.Msg.Path)); err != nil {
		return nil, filesystemTestError(err)
	}
	return connect.NewResponse(&filesystem.RemoveResponse{}), nil
}
func (h *workspaceFilesystemHandler) Move(_ context.Context, r *connect.Request[filesystem.MoveRequest]) (*connect.Response[filesystem.MoveResponse], error) {
	if h.moveErr != nil {
		return nil, filesystemTestError(h.moveErr)
	}
	dst := h.resolve(r.Msg.Destination)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return nil, err
	}
	if err := os.Rename(h.resolve(r.Msg.Source), dst); err != nil {
		return nil, filesystemTestError(err)
	}
	return connect.NewResponse(&filesystem.MoveResponse{}), nil
}
func (h *workspaceFilesystemHandler) serveFiles(w http.ResponseWriter, r *http.Request) {
	p := h.resolve(r.URL.Query().Get("path"))
	if r.Method == http.MethodGet {
		f, err := os.Open(p)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		http.ServeContent(w, r, st.Name(), st.ModTime(), f)
		return
	}
	if h.writeErr != nil {
		http.Error(w, h.writeErr.Error(), 500)
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	part, err := reader.NextPart()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer part.Close()
	if err = os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Match envd: an existing file retains its permission bits.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_, err = io.Copy(f, part)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "[]")
}

// Exercise framing with an open stdin descriptor, as on envd versions without
// CloseStdin. The script exceeds typical exec argument limits and uses UTF-8.
func TestWorkspaceScriptFraming(t *testing.T) {
	for _, tc := range []struct {
		name, script, want string
		fail               bool
	}{
		{"large", "#" + strings.Repeat("x", 256*1024) + "\nprintf '中文'", "中文", false},
		{"failure", "printf diagnostic >&2; exit 7", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()
			cmd := exec.CommandContext(ctx, "/bin/bash", "-c", workspaceScriptBootstrap, "trpc-workspace", strconv.Itoa(len(tc.script)))
			cmd.Stdin = reader
			var out, stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			require.NoError(t, cmd.Start())
			_, err = io.WriteString(writer, tc.script)
			require.NoError(t, err)
			// Deliberately leave writer open while waiting for completion.
			err = cmd.Wait()
			if tc.fail {
				require.Error(t, err)
				assert.Equal(t, 7, cmd.ProcessState.ExitCode())
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, ctx.Err())
			assert.Equal(t, tc.want, out.String())
		})
	}
}

func TestNativeWorkspaceLifecycle(t *testing.T) {
	srv := newMockE2BServer(t, nil)
	defer srv.close()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	srv.fs.localRoot = root
	srv.process.script = func(ctx context.Context, _ *connect.Request[process.StartRequest], script string) (string, string, int32, error) {
		cmd := exec.CommandContext(ctx, "/bin/bash", "-c", workspaceScriptBootstrap, "trpc-workspace", strconv.Itoa(len(script)))
		cmd.Stdin = strings.NewReader(script)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return out.String(), stderr.String(), int32(exitErr.ExitCode()), nil
		}
		return out.String(), stderr.String(), 0, err
	}
	c := newMockedExecutor(t, srv, WithSandboxRunBase(root), WithWorkspacePersistence(WorkspacePersistencePerSession))
	ctx := context.Background()
	ws, err := c.CreateWorkspace(ctx, "native", codeexecutor.WorkspacePolicy{})
	require.NoError(t, err)
	data := bytes.Repeat([]byte{0, 255, 128, 10, 65}, 100000)
	require.NoError(t, c.PutFiles(ctx, ws, []codeexecutor.PutFile{{Path: "out/binary", Content: data, Mode: 0600}}))
	got, err := os.ReadFile(filepath.Join(ws.Path, "out/binary"))
	require.NoError(t, err)
	require.Equal(t, data, got)
	st, err := os.Stat(filepath.Join(ws.Path, "out/binary"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), st.Mode().Perm())
	rt := c.ensureRuntime()
	got, size, err := rt.readFile(ctx, filepath.Join(ws.Path, "out/binary"), 17)
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)), size)
	assert.Equal(t, data[:17], got)
	require.NoError(t, rt.saveWorkspaceMetadata(ctx, ws, codeexecutor.WorkspaceMetadata{Version: 2}))
	mdPath := filepath.Join(ws.Path, codeexecutor.MetaFileName)
	before, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	st, err = os.Stat(mdPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), st.Mode().Perm())
	again, err := c.CreateWorkspace(ctx, "native", codeexecutor.WorkspacePolicy{})
	require.NoError(t, err)
	assert.Equal(t, ws.Path, again.Path)
	after, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	require.NoError(t, os.Remove(mdPath))
	require.NoError(t, os.Mkdir(mdPath, 0755))
	require.Error(t, rt.saveWorkspaceMetadata(ctx, ws, codeexecutor.WorkspaceMetadata{}))
	entries, err := os.ReadDir(ws.Path)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".metadata"), e.Name())
	}
	temp := filepath.Join(ws.Path, "canceled-temp")
	require.NoError(t, os.WriteFile(temp, []byte("temp"), 0600))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	rt.removeTemporary(canceled, temp)
	_, err = os.Stat(temp)
	require.True(t, os.IsNotExist(err))
	require.NoError(t, c.Cleanup(ctx, ws))
	_, err = os.Stat(ws.Path)
	require.True(t, os.IsNotExist(err))
	assert.Zero(t, srv.interpreterCalls)
}
