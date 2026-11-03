//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package codeinterpreter

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"trpc.group/trpc-go/trpc-agent-go/log"
)

func TestDiagnosticsRedactsCredentials(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	previous := log.Default
	log.Default = zap.New(core).Sugar()
	t.Cleanup(func() { log.Default = previous })
	secret := "never-print-this-secret"
	req, err := http.NewRequest("POST", "https://user:"+secret+"@49983-sandbox.example/process.Process/Start?token="+secret, nil)
	require.NoError(t, err)
	for _, name := range []string{"X-API-Key", "X-Access-Token", "E2B-Traffic-Access-Token", "Cube-Traffic-Access-Token", "Authorization"} {
		req.Header.Set(name, secret)
	}
	sentinel := errors.New(secret)
	original := &http.Client{Timeout: time.Second, Transport: processRoundTripper(func(got *http.Request) (*http.Response, error) {
		require.Same(t, req, got)
		require.Equal(t, secret, got.Header.Get("X-Access-Token"))
		return nil, sentinel
	})}
	client := diagnosticClient(original)
	require.Equal(t, original.Timeout, client.Timeout)
	_, err = client.Transport.RoundTrip(req)
	require.ErrorIs(t, err, sentinel)
	var messages string
	for _, entry := range logs.All() {
		messages += entry.Message
	}
	require.NotContains(t, messages, secret)
	require.Contains(t, messages, `path="/process.Process/Start"`)
	require.Contains(t, messages, "envd_token_present=true")
	require.Contains(t, messages, "transport_failed=true")
	require.Contains(t, messages, `proxy_mode="custom_transport"`)
}

func TestDiagnosticsProxySelectionPreservesPolicy(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	previous := log.Default
	log.Default = zap.New(core).Sugar()
	t.Cleanup(func() { log.Default = previous })
	calls := 0
	target, err := url.Parse("http://user:proxy-secret@proxy.example:8080?secret=hidden")
	require.NoError(t, err)
	original := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { calls++; return target, nil }}
	client := diagnosticClient(&http.Client{Transport: original})
	wrapped := client.Transport.(*diagnosticTransport).base.(*http.Transport)
	require.NotSame(t, original, wrapped)
	require.Zero(t, calls)
	req, _ := http.NewRequest("GET", "https://sandbox.example/execute", nil)
	actual, err := wrapped.Proxy(req)
	require.NoError(t, err)
	require.Same(t, target, actual)
	require.Equal(t, 1, calls)
	message := logs.All()[0].Message
	require.Contains(t, message, `proxy_host="proxy.example:8080"`)
	require.False(t, strings.Contains(message, "proxy-secret"))
	require.NotContains(t, message, "hidden")
}

func TestForbiddenDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, body, format, reason, code string
		ingress                          bool
	}{
		{"ingress", `{"error":"access denied by ingress policy","reason":"policy_default_deny","token":"never-print-this-secret"}`, "json", "policy_default_deny", "unknown", true},
		{"connect", `{"code":"permission_denied","message":"never-print-this-secret"}`, "json", "unknown", "permission_denied", false},
		{"auth", `{"code":"unauthenticated"}`, "json", "unknown", "unauthenticated", false},
		{"unknown fields", `{"code":"never-print-this-secret","reason":"never-print-this-secret","error":"never-print-this-secret"}`, "json", "unknown", "unknown", false},
		{"malformed", `<html>never-print-this-secret</html>`, "unrecognized", "unknown", "unknown", false},
		{"large", strings.Repeat("never-print-this-secret", 1000), "oversized", "unknown", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			previous := log.Default
			log.Default = zap.New(core).Sugar()
			t.Cleanup(func() { log.Default = previous })
			body := &diagnosticTestBody{Reader: strings.NewReader(tc.body)}
			client := diagnosticClient(&http.Client{Transport: processRoundTripper(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 403, Body: body}, nil })})
			req, err := http.NewRequest("POST", "https://49983-sandbox.example/filesystem.Filesystem/MakeDir", nil)
			require.NoError(t, err)
			resp, err := client.Transport.RoundTrip(req)
			require.NoError(t, err)
			require.Zero(t, body.reads, "must not prefetch response")
			got, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.body, string(got))
			require.NoError(t, resp.Body.Close())
			require.True(t, body.closed)
			entries := logs.FilterMessageSnippet("e2b http forbidden:").All()
			require.Len(t, entries, 1)
			msg := entries[0].Message
			require.Contains(t, msg, fmt.Sprintf("body_format=%q", tc.format))
			require.Contains(t, msg, fmt.Sprintf("reason=%q", tc.reason))
			require.Contains(t, msg, fmt.Sprintf("code=%q", tc.code))
			require.Contains(t, msg, fmt.Sprintf("ingress_policy_message=%t", tc.ingress))
			for _, entry := range logs.All() {
				require.NotContains(t, entry.Message, "never-print-this-secret")
			}
		})
	}
}

type diagnosticTestBody struct {
	*strings.Reader
	reads             int
	closed            bool
	readErr, closeErr error
}

func (b *diagnosticTestBody) Read(p []byte) (int, error) {
	b.reads++
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.Reader.Read(p)
}
func (b *diagnosticTestBody) Close() error { b.closed = true; return b.closeErr }

func TestForbiddenDiagnosticsPreserveErrorsAndEarlyClose(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			previous := log.Default
			log.Default = zap.New(core).Sugar()
			t.Cleanup(func() { log.Default = previous })
			sentinel := errors.New("never-print-this-secret")
			original := &diagnosticTestBody{Reader: strings.NewReader("secret"), closeErr: sentinel}
			body := &forbiddenDiagnosticBody{ReadCloser: original}
			if fail {
				original.readErr = sentinel
				_, err := body.Read(make([]byte, 4))
				require.ErrorIs(t, err, sentinel)
			}
			require.ErrorIs(t, body.Close(), sentinel)
			require.True(t, original.closed)
			entries := logs.FilterMessageSnippet("e2b http forbidden:").All()
			require.Len(t, entries, 1)
			require.Contains(t, entries[0].Message, "body_complete=false")
			require.NotContains(t, entries[0].Message, "never-print-this-secret")
		})
	}
}

func TestDiagnosticsDoNotWrapOtherResponses(t *testing.T) {
	original := &diagnosticTestBody{Reader: strings.NewReader("ok")}
	client := diagnosticClient(&http.Client{Transport: processRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: original}, nil
	})})
	req, _ := http.NewRequest("GET", "https://sandbox.example/health", nil)
	resp, err := client.Transport.RoundTrip(req)
	require.NoError(t, err)
	require.Same(t, original, resp.Body)
	require.NoError(t, resp.Body.Close())
}
