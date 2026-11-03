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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"trpc.group/trpc-go/trpc-agent-go/log"
)

// diagnosticClient preserves client policy and only logs routing metadata.
// URLs, bodies, errors and header values may contain credentials and are never dumped.
func diagnosticClient(client *http.Client) *http.Client {
	clone := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if _, ok := base.(*diagnosticTransport); ok {
		return client
	}
	route := "custom_transport"
	if transport, ok := base.(*http.Transport); ok {
		transport = transport.Clone()
		route = "direct"
		if proxy := transport.Proxy; proxy != nil {
			route = "transport_proxy_function"
			transport.Proxy = func(req *http.Request) (*url.URL, error) {
				target, err := proxy(req)
				proxyHost, proxyScheme := "", ""
				if target != nil {
					proxyHost, proxyScheme = target.Host, target.Scheme
				}
				log.Debugf("e2b http proxy: host=%q path=%q proxy_host=%q proxy_scheme=%q proxy_selected=%t selection_failed=%t", req.URL.Host, req.URL.Path, proxyHost, proxyScheme, target != nil, err != nil)
				return target, err
			}
		}
		base = transport
	}
	clone.Transport = &diagnosticTransport{base: base, route: route}
	return &clone
}

type diagnosticTransport struct {
	base  http.RoundTripper
	route string
}

func (t *diagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	log.Debugf("e2b http request: method=%q scheme=%q host=%q path=%q proxy_mode=%q api_key_present=%t envd_token_present=%t traffic_token_present=%t cube_traffic_token_present=%t authorization_present=%t", req.Method, req.URL.Scheme, req.URL.Host, req.URL.Path, t.route, req.Header.Get("X-API-Key") != "", req.Header.Get("X-Access-Token") != "", req.Header.Get("E2B-Traffic-Access-Token") != "", req.Header.Get("Cube-Traffic-Access-Token") != "", req.Header.Get("Authorization") != "")
	resp, err := t.base.RoundTrip(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	log.Debugf("e2b http response: method=%q host=%q path=%q status=%d transport_failed=%t elapsed_ms=%d", req.Method, req.URL.Host, req.URL.Path, status, err != nil, time.Since(start).Milliseconds())
	if err == nil && resp != nil && resp.StatusCode == http.StatusForbidden && resp.Body != nil {
		resp.Body = &forbiddenDiagnosticBody{ReadCloser: resp.Body, method: req.Method, host: req.URL.Host, path: req.URL.Path}
	}
	return resp, err
}

func (t *diagnosticTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Observe only bytes the caller reads. Do not prefetch, retry or replace errors:
// diagnostics must not change streaming, cancellation or connection ownership.
const forbiddenDiagnosticLimit = 8192

type forbiddenDiagnosticBody struct {
	io.ReadCloser
	method, host, path  string
	mu                  sync.Mutex
	sample              []byte
	truncated, reported bool
}

func (b *forbiddenDiagnosticBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.reported {
		remaining := forbiddenDiagnosticLimit - len(b.sample)
		b.sample = append(b.sample, p[:min(n, remaining)]...)
		b.truncated = b.truncated || n > remaining
		if err != nil {
			b.reportLocked(err == io.EOF, err != io.EOF)
		}
	}
	return n, err
}
func (b *forbiddenDiagnosticBody) Close() error {
	err := b.ReadCloser.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reportLocked(false, false)
	return err
}
func (b *forbiddenDiagnosticBody) reportLocked(complete, readFailed bool) {
	if b.reported {
		return
	}
	b.reported = true
	format, reason, code, ingress := "incomplete", "unknown", "unknown", false
	if complete && !b.truncated {
		var fields struct {
			Reason string `json:"reason"`
			Code   string `json:"code"`
			Error  string `json:"error"`
		}
		if json.Unmarshal(b.sample, &fields) == nil {
			format = "json"
			// Exact allowlists only: even fields named code/reason can contain secrets.
			if fields.Reason == "policy_default_deny" {
				reason = "policy_default_deny"
			}
			switch fields.Code {
			case "permission_denied", "unauthenticated":
				code = fields.Code
			}
			ingress = fields.Error == "access denied by ingress policy"
		} else {
			format = "unrecognized"
		}
	} else if b.truncated {
		format = "oversized"
	}
	log.Debugf("e2b http forbidden: method=%q host=%q path=%q status=403 body_format=%q body_complete=%t body_truncated=%t body_read_failed=%t reason=%q code=%q ingress_policy_message=%t", b.method, b.host, b.path, format, complete, b.truncated, readFailed, reason, code, ingress)
	b.sample = nil
}
