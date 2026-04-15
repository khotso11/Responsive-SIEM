package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
)

func TestEveEncodeLabPath(t *testing.T) {
	got := eveEncodeLabPath("/R-SIEM/rsiem-infrastructure.unl")
	want := "R-SIEM/rsiem-infrastructure.unl"
	if got != want {
		t.Fatalf("encode mismatch: got %q want %q", got, want)
	}
}

func TestFetchEveNGRuntime(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/api/auth/login":
				return jsonResponse(req, `{"code":200,"status":"success","message":"User logged in"}`, []*http.Cookie{{Name: "eve", Value: "ok", Path: "/"}}), nil
			case "/api/labs/R-SIEM/rsiem-infrastructure.unl/nodes":
				if cookie := req.Header.Get("Cookie"); !strings.Contains(cookie, "eve=ok") {
					t.Fatalf("missing session cookie header: %q", cookie)
				}
				return jsonResponse(req, `{"code":200,"status":"success","data":{"1":{"id":1,"name":"edge-rtr-01","status":2,"url":"telnet://127.0.0.1:32769","left":400,"top":180,"image":"vios"},"2":{"id":2,"name":"fw-01","status":0,"url":"telnet://127.0.0.1:32770","left":680,"top":180,"image":"fortios"}}}`, nil), nil
			default:
				t.Fatalf("unexpected path: %s", req.URL.Path)
				return nil, nil
			}
		}),
	}

	view := fetchEveNGRuntimeWithClient(context.Background(), infrastructureProviderSpec{
		Kind:       "eve_ng",
		APIBaseURL: "https://eve-ng.local",
		APILabPath: "/R-SIEM/rsiem-infrastructure.unl",
	}, "admin", "eve", client)
	if view.Status != "connected" {
		t.Fatalf("unexpected runtime status: %+v", view)
	}
	if got := view.Nodes["edge-rtr-01"].Status; got != "running" {
		t.Fatalf("unexpected node status: %q", got)
	}
	if got := view.Nodes["fw-01"].Status; got != "stopped" {
		t.Fatalf("unexpected fw status: %q", got)
	}
}

func TestFetchEveNGRuntimeMissingCreds(t *testing.T) {
	os.Unsetenv("TEST_EVE_USER_MISSING")
	os.Unsetenv("TEST_EVE_PASS_MISSING")
	view := fetchEveNGRuntime(context.Background(), infrastructureProviderSpec{
		Kind:        "eve_ng",
		APIBaseURL:  "https://eve-ng.local",
		APILabPath:  "/R-SIEM/rsiem-infrastructure.unl",
		UsernameEnv: "TEST_EVE_USER_MISSING",
		PasswordEnv: "TEST_EVE_PASS_MISSING",
	})
	if view.Status != "credentials_missing" {
		t.Fatalf("expected credentials_missing, got %+v", view)
	}
}

func TestApplyInfrastructureEnvOverrides(t *testing.T) {
	t.Setenv("RSIEM_EVE_NG_UI_URL", "https://10.0.0.50/")
	t.Setenv("RSIEM_EVE_NG_API_BASE_URL", "https://10.0.0.50")
	t.Setenv("RSIEM_EVE_NG_API_LAB_PATH", "/labs/demo.unl")
	t.Setenv("RSIEM_EVE_NG_ALLOW_INSECURE_TLS", "true")
	spec := applyInfrastructureEnvOverrides(infrastructureLabFile{
		Provider: infrastructureProviderSpec{
			UIURL:            "https://eve-ng.local/",
			APIBaseURL:       "https://eve-ng.local",
			APILabPath:       "/R-SIEM/rsiem-infrastructure.unl",
			AllowInsecureTLS: false,
		},
	})
	if spec.Provider.UIURL != "https://10.0.0.50/" || spec.Provider.APIBaseURL != "https://10.0.0.50" || spec.Provider.APILabPath != "/labs/demo.unl" || !spec.Provider.AllowInsecureTLS {
		t.Fatalf("env overrides not applied: %+v", spec.Provider)
	}
}

func TestEveNGNodeAction(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/api/auth/login":
				return jsonResponse(req, `{"code":200,"status":"success","message":"User logged in"}`, []*http.Cookie{{Name: "eve", Value: "ok", Path: "/"}}), nil
			case "/api/labs/R-SIEM/rsiem-infrastructure.unl/nodes/1/start":
				if cookie := req.Header.Get("Cookie"); !strings.Contains(cookie, "eve=ok") {
					t.Fatalf("missing session cookie header: %q", cookie)
				}
				return jsonResponse(req, `{"code":200,"status":"success","message":"node started"}`, nil), nil
			case "/api/labs/R-SIEM/rsiem-infrastructure.unl/nodes":
				return jsonResponse(req, `{"code":200,"status":"success","data":{"1":{"id":1,"name":"edge-rtr-01","status":2,"url":"telnet://127.0.0.1:32769","left":400,"top":180,"image":"vios"}}}`, nil), nil
			default:
				t.Fatalf("unexpected path: %s", req.URL.Path)
				return nil, nil
			}
		}),
	}

	result, err := eveNGNodeActionWithClient(context.Background(), infrastructureProviderSpec{
		Kind:       "eve_ng",
		APIBaseURL: "https://eve-ng.local",
		APILabPath: "/R-SIEM/rsiem-infrastructure.unl",
	}, "admin", "eve", client, "https://eve-ng.local", "1", "start")
	if err != nil {
		t.Fatalf("action failed: %v", err)
	}
	if result.Action != "start" || result.RuntimeStatus != "running" || result.NodeName != "edge-rtr-01" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(req *http.Request, body string, cookies []*http.Cookie) *http.Response {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		resp.Header.Add("Set-Cookie", cookie.String())
	}
	return resp
}
