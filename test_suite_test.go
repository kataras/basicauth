package basicauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"
)

// a simple test suite written specifically for the basicauth middleware.
type testie struct {
	t    *testing.T
	resp *http.Response
}

func (te *testie) fatal(err error) {
	msg := fmt.Sprintf("[%s] %v", te.resp.Request.URL.String(), err)

	if id := te.resp.Request.Header.Get("X-Request-Id"); id != "" {
		msg = fmt.Sprintf("[%s] %s", id, msg)
	}

	te.t.Fatal(msg)
}

func (te *testie) fatalf(format string, args ...interface{}) {
	te.fatal(fmt.Errorf(format, args...))
}

func (te *testie) statusCode(expected int) *testie {
	if got := te.resp.StatusCode; expected != got {
		te.fatalf("expected status code: %d but got: %d", expected, got)
	}

	return te
}

func (te *testie) jsonEq(v interface{}) *testie {
	media, _, err := mime.ParseMediaType(te.resp.Header.Get("Content-Type"))
	if err != nil {
		te.fatal(err)
	}

	if media != "application/json" {
		te.fatalf("expected to be a json response but got: %q", media)
	}

	expected, err := json.Marshal(v)
	if err != nil {
		te.fatal(err)
	}

	got, err := io.ReadAll(te.resp.Body)
	_ = te.resp.Body.Close()
	if err != nil {
		te.fatal(err)
	}

	got = bytes.TrimSuffix(got, []byte("\n"))

	if !bytes.EqualFold(expected, got) {
		te.fatalf("expected to receive:\n'%s'\nbut got:\n'%s'", string(expected), string(got))
	}

	return te
}

func testHandler(t *testing.T, handler http.Handler, method, url string, reqOpts ...requestOption) *testie {
	t.Helper()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, url, nil)
	for _, opt := range reqOpts {
		if err := opt(req); err != nil {
			t.Fatal(err)
		}
	}

	handler.ServeHTTP(w, req)
	resp := w.Result()
	resp.Request = req
	return &testie{t: t, resp: resp}
}

type requestOption func(*http.Request) error

func withBasicAuth(username, password string) requestOption {
	return func(r *http.Request) error {
		r.SetBasicAuth(username, password)
		return nil
	}
}

func withRequestID(id interface{}) requestOption { // useful for logging.
	return func(r *http.Request) error {
		r.Header.Set("X-Request-Id", fmt.Sprintf("%v", id))
		return nil
	}
}
