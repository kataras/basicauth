package basicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkDecodeHeader(b *testing.B) {
	header, _ := encodeHeader("kataras", "kataras_pass")
	b.ReportAllocs()
	for b.Loop() {
		_, _, _, ok := decodeHeader(header)
		if !ok {
			b.Fatal("decode failed")
		}
	}
}

func BenchmarkAllowUsers(b *testing.B) {
	type user struct {
		Username string
		Password string
		Role     string
	}
	allow := AllowUsers([]user{
		{"kataras", "kataras_pass", "admin"},
		{"george", "george_pass", "member"},
	})

	b.ReportAllocs()
	for b.Loop() {
		if _, ok := allow(nil, "george", "george_pass"); !ok {
			b.Fatal("expected success")
		}
	}
}

func BenchmarkServeHTTP(b *testing.B) {
	auth := Default(map[string]string{"kataras": "kataras_pass"})
	handler := auth.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.User(r); !ok {
			b.Fatal("missing user")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("kataras", "kataras_pass")

	b.ReportAllocs()
	for b.Loop() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}
