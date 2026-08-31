package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sauron666/Honeypot/internal/catalog"
)

func serverWithImages(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cat, err := catalog.Open(filepath.Join(dir, "images.json"))
	if err != nil {
		t.Fatal(err)
	}
	uploadDir := filepath.Join(dir, "uploads")
	srv, err := New(":0", Deps{
		Store: &stubStore{}, Images: cat,
		ImagesUploadDir: uploadDir, ImagesMaxUploadBytes: 4 << 20,
		StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, dir
}

func TestImageRegisterByPath(t *testing.T) {
	srv, dir := serverWithImages(t)
	// A real file on the host to register.
	imgPath := filepath.Join(dir, "web01.qcow2")
	if err := os.WriteFile(imgPath, []byte("fake image bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"path":"` + imgPath + `","name":"web01","difficulty":"easy","persona":"linux/web"}`
	rec := doBody(srv.Handler(), "POST", "/api/images", "", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	// It must now show in the list.
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/images", ""))
	imgs, _ := m["images"].([]any)
	if len(imgs) != 1 {
		t.Fatalf("expected 1 image, got %v", m["images"])
	}
	// A missing path is a clean 400, not a panic.
	if rec := doBody(srv.Handler(), "POST", "/api/images", "", `{"path":"/no/such/file.iso"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing file should be 400, got %d", rec.Code)
	}
}

func uploadReq(t *testing.T, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(content)
	mw.WriteField("difficulty", "medium")
	mw.WriteField("persona", "linux/web")
	mw.Close()
	req := httptest.NewRequest("POST", "/api/images/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func TestImageUpload(t *testing.T) {
	srv, _ := serverWithImages(t)

	// A good upload lands on disk and registers.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, uploadReq(t, "decoy.qcow2", []byte("qcow2 bytes here")))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	m := jsonBody(t, do(srv.Handler(), "GET", "/api/images", ""))
	if imgs, _ := m["images"].([]any); len(imgs) != 1 {
		t.Fatalf("uploaded image not registered: %v", m["images"])
	}

	// A disallowed extension is refused.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, uploadReq(t, "evil.sh", []byte("#!/bin/sh")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a .sh upload must be rejected, got %d", rec.Code)
	}

	// Path traversal in the filename cannot escape the upload dir.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, uploadReq(t, "../../etc/passwd.iso", []byte("x")))
	// The base name is passwd.iso (allowed ext), so it succeeds but lands in the
	// upload dir, never at ../../etc. Confirm it did not escape.
	if rec.Code == http.StatusOK {
		if _, err := os.Stat("/etc/passwd.iso"); err == nil {
			t.Fatal("traversal escaped the upload directory")
		}
	}
}

func TestImageUploadDisabledWithoutDir(t *testing.T) {
	dir := t.TempDir()
	cat, _ := catalog.Open(filepath.Join(dir, "images.json"))
	srv, _ := New(":0", Deps{Store: &stubStore{}, Images: cat, StartedAt: time.Now()})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, uploadReq(t, "x.iso", []byte("x")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload without a configured dir should be 503, got %d", rec.Code)
	}
}
