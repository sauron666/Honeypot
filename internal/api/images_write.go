package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sauron666/Honeypot/internal/catalog"
)

// This file lets an operator add VM decoy images from the console, two ways:
// register a file already on the host by its path, or upload one through the
// browser. Both end in the same place -- a catalog entry -- and neither ships
// or distributes anyone's image (HackTheBox and the like are the operator's own
// copy). Upload is deliberately guarded: an allow-listed extension, a base
// filename only (no path traversal), a size cap, and no overwrite. Large images
// are still better dropped on disk and registered by path; the size cap says so.

// imageExtAllowed is the set of VM image/appliance extensions the upload accepts.
var imageExtAllowed = map[string]bool{
	".iso": true, ".ova": true, ".ovf": true, ".qcow2": true, ".qcow": true,
	".vmdk": true, ".vhd": true, ".vhdx": true, ".img": true, ".raw": true, ".vdi": true,
}

// imageRegister adds an image that already exists on the host, by path. This is
// the catalog's native model: it records metadata and a checksum, and never
// copies or moves the file.
func (s *Server) imageRegister(w http.ResponseWriter, r *http.Request) {
	if s.deps.Images == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no image library"})
		return
	}
	var body struct {
		Path       string   `json:"path"`
		Name       string   `json:"name"`
		Difficulty string   `json:"difficulty"`
		Persona    string   `json:"persona"`
		Source     string   `json:"source"`
		Tags       []string `json:"tags"`
		Notes      string   `json:"notes"`
		Checksum   bool     `json:"checksum"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if strings.TrimSpace(body.Path) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a file path is required"})
		return
	}
	im, err := s.deps.Images.Import(body.Path, catalog.ImportOptions{
		Name: body.Name, Difficulty: catalog.Difficulty(body.Difficulty),
		Persona: body.Persona, Source: body.Source, Tags: body.Tags,
		Notes: body.Notes, Checksum: body.Checksum,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.deps.Log.Info("image registered from console", "id", im.ID, "path", im.Path)
	writeJSON(w, http.StatusOK, im)
}

// imageUpload streams a multipart file to the images directory and registers it.
// The guards are the point: without them this is an arbitrary-file-write to the
// host.
func (s *Server) imageUpload(w http.ResponseWriter, r *http.Request) {
	if s.deps.Images == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no image library"})
		return
	}
	if s.deps.ImagesUploadDir == "" {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "uploads are disabled: no images upload directory configured"})
		return
	}
	max := s.deps.ImagesMaxUploadBytes
	if max <= 0 {
		max = 8 << 30
	}
	// Cap the whole request body, so a huge upload cannot fill the disk.
	r.Body = http.MaxBytesReader(w, r.Body, max+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a valid multipart upload (or too large): " + err.Error()})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file field in the upload"})
		return
	}
	defer file.Close()

	// A base name only: no directory components, no traversal.
	name := filepath.Base(filepath.Clean("/" + header.Filename))
	if name == "" || name == "." || name == "/" || strings.ContainsAny(name, `/\`) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid file name"})
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	if !imageExtAllowed[ext] {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "unsupported image type " + ext + " (allowed: iso, ova, ovf, qcow2, vmdk, vhd, vhdx, img, raw, vdi)"})
		return
	}

	if err := os.MkdirAll(s.deps.ImagesUploadDir, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create images directory: " + err.Error()})
		return
	}
	dst := filepath.Join(s.deps.ImagesUploadDir, name)
	// O_EXCL: never overwrite an existing image (it may be in use, and clobbering
	// evidence-adjacent files silently is not acceptable).
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		if os.IsExist(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "an image named " + name + " already exists; rename it first"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot create file: " + err.Error()})
		return
	}
	written, copyErr := io.Copy(out, io.LimitReader(file, max))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(dst) // don't leave a half-written image behind
		msg := "write failed"
		if copyErr != nil {
			msg = copyErr.Error()
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upload failed: " + msg})
		return
	}

	im, err := s.deps.Images.Import(dst, catalog.ImportOptions{
		Name:       formValue(r, "name"),
		Difficulty: catalog.Difficulty(formValue(r, "difficulty")),
		Persona:    formValue(r, "persona"),
		Source:     firstNonEmpty(formValue(r, "source"), "upload"),
	})
	if err != nil {
		os.Remove(dst) // registration failed; don't orphan the file
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "saved but could not register: " + err.Error()})
		return
	}
	s.deps.Log.Info("image uploaded from console", "id", im.ID, "path", dst, "bytes", written)
	writeJSON(w, http.StatusOK, map[string]any{"image": im, "bytes": written})
}

func formValue(r *http.Request, key string) string {
	if r.MultipartForm != nil {
		if v := r.MultipartForm.Value[key]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
