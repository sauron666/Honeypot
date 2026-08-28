package event

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSON renders the event deterministically: struct fields in
// declaration order, map keys sorted by encoding/json, no HTML escaping and no
// trailing newline. Two processes encoding the same event must produce
// byte-identical output or the hash chain is worthless.
func CanonicalJSON(e *Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Decode parses an event from its canonical (or any valid JSON) encoding.
func Decode(b []byte) (*Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // keep integers exact so re-encoding reproduces the hash
	if err := dec.Decode(&e); err != nil {
		return nil, err
	}
	return &e, nil
}
