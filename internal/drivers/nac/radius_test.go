package nac

import (
	"context"
	"crypto/md5"
	"net"
	"testing"
	"time"
)

// fakeNAS is a minimal RFC 5176 responder: it verifies the CoA-Request's
// authenticator with the shared secret and replies ACK, exactly as FreeRADIUS
// would. It is here to prove our packet is one a real NAS accepts -- a CoA with
// a bad authenticator (the previous bug) would be silently dropped by a real
// server, so only a test that checks the authenticator catches that.
func fakeNAS(t *testing.T, secret string, reply byte) (addr string, gotVLAN chan int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	gotVLAN = make(chan int, 1)

	go func() {
		buf := make([]byte, 4096)
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil || n < 20 {
			return
		}
		req := append([]byte(nil), buf[:n]...)

		// Verify the Request Authenticator: MD5(header+zeroed-auth+attrs+secret).
		reqAuth := append([]byte(nil), req[4:20]...)
		zeroed := append([]byte(nil), req...)
		for i := 4; i < 20; i++ {
			zeroed[i] = 0
		}
		sum := md5.Sum(append(zeroed, []byte(secret)...))
		valid := true
		for i := range reqAuth {
			if reqAuth[i] != sum[i] {
				valid = false
			}
		}
		if !valid {
			gotVLAN <- -1 // signal: rejected, real FreeRADIUS would drop this
			return
		}
		// Pull the Tunnel-Private-Group-Id (81) to confirm the VLAN.
		vlan := parseVLAN(req[20:])
		gotVLAN <- vlan

		// Build the reply with a valid Response Authenticator.
		resp := make([]byte, 20)
		resp[0] = reply
		resp[1] = req[1]
		resp[2], resp[3] = 0, 20
		raInput := append([]byte{resp[0], resp[1], resp[2], resp[3]}, reqAuth...)
		raInput = append(raInput, []byte(secret)...)
		ra := md5.Sum(raInput)
		copy(resp[4:20], ra[:])
		pc.WriteTo(resp, raddr)
	}()
	return pc.LocalAddr().String(), gotVLAN
}

func parseVLAN(attrs []byte) int {
	i := 0
	for i+2 <= len(attrs) {
		typ, ln := attrs[i], int(attrs[i+1])
		if ln < 2 || i+ln > len(attrs) {
			break
		}
		if typ == 81 { // Tunnel-Private-Group-Id, tag byte then ASCII vlan
			v := attrs[i+2 : i+ln]
			if len(v) > 1 {
				n := 0
				for _, c := range v[1:] {
					if c >= '0' && c <= '9' {
						n = n*10 + int(c-'0')
					}
				}
				return n
			}
		}
		i += ln
	}
	return 0
}

func newRadius(t *testing.T, addr, secret string, vlan int) *Radius {
	t.Helper()
	_, port, _ := net.SplitHostPort(addr)
	d, err := NewRadius(map[string]any{
		"server": addr, "secret": secret,
		"deception_vlan": vlan, "coa_port": mustAtoi(port),
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Radius)
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestCoAIsAcceptedByARealNAS(t *testing.T) {
	// The whole point: our CoA must have a valid authenticator, or FreeRADIUS
	// drops it and the device is never steered.
	addr, gotVLAN := fakeNAS(t, "s3cr3t", 44 /* CoA-ACK */)
	r := newRadius(t, addr, "s3cr3t", 666)

	if err := r.SteerToDeception(context.Background(), "00:11:22:33:44:55", "10.0.0.1", 3); err != nil {
		t.Fatalf("a valid CoA was rejected: %v", err)
	}
	select {
	case v := <-gotVLAN:
		if v == -1 {
			t.Fatal("the NAS rejected our CoA authenticator -- the packet is malformed")
		}
		if v != 666 {
			t.Fatalf("the CoA reassigned to VLAN %d, want 666", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the NAS never received a valid CoA")
	}
}

func TestCoANAKSurfacesAsAnError(t *testing.T) {
	// A NAS that refuses (CoA-NAK) must not look like success -- steering that
	// silently failed is worse than an honest error.
	addr, _ := fakeNAS(t, "s3cr3t", 45 /* CoA-NAK */)
	r := newRadius(t, addr, "s3cr3t", 666)
	if err := r.SteerToDeception(context.Background(), "aa:bb:cc:dd:ee:ff", "10.0.0.1", 1); err == nil {
		t.Fatal("a CoA-NAK was reported as success")
	}
}

func TestWrongSecretIsDetected(t *testing.T) {
	// If our secret does not match the NAS, the reply authenticator will not
	// verify; we must report that rather than assume the device was steered.
	addr, _ := fakeNAS(t, "correct-secret", 44)
	r := newRadius(t, addr, "wrong-secret", 666)
	if err := r.SteerToDeception(context.Background(), "aa:bb:cc:dd:ee:ff", "10.0.0.1", 1); err == nil {
		t.Fatal("a secret mismatch was not detected")
	}
}

func TestNoneNACIsHonest(t *testing.T) {
	n, _ := NewNone(nil)
	if err := n.(*None).SteerToDeception(context.Background(), "mac", "ip", 1); err == nil {
		t.Fatal("the null NAC should report it steered nothing")
	}
}
