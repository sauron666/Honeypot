package honeyd

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/sauron666/Honeypot/internal/event"
)

func init() { RegisterService("modbus", newModbus) }

// modbusSvc emulates a Modbus/TCP PLC.
//
// Industrial decoys matter for a reason no IT decoy does: an operator cannot
// put an agent on a PLC, so a passive decoy is often the only detection that is
// possible at all. Reads are reconnaissance. Writes are an attempt to change a
// physical process, and are treated as critical.
type modbusSvc struct {
	p        *Persona
	vendor   string
	product  string
	revision string

	// Register banks are per-connection state in a real PLC; here they are
	// per-service so an attacker who writes and reads back sees consistency.
	coils     []bool
	registers []uint16
}

func newModbus(p *Persona, opts map[string]any) (Service, error) {
	m := &modbusSvc{
		p: p, vendor: "Siemens", product: "SIMATIC S7-1200", revision: "4.4.1",
		coils: make([]bool, 2048), registers: make([]uint16, 2048),
	}
	for k, field := range map[string]*string{"vendor": &m.vendor, "product": &m.product, "revision": &m.revision} {
		if v, ok := opts[k].(string); ok && v != "" {
			*field = v
		}
	}
	// Seed plausible process values so a scan sees a running plant, not zeroes.
	for i := range m.registers {
		m.registers[i] = uint16(m.p.rnd.Intn(1000) + 200)
	}
	for i := range m.coils {
		m.coils[i] = m.p.rnd.Intn(4) == 0
	}
	return m, nil
}

func (m *modbusSvc) Type() string { return "modbus" }

// Modbus function codes.
const (
	fcReadCoils              = 0x01
	fcReadDiscreteInputs     = 0x02
	fcReadHoldingRegisters   = 0x03
	fcReadInputRegisters     = 0x04
	fcWriteSingleCoil        = 0x05
	fcWriteSingleRegister    = 0x06
	fcWriteMultipleCoils     = 0x0f
	fcWriteMultipleRegisters = 0x10
	fcReadDeviceID           = 0x2b
)

func (m *modbusSvc) Serve(ctx context.Context, conn net.Conn, s *Session) error {
	r := bufio.NewReader(conn)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var mbap [7]byte
		if _, err := io.ReadFull(r, mbap[:]); err != nil {
			return nil
		}
		txID := binary.BigEndian.Uint16(mbap[0:2])
		proto := binary.BigEndian.Uint16(mbap[2:4])
		length := int(binary.BigEndian.Uint16(mbap[4:6]))
		unit := mbap[6]

		if proto != 0 || length < 2 || length > 300 {
			s.Note(event.SeverityLow, "malformed Modbus header (proto=%d len=%d)", proto, length)
			return nil
		}
		pdu := make([]byte, length-1)
		if _, err := io.ReadFull(r, pdu); err != nil {
			return nil
		}
		s.Record("in", append(mbap[:], pdu...))

		resp := m.handle(unit, pdu, s)
		if resp == nil {
			return nil
		}
		out := make([]byte, 7+len(resp))
		binary.BigEndian.PutUint16(out[0:], txID)
		binary.BigEndian.PutUint16(out[2:], 0)
		binary.BigEndian.PutUint16(out[4:], uint16(len(resp)+1))
		out[6] = unit
		copy(out[7:], resp)
		s.Record("out", out)
		if _, err := conn.Write(out); err != nil {
			return err
		}
	}
}

func (m *modbusSvc) handle(unit byte, pdu []byte, s *Session) []byte {
	if len(pdu) == 0 {
		return nil
	}
	fc := pdu[0]

	switch fc {
	case fcReadCoils, fcReadDiscreteInputs, fcReadHoldingRegisters, fcReadInputRegisters:
		if len(pdu) < 5 {
			return modbusException(fc, 0x03)
		}
		addr := binary.BigEndian.Uint16(pdu[1:3])
		count := binary.BigEndian.Uint16(pdu[3:5])
		m.record(s, event.SeverityMedium, fc, unit,
			fmt.Sprintf("read %s: %d values from address %d", fcName(fc), count, addr),
			map[string]any{"address": int(addr), "quantity": int(count)},
			event.Technique{Tactic: "TA0102", Technique: "T0846", Name: "Remote System Discovery"})

		if count == 0 || count > 125 {
			return modbusException(fc, 0x03)
		}
		if fc == fcReadCoils || fc == fcReadDiscreteInputs {
			nbytes := (int(count) + 7) / 8
			out := make([]byte, 2+nbytes)
			out[0], out[1] = fc, byte(nbytes)
			for i := 0; i < int(count); i++ {
				if m.coilAt(int(addr) + i) {
					out[2+i/8] |= 1 << (i % 8)
				}
			}
			return out
		}
		out := make([]byte, 2+int(count)*2)
		out[0], out[1] = fc, byte(int(count)*2)
		for i := 0; i < int(count); i++ {
			binary.BigEndian.PutUint16(out[2+i*2:], m.regAt(int(addr)+i))
		}
		return out

	case fcWriteSingleCoil, fcWriteSingleRegister:
		if len(pdu) < 5 {
			return modbusException(fc, 0x03)
		}
		addr := binary.BigEndian.Uint16(pdu[1:3])
		value := binary.BigEndian.Uint16(pdu[3:5])
		// Writing to a PLC is an attempt to change something physical.
		m.record(s, event.SeverityCritical, fc, unit,
			fmt.Sprintf("PROCESS WRITE: %s address %d = 0x%04x", fcName(fc), addr, value),
			map[string]any{"address": int(addr), "value": int(value), "applied": false},
			event.Technique{Tactic: "TA0106", Technique: "T0836", Name: "Modify Parameter"},
			event.Technique{Tactic: "TA0105", Technique: "T0855", Name: "Unauthorized Command Message"})

		if fc == fcWriteSingleCoil {
			m.setCoil(int(addr), value == 0xff00)
		} else {
			m.setReg(int(addr), value)
		}
		return append([]byte{fc}, pdu[1:5]...)

	case fcWriteMultipleCoils, fcWriteMultipleRegisters:
		if len(pdu) < 6 {
			return modbusException(fc, 0x03)
		}
		addr := binary.BigEndian.Uint16(pdu[1:3])
		count := binary.BigEndian.Uint16(pdu[3:5])
		m.record(s, event.SeverityCritical, fc, unit,
			fmt.Sprintf("PROCESS WRITE: %s %d values from address %d", fcName(fc), count, addr),
			map[string]any{
				"address": int(addr), "quantity": int(count),
				"payload_hex": hex.EncodeToString(pdu), "applied": false,
			},
			event.Technique{Tactic: "TA0106", Technique: "T0836", Name: "Modify Parameter"})

		out := make([]byte, 5)
		out[0] = fc
		binary.BigEndian.PutUint16(out[1:], addr)
		binary.BigEndian.PutUint16(out[3:], count)
		return out

	case fcReadDeviceID:
		// Device identification is how an attacker decides what they have
		// found. Answering makes the decoy worth exploring.
		m.record(s, event.SeverityMedium, fc, unit, "device identification requested", nil,
			event.Technique{Tactic: "TA0102", Technique: "T0888", Name: "Remote System Information Discovery"})
		return m.deviceID()

	default:
		m.record(s, event.SeverityHigh, fc, unit,
			fmt.Sprintf("unsupported function code 0x%02x", fc),
			map[string]any{"pdu_hex": hex.EncodeToString(pdu)},
			event.Technique{Tactic: "TA0105", Technique: "T0855", Name: "Unauthorized Command Message"})
		return modbusException(fc, 0x01)
	}
}

func (m *modbusSvc) record(s *Session, sev event.Severity, fc, unit byte, msg string,
	fields map[string]any, techniques ...event.Technique) {

	e := s.Event(event.ClassDecoyInteraction, 1, sev).
		WithMessage("Modbus unit %d: %s", unit, msg).WithAttack(techniques...)
	e.Set("function_code", int(fc)).Set("function", fcName(fc)).Set("unit_id", int(unit))
	for k, v := range fields {
		e.Set(k, v)
	}
	s.Emit(e)
}

func (m *modbusSvc) coilAt(i int) bool {
	if i < 0 || i >= len(m.coils) {
		return false
	}
	return m.coils[i]
}

func (m *modbusSvc) regAt(i int) uint16 {
	if i < 0 || i >= len(m.registers) {
		return 0
	}
	return m.registers[i]
}

func (m *modbusSvc) setCoil(i int, v bool) {
	if i >= 0 && i < len(m.coils) {
		m.coils[i] = v
	}
}

func (m *modbusSvc) setReg(i int, v uint16) {
	if i >= 0 && i < len(m.registers) {
		m.registers[i] = v
	}
}

func (m *modbusSvc) deviceID() []byte {
	objects := []string{m.vendor, m.product, m.revision}
	body := []byte{fcReadDeviceID, 0x0e, 0x01, 0x01, 0x00, 0x00, byte(len(objects))}
	for i, o := range objects {
		body = append(body, byte(i), byte(len(o)))
		body = append(body, o...)
	}
	return body
}

func modbusException(fc, code byte) []byte { return []byte{fc | 0x80, code} }

func fcName(fc byte) string {
	switch fc {
	case fcReadCoils:
		return "read coils"
	case fcReadDiscreteInputs:
		return "read discrete inputs"
	case fcReadHoldingRegisters:
		return "read holding registers"
	case fcReadInputRegisters:
		return "read input registers"
	case fcWriteSingleCoil:
		return "write single coil"
	case fcWriteSingleRegister:
		return "write single register"
	case fcWriteMultipleCoils:
		return "write multiple coils"
	case fcWriteMultipleRegisters:
		return "write multiple registers"
	case fcReadDeviceID:
		return "read device identification"
	default:
		return fmt.Sprintf("function 0x%02x", fc)
	}
}
