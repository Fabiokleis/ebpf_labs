package main

import (
	"encoding/binary"
	"fmt"
	"time"
)

// FieldStatus classifies CBOM fields
type FieldStatus string

const (
	StatusRegistered    FieldStatus = "R"
	StatusDerived       FieldStatus = "D"
	StatusNRProtocol    FieldStatus = "NR: protocolo"
	StatusNRObservation FieldStatus = "NR: ponto de observação"
	StatusNRImpl        FieldStatus = "NR: implementação"
)

// HandshakeInfo holds runtime observations
type HandshakeInfo struct {
	// Application & process context (metadata.component, evidence)
	Pid       uint32
	Fd        uint32
	Comm      string
	Timestamp time.Time
	OrigLen   uint32
	CapLen    uint32
	Truncated bool

	// Protocol & version (protocolProperties.version)
	TLSVersion    string
	VersionStatus FieldStatus

	// Cipher suite (protocolProperties.cipherSuites[])
	CipherID     uint16
	CipherName   string
	CipherStatus FieldStatus

	// Key exchange group (tlsGroups + algorithmProperties)
	GroupID       uint16
	GroupName     string
	GroupFamily   string
	EllipticCurve string
	GroupStatus   FieldStatus

	// Handshake signature scheme
	SigSchemeID     uint16
	SigSchemeName   string
	SigSchemeStatus FieldStatus

	// Derived suite algorithms
	CipherAlg     string
	HashAlg       string
	DerivedStatus FieldStatus

	// Certificate & public key
	CertSubject   string
	CertIssuer    string
	CertNotBefore string
	CertNotAfter  string
	CertSHA256    string
	PubKeyType    string
	PubKeySize    int
	CertStatus    FieldStatus
}

var cipherNames = map[uint16]string{
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0x1302: "TLS_AES_256_GCM_SHA384",
}

type groupSpec struct {
	Name   string
	Family string
	Curve  string
}

// IANA TLS Supported Groups mapped to CycloneDX 1.7 normalization values.
var groupTable = map[uint16]groupSpec{
	0x0017: {"secp256r1", "ECDH", "NIST/P-256"},
	0x0018: {"secp384r1", "ECDH", "NIST/P-384"},
	0x0019: {"secp521r1", "ECDH", "NIST/P-521"},
	0x001d: {"x25519", "ECDH", "other/Curve25519"},
	0x001e: {"x448", "ECDH", "other/Curve448"},
	0x11ec: {"X25519MLKEM768", "ML-KEM", "X25519MLKEM768"},
}

func ParseHandshake(payload []byte) (*HandshakeInfo, error) {
	// TLS record header (5B) + handshake header (4B) + min ServerHello body (38B)
	if len(payload) < 47 {
		return nil, fmt.Errorf("short payload: %d bytes", len(payload))
	}
	if payload[0] != 0x16 || payload[5] != 0x02 {
		return nil, fmt.Errorf("not a ServerHello message")
	}

	info := &HandshakeInfo{
		TLSVersion:  "1.2",
		GroupName:   "none",
		GroupStatus: StatusNRImpl,
	}

	buf := payload
	for len(buf) >= 5 {
		recType := buf[0]
		recLen := int(binary.BigEndian.Uint16(buf[3:5]))
		buf = buf[5:]

		// Stop on non-handshake records (0x14 ChangeCipherSpec, 0x17 encrypted)
		if recType != 0x16 {
			break
		}
		if recLen > len(buf) {
			info.Truncated = true
			break
		}

		parseHandshakeRecord(buf[:recLen], info)
		buf = buf[recLen:]

		// In TLS 1.3, all messages after ServerHello are encrypted
		if info.TLSVersion == "1.3" {
			break
		}
	}

	return info, nil
}

func parseHandshakeRecord(rec []byte, info *HandshakeInfo) {
	for len(rec) >= 4 {
		hsType := rec[0]
		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		rec = rec[4:]

		if hsLen > len(rec) {
			info.Truncated = true
			return
		}

		body := rec[:hsLen]
		rec = rec[hsLen:]

		switch hsType {
		case 0x02: // ServerHello
			parseServerHello(body, info)
		case 0x0c: // ServerKeyExchange (TLS 1.2, RFC 8422 Section 5.4)
			parseServerKeyExchange(body, info)
		}
	}
}

func parseServerHello(body []byte, info *HandshakeInfo) {
	if len(body) < 38 {
		return
	}

	sidLen := int(body[34])
	if 35+sidLen+3 > len(body) {
		return
	}

	rest := body[35+sidLen:]
	info.CipherID = binary.BigEndian.Uint16(rest[0:2])
	info.CipherStatus = StatusRegistered
	info.VersionStatus = StatusRegistered

	if name, ok := cipherNames[info.CipherID]; ok {
		info.CipherName = name
	} else {
		info.CipherName = fmt.Sprintf("0x%04X", info.CipherID)
	}

	// Skip cipher suite (2B) and compression method (1B)
	rest = rest[3:]
	if len(rest) < 2 {
		return
	}

	extLen := int(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if extLen > len(rest) {
		extLen = len(rest)
	}

	parseExtensions(rest[:extLen], info)
}

func parseExtensions(extBuf []byte, info *HandshakeInfo) {
	for len(extBuf) >= 4 {
		extType := binary.BigEndian.Uint16(extBuf[0:2])
		extLen := int(binary.BigEndian.Uint16(extBuf[2:4]))
		extBuf = extBuf[4:]

		if extLen > len(extBuf) {
			return
		}

		extData := extBuf[:extLen]
		extBuf = extBuf[extLen:]

		switch extType {
		case 0x002b: // supported_versions (0x0304 = TLS 1.3)
			if len(extData) >= 2 && binary.BigEndian.Uint16(extData[0:2]) == 0x0304 {
				info.TLSVersion = "1.3"
			}
		case 0x0033: // key_share (RFC 8446 Section 4.2.8)
			if len(extData) >= 2 {
				setGroup(info, binary.BigEndian.Uint16(extData[0:2]))
			}
		}
	}
}

func parseServerKeyExchange(body []byte, info *HandshakeInfo) {
	// ECCurveType 0x03 = named_curve, followed by 2-byte NamedGroup ID
	if len(body) < 3 || body[0] != 0x03 {
		return
	}
	setGroup(info, binary.BigEndian.Uint16(body[1:3]))
}

func setGroup(info *HandshakeInfo, id uint16) {
	info.GroupID = id
	if g, ok := groupTable[id]; ok {
		info.GroupName = g.Name
		info.GroupFamily = g.Family
		info.EllipticCurve = g.Curve
		info.GroupStatus = StatusRegistered
	} else {
		info.GroupName = fmt.Sprintf("0x%04X", id)
		info.GroupStatus = StatusNRImpl
	}
}
