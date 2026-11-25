package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// Wire-format header sizes.
const (
	// RFC 5246 Section 6.2.1 / RFC 8446 Section 5.1:
	// [1B ContentType][2B LegacyRecordVersion][2B Length]
	tlsRecordHeaderLen = 5

	// RFC 5246 Section 7.4 / RFC 8446 Section 4:
	// [1B HandshakeType][3B Length]
	tlsHandshakeHeaderLen = 4
)

// TLS Record ContentType values.
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
const (
	recChangeCipherSpec uint8 = 0x14
	recAlert            uint8 = 0x15
	recHandshake        uint8 = 0x16
	recApplicationData  uint8 = 0x17
)

// TLS HandshakeType values.
// Ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4
const (
	hsClientHello       uint8 = 0x01
	hsServerHello       uint8 = 0x02
	hsNewSessionTicket  uint8 = 0x04
	hsCertificate       uint8 = 0x0b
	hsServerKeyExchange uint8 = 0x0c
	hsServerHelloDone   uint8 = 0x0e
	hsClientKeyExchange uint8 = 0x10
)

// TLS ExtensionType values.
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
const (
	extSupportedVersions uint16 = 0x002b // RFC 8446 Section 4.2.1
	extKeyShare          uint16 = 0x0033 // RFC 8446 Section 4.2.8
)

// FieldStatus classifies each CBOM field according to Table VII.
type FieldStatus string

const (
	StatusRegistered    FieldStatus = "R"
	StatusDerived       FieldStatus = "D"
	StatusNRProtocol    FieldStatus = "NR: protocolo"
	StatusNRObservation FieldStatus = "NR: ponto de observação"
	StatusNRImpl        FieldStatus = "NR: implementação"
)

// HandshakeInfo holds runtime observations aligned with Table V and Table IX.
type HandshakeInfo struct {
	Pid         uint32
	Fd          uint32
	Comm        string
	Timestamp   time.Time
	WriteCount  int
	OrigLen     uint32
	CapLen      uint32
	Truncated   bool
	Complete    bool
	CloseReason string

	TLSVersion    string
	VersionStatus FieldStatus

	CipherID     uint16
	CipherName   string
	CipherStatus FieldStatus

	GroupID       uint16
	GroupName     string
	GroupFamily   string
	EllipticCurve string
	GroupStatus   FieldStatus

	SigSchemeID     uint16
	SigSchemeName   string
	SigSchemeStatus FieldStatus

	CipherAlg     string
	HashAlg       string
	DerivedStatus FieldStatus

	CertSubject   string
	CertIssuer    string
	CertNotBefore string
	CertNotAfter  string
	CertSHA256    string
	PubKeyType    string
	PubKeySize    int
	CertStatus    FieldStatus
}

// IANA TLS Cipher Suite Registry.
// Ref: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
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
// Ref: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7
var groupTable = map[uint16]groupSpec{
	0x0017: {"secp256r1", "ECDH", "NIST/P-256"},
	0x0018: {"secp384r1", "ECDH", "NIST/P-384"},
	0x0019: {"secp521r1", "ECDH", "NIST/P-521"},
	0x001d: {"x25519", "ECDH", "other/Curve25519"},
	0x001e: {"x448", "ECDH", "other/Curve448"},
	0x11ec: {"X25519MLKEM768", "ML-KEM", "X25519MLKEM768"},
}

// IANA TLS SignatureScheme Registry.
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
var sigSchemeNames = map[uint16]string{
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
}

// recTypeName maps a TLS Record ContentType byte to its RFC name.
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
func recTypeName(t uint8) string {
	switch t {
	case recChangeCipherSpec:
		return "ChangeCipherSpec"
	case recAlert:
		return "Alert"
	case recHandshake:
		return "Handshake"
	case recApplicationData:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", t)
	}
}

// hsTypeName maps a TLS HandshakeType byte to its RFC name.
// Ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4
// Ref: https://datatracker.ietf.org/doc/html/rfc8446#section-4
func hsTypeName(t uint8) string {
	switch t {
	case hsClientHello:
		return "ClientHello"
	case hsServerHello:
		return "ServerHello"
	case hsNewSessionTicket:
		return "NewSessionTicket"
	case hsCertificate:
		return "Certificate"
	case hsServerKeyExchange:
		return "ServerKeyExchange"
	case hsServerHelloDone:
		return "ServerHelloDone"
	case hsClientKeyExchange:
		return "ClientKeyExchange"
	default:
		return fmt.Sprintf("Other(0x%02X)", t)
	}
}

func readUint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// NewHandshakeInfo initializes a flight with fail-closed defaults:
// TLSVersion starts as "1.2" (upgraded to "1.3" only if extension 0x002b is present)
// and optional fields start as StatusNRImpl until observed.
func NewHandshakeInfo(pid, fd uint32, comm string) *HandshakeInfo {
	return &HandshakeInfo{
		Pid:             pid,
		Fd:              fd,
		Comm:            comm,
		Timestamp:       time.Now().UTC(),
		TLSVersion:      "1.2",
		GroupName:       "none",
		GroupStatus:     StatusNRImpl,
		SigSchemeName:   "none",
		SigSchemeStatus: StatusNRImpl,
		CertStatus:      StatusNRImpl,
	}
}

// ParseRecords decodes cleartext TLS handshake records (0x16) from a single write() buffer.
func ParseRecords(payload []byte, info *HandshakeInfo, origLen uint32) {
	info.WriteCount++
	slog.Info("write captured",
		"write_seq", info.WriteCount,
		"pid", info.Pid,
		"fd", info.Fd,
		"orig_bytes", origLen,
		"cap_bytes", len(payload),
	)

	buf := payload
	for len(buf) >= tlsRecordHeaderLen {
		recType := buf[0]
		recLen := int(binary.BigEndian.Uint16(buf[3:5]))
		buf = buf[tlsRecordHeaderLen:]

		if recType != recHandshake {
			info.Complete = true
			info.CloseReason = recTypeName(recType)
			return
		}

		if recLen > len(buf) {
			info.Truncated = true
			slog.Warn("record truncated", "pid", info.Pid, "fd", info.Fd, "declared", recLen, "available", len(buf))
			parseHandshakeMessages(buf, info)
			return
		}

		parseHandshakeMessages(buf[:recLen], info)
		buf = buf[recLen:]

		if info.Complete {
			return
		}
	}
}

// parseHandshakeMessages iterates over 4-byte-framed handshake messages inside a single TLS record.
func parseHandshakeMessages(rec []byte, info *HandshakeInfo) {
	for len(rec) >= tlsHandshakeHeaderLen {
		hsType := rec[0]
		hsLen := readUint24(rec[1:4])
		rec = rec[tlsHandshakeHeaderLen:]

		if hsLen > len(rec) {
			info.Truncated = true
			slog.Warn("handshake message truncated",
				"pid", info.Pid, "fd", info.Fd,
				"msg", hsTypeName(hsType), "declared", hsLen, "available", len(rec),
			)
			return
		}

		body := rec[:hsLen]
		rec = rec[hsLen:]

		dispatchHandshakeMessage(hsType, body, info)
		if info.Complete {
			return
		}
	}
}

func dispatchHandshakeMessage(hsType uint8, body []byte, info *HandshakeInfo) {
	switch hsType {
	case hsServerHello:
		parseServerHello(body, info)
		if info.TLSVersion == "1.3" {
			info.SigSchemeStatus = StatusNRProtocol
			info.CertStatus = StatusNRProtocol
			info.Complete = true
			info.CloseReason = "tls1.3_encrypted_boundary"
		}
	case hsCertificate:
		parseCertificate(body, info)
	case hsServerKeyExchange:
		parseServerKeyExchange(body, info)
	case hsServerHelloDone:
		info.Complete = true
		info.CloseReason = "ServerHelloDone"
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
		case extSupportedVersions:
			if len(extData) >= 2 && binary.BigEndian.Uint16(extData[0:2]) == 0x0304 {
				info.TLSVersion = "1.3"
			}
		case extKeyShare:
			if len(extData) >= 2 {
				setGroup(info, binary.BigEndian.Uint16(extData[0:2]))
			}
		}
	}
}

// parseCertificate decodes the leaf X.509 DER certificate from a TLS 1.2 Certificate message.
// Ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
func parseCertificate(body []byte, info *HandshakeInfo) {
	if len(body) < 6 {
		info.CertStatus = StatusNRImpl
		return
	}

	certLen := readUint24(body[3:6])
	if 6+certLen > len(body) {
		info.Truncated = true
		info.CertStatus = StatusNRImpl
		return
	}

	der := body[6 : 6+certLen]
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		info.CertStatus = StatusNRImpl
		return
	}

	sum := sha256.Sum256(der)
	info.CertSubject = cert.Subject.String()
	info.CertIssuer = cert.Issuer.String()
	info.CertNotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	info.CertNotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	info.CertSHA256 = hex.EncodeToString(sum[:])
	info.PubKeyType = cert.PublicKeyAlgorithm.String()
	if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		info.PubKeySize = rsaPub.N.BitLen()
	}
	info.CertStatus = StatusRegistered
}

// parseServerKeyExchange extracts NamedGroup and SignatureScheme from TLS 1.2 ECDHE ServerKeyExchange.
// Ref: https://datatracker.ietf.org/doc/html/rfc8422#section-5.4
func parseServerKeyExchange(body []byte, info *HandshakeInfo) {
	// ECCurveType 0x03 = named_curve, 2-byte NamedGroup, 1-byte point length
	if len(body) < 4 || body[0] != 0x03 {
		return
	}
	setGroup(info, binary.BigEndian.Uint16(body[1:3]))

	pointLen := int(body[3])
	sigOffset := 4 + pointLen
	if sigOffset+2 <= len(body) {
		setSigScheme(info, binary.BigEndian.Uint16(body[sigOffset:sigOffset+2]))
	}
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

func setSigScheme(info *HandshakeInfo, id uint16) {
	info.SigSchemeID = id
	if name, ok := sigSchemeNames[id]; ok {
		info.SigSchemeName = name
		info.SigSchemeStatus = StatusRegistered
	} else {
		info.SigSchemeName = fmt.Sprintf("0x%04X", id)
		info.SigSchemeStatus = StatusNRImpl
	}
}
