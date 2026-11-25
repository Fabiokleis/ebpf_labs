package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CycloneDX 1.7 CBOM JSON structures.
// Ref: https://cyclonedx.org/docs/1.7/json/
type CBOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     CBOMMetadata `json:"metadata"`
	Components   []Component  `json:"components"`
}

type CBOMMetadata struct {
	Timestamp string     `json:"timestamp"`
	Component *Component `json:"component,omitempty"`
}

type Component struct {
	BOMRef           string            `json:"bom-ref,omitempty"`
	Type             string            `json:"type"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CryptoProperties struct {
	AssetType             string                 `json:"assetType"`
	AlgorithmProperties   *AlgorithmProperties   `json:"algorithmProperties,omitempty"`
	CertificateProperties *CertificateProperties `json:"certificateProperties,omitempty"`
	ProtocolProperties    *ProtocolProperties    `json:"protocolProperties,omitempty"`
	RelatedCryptoMaterial *RelatedCryptoMaterial `json:"relatedCryptoMaterialProperties,omitempty"`
}

type ProtocolProperties struct {
	Type           string        `json:"type"`
	Version        string        `json:"version"`
	CipherSuites   []CipherSuite `json:"cipherSuites,omitempty"`
	CryptoRefArray []string      `json:"cryptoRefArray,omitempty"`
}

type CipherSuite struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type AlgorithmProperties struct {
	Primitive              string `json:"primitive"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	Curve                  string `json:"curve,omitempty"`
	Mode                   string `json:"mode,omitempty"`
}

type CertificateProperties struct {
	SubjectName          string `json:"subjectName,omitempty"`
	IssuerName           string `json:"issuerName,omitempty"`
	NotValidBefore       string `json:"notValidBefore,omitempty"`
	NotValidAfter        string `json:"notValidAfter,omitempty"`
	SubjectPublicKeyRef  string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat    string `json:"certificateFormat,omitempty"`
	CertificateExtension string `json:"certificateExtension,omitempty"`
}

type RelatedCryptoMaterial struct {
	Type string `json:"type"`
	Size int    `json:"size,omitempty"`
}

type derivedSuite struct {
	CipherName string
	CipherMode string
	CipherBits string
	HashName   string
	HashBits   string
}

var derivedSuites = map[uint16]derivedSuite{
	0xc030: {CipherName: "AES-256-GCM", CipherMode: "gcm", CipherBits: "256", HashName: "SHA-384", HashBits: "384"},
	0x1302: {CipherName: "AES-256-GCM", CipherMode: "gcm", CipherBits: "256", HashName: "SHA-384", HashBits: "384"},
}

// BuildCBOM converts a completed HandshakeInfo into a CycloneDX 1.7 CBOM document.
func BuildCBOM(hs *HandshakeInfo) CBOM {
	var components []Component
	var protoRefs []string
	var suiteAlgRefs []string

	// 1. Derived symmetric cipher & hash algorithms [D]
	if ds, ok := derivedSuites[hs.CipherID]; ok {
		hs.CipherAlg = ds.CipherName
		hs.HashAlg = ds.HashName
		hs.DerivedStatus = StatusDerived

		cipherRef := "alg-" + strings.ToLower(ds.CipherName)
		hashRef := "alg-" + strings.ToLower(ds.HashName)
		suiteAlgRefs = append(suiteAlgRefs, cipherRef, hashRef)
		protoRefs = append(protoRefs, cipherRef, hashRef)

		components = append(components,
			Component{
				BOMRef: cipherRef,
				Type:   "cryptographic-asset",
				Name:   ds.CipherName,
				CryptoProperties: &CryptoProperties{
					AssetType: "algorithm",
					AlgorithmProperties: &AlgorithmProperties{
						Primitive:              "ae",
						Mode:                   ds.CipherMode,
						ParameterSetIdentifier: ds.CipherBits,
					},
				},
				Properties: []Property{{Name: "cbom:observability", Value: string(StatusDerived)}},
			},
			Component{
				BOMRef: hashRef,
				Type:   "cryptographic-asset",
				Name:   ds.HashName,
				CryptoProperties: &CryptoProperties{
					AssetType: "algorithm",
					AlgorithmProperties: &AlgorithmProperties{
						Primitive:              "hash",
						ParameterSetIdentifier: ds.HashBits,
					},
				},
				Properties: []Property{{Name: "cbom:observability", Value: string(StatusDerived)}},
			},
		)
	}

	// 2. Key exchange group [R]
	if hs.GroupStatus == StatusRegistered {
		groupRef := "kex-" + strings.ToLower(hs.GroupName)
		protoRefs = append(protoRefs, groupRef)

		primitive := "key-agree"
		algProps := &AlgorithmProperties{
			Primitive: primitive,
			Curve:     hs.EllipticCurve,
		}
		if hs.GroupFamily == "ML-KEM" {
			primitive = "kem"
			algProps = &AlgorithmProperties{
				Primitive:              primitive,
				ParameterSetIdentifier: hs.GroupName,
			}
		}

		components = append(components, Component{
			BOMRef: groupRef,
			Type:   "cryptographic-asset",
			Name:   hs.GroupName,
			CryptoProperties: &CryptoProperties{
				AssetType:           "algorithm",
				AlgorithmProperties: algProps,
			},
			Properties: []Property{
				{Name: "cbom:observability", Value: string(hs.GroupStatus)},
				{Name: "cbom:iana-group-id", Value: fmt.Sprintf("0x%04X", hs.GroupID)},
			},
		})
	}

	// 3. Handshake signature scheme [R] (TLS 1.2)
	if hs.SigSchemeStatus == StatusRegistered {
		sigRef := "sig-" + strings.ToLower(hs.SigSchemeName)
		protoRefs = append(protoRefs, sigRef)

		components = append(components, Component{
			BOMRef: sigRef,
			Type:   "cryptographic-asset",
			Name:   hs.SigSchemeName,
			CryptoProperties: &CryptoProperties{
				AssetType: "algorithm",
				AlgorithmProperties: &AlgorithmProperties{
					Primitive: "signature",
				},
			},
			Properties: []Property{
				{Name: "cbom:observability", Value: string(hs.SigSchemeStatus)},
				{Name: "cbom:iana-sig-id", Value: fmt.Sprintf("0x%04X", hs.SigSchemeID)},
			},
		})
	}

	// 4. Server certificate & public key [R] (TLS 1.2 non-truncated)
	if hs.CertStatus == StatusRegistered {
		pubKeyRef := "pubkey-" + hs.CertSHA256[:12]
		certRef := "cert-" + hs.CertSHA256[:12]
		protoRefs = append(protoRefs, certRef)

		components = append(components,
			Component{
				BOMRef: pubKeyRef,
				Type:   "cryptographic-asset",
				Name:   fmt.Sprintf("%s-%d", hs.PubKeyType, hs.PubKeySize),
				CryptoProperties: &CryptoProperties{
					AssetType: "related-crypto-material",
					RelatedCryptoMaterial: &RelatedCryptoMaterial{
						Type: "public-key",
						Size: hs.PubKeySize,
					},
				},
				Properties: []Property{{Name: "cbom:observability", Value: string(hs.CertStatus)}},
			},
			Component{
				BOMRef: certRef,
				Type:   "cryptographic-asset",
				Name:   hs.CertSubject,
				CryptoProperties: &CryptoProperties{
					AssetType: "certificate",
					CertificateProperties: &CertificateProperties{
						SubjectName:          hs.CertSubject,
						IssuerName:           hs.CertIssuer,
						NotValidBefore:       hs.CertNotBefore,
						NotValidAfter:        hs.CertNotAfter,
						SubjectPublicKeyRef:  pubKeyRef,
						CertificateFormat:    "X.509",
						CertificateExtension: "der",
					},
				},
				Properties: []Property{
					{Name: "cbom:observability", Value: string(hs.CertStatus)},
					{Name: "cbom:sha256", Value: hs.CertSHA256},
				},
			},
		)
	}

	// 5. TLS Protocol component (root cryptographic asset)
	protoComp := Component{
		BOMRef:  fmt.Sprintf("tls-%s-pid%d-fd%d", hs.TLSVersion, hs.Pid, hs.Fd),
		Type:    "cryptographic-asset",
		Name:    "TLS",
		Version: hs.TLSVersion,
		CryptoProperties: &CryptoProperties{
			AssetType: "protocol",
			ProtocolProperties: &ProtocolProperties{
				Type:    "tls",
				Version: hs.TLSVersion,
				CipherSuites: []CipherSuite{
					{
						Name:        hs.CipherName,
						Algorithms:  suiteAlgRefs,
						Identifiers: []string{fmt.Sprintf("0x%04X", hs.CipherID)},
					},
				},
				CryptoRefArray: protoRefs,
			},
		},
		Properties: []Property{
			{Name: "cbom:status:version", Value: string(hs.VersionStatus)},
			{Name: "cbom:status:cipher", Value: string(hs.CipherStatus)},
			{Name: "cbom:status:group", Value: string(hs.GroupStatus)},
			{Name: "cbom:status:signature", Value: string(hs.SigSchemeStatus)},
			{Name: "cbom:status:certificate", Value: string(hs.CertStatus)},
			{Name: "cbom:evidence:pid", Value: strconv.FormatUint(uint64(hs.Pid), 10)},
			{Name: "cbom:evidence:fd", Value: strconv.FormatUint(uint64(hs.Fd), 10)},
			{Name: "cbom:evidence:writes", Value: strconv.Itoa(hs.WriteCount)},
			{Name: "cbom:evidence:closed_by", Value: hs.CloseReason},
			{Name: "cbom:evidence:truncated", Value: strconv.FormatBool(hs.Truncated)},
		},
	}

	// Place protocol first for readability
	allComponents := append([]Component{protoComp}, components...)

	return CBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:" + newUUIDv4(),
		Version:      1,
		Metadata: CBOMMetadata{
			Timestamp: hs.Timestamp.Format(time.RFC3339),
			Component: &Component{
				Type: "application",
				Name: hs.Comm,
			},
		},
		Components: allComponents,
	}
}

// WriteCBOM serializes the CBOM to a timestamped JSON file inside outDir.
func WriteCBOM(outDir string, hs *HandshakeInfo) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	doc := BuildCBOM(hs)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("cbom_%s_pid%d_fd%d_tls%s.json",
		hs.Timestamp.Format("20060102T150405Z"),
		hs.Pid, hs.Fd, hs.TLSVersion,
	)
	path := filepath.Join(outDir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
