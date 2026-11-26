## OpenSSL

> **Note:** Run all commands below from the repository root (`ebpf_lab/`) so paths under `artifacts/` resolve properly.

### Certificates

*small certificate < 4KB*:
```shell
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout artifacts/key.pem -out artifacts/cert_small.pem \
  -days 365 -subj "/CN=localhost"
```

*4KB SANs >*
```shell
python3 -c '
sans = ",".join([f"DNS:san-{i:03d}.experimento.utfpr.edu.br" for i in range(250)])
print(f"[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName={sans}")
' > artifacts/san.cnf
```

*large certificate*
```shell
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout artifacts/key_large.pem -out artifacts/cert_large.pem \
  -days 365 -subj "/CN=localhost" -config artifacts/san.cnf
```

### OpenSSL server

`artifacts/openssl.cnf` mirrors the `-cipher`/`-ciphersuites` flags so the
static scanner (CBOMkit-theia, below) reads the same TLS configuration the
server loads. Loading it via `OPENSSL_CONF` does not change the negotiation
(TLS 1.2: `0xC030`, X25519, `rsa_pss_rsae_sha256`; TLS 1.3: `0x1302`,
X25519MLKEM768).

*small cert:*
```shell
OPENSSL_CONF=artifacts/openssl.cnf openssl s_server -accept 4433 \
  -cert artifacts/cert_small.pem -key artifacts/key.pem \
  -cipher ECDHE-RSA-AES256-GCM-SHA384 \
  -ciphersuites TLS_AES_256_GCM_SHA384
```

*large cert*
```shell
OPENSSL_CONF=artifacts/openssl.cnf openssl s_server -accept 4433 \
  -cert artifacts/cert_large.pem -key artifacts/key_large.pem \
  -cipher ECDHE-RSA-AES256-GCM-SHA384 \
  -ciphersuites TLS_AES_256_GCM_SHA384
```

### OpenSSL clients

*tls 1.2*:
```shell
openssl s_client -connect 127.0.0.1:4433 -tls1_2
```
*tls 1.3*:
```shell
openssl s_client -connect 127.0.0.1:4433 -tls1_3
```

## Static CBOM (CBOMkit-theia)

Static baseline for the comparison: [CBOMkit-theia](https://github.com/cbomkit/cbomkit-theia)
`dir` over the same server files (certificates, keys, `openssl.cnf`).
No container runtime is needed for `dir`.

### Build (pinned to v1.1.2, inside `nix-shell shell.nix`)

```shell
git clone https://github.com/cbomkit/cbomkit-theia.git ../cbomkit-theia
git -C ../cbomkit-theia checkout v1.1.2   # commit dcd95ac
(cd ../cbomkit-theia && CGO_ENABLED=0 go build \
  -ldflags '-X github.com/cbomkit/cbomkit-theia/scanner.Version=v1.1.2' \
  -o cbomkit-theia .)
```

Without `-ldflags`, the CBOM reports the tool version as `edge`.

### Scan

```shell
mkdir -p artifacts/cbom_static
../cbomkit-theia/cbomkit-theia dir artifacts \
  --ignore 'cbom/,cbom_static/,san.cnf,environment.txt' \
  > artifacts/cbom_static/cbom_theia_dir.json
```

Default plugins in v1.1.2: `certificates,javasecurity,secrets,opensslconf,problematicca`.

### Validation

The theia output is CycloneDX **1.6** (the runtime CBOM is 1.7), so validate it against the 1.6 schema:

```shell
check-jsonschema --schemafile https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json artifacts/cbom_static/cbom_theia_dir.json
```

### What theia reports (v1.1.2)

| Source | Components |
|---|---|
| `cert_small.pem`, `cert_large.pem` | `certificate` (subject/issuer `localhost`, validity), public key `RSA-2048`, algorithms `RSA`, `SHA256`, `SHA256-RSA` (certificate signature) |
| `key.pem`, `key_large.pem` | private key `RSA-2048` |
| `openssl.cnf` | `protocol` TLSv1.2 and TLSv1.3, both listing suite `TLS_AES_256_GCM_SHA384` (`0x13,0x02`); `AES256 GCM`, `SHA384`; properties `MinProtocol`, `MaxProtocol`, `CipherString=ECDHE-RSA-AES256-GCM-SHA384` |

Limitations of the `opensslconf` plugin that matter for the comparison:
- It only recognizes `TLS_*` names. `CipherString` in OpenSSL syntax (`ECDHE-RSA-AES256-GCM-SHA384`) stays a text property and is never mapped to `0xC030`.
- It assigns every suite found to every version from `Min/MaxProtocol`, so TLSv1.2 ends up with a TLS 1.3-only suite.
- It does not read `Groups`/`SignatureAlgorithms`, so no key exchange group or handshake signature appears.
- `dir` does not identify the OpenSSL library or its version.
- Without `artifacts/openssl.cnf` (configuration only on the `s_server` command line), the `opensslconf` plugin produces no `protocol` component.

### Comparison keys

| Asset | Runtime CBOM | Static CBOM | Normalization |
|---|---|---|---|
| Suite | `identifiers: ["0xC030"]` / `["0x1302"]` | `identifiers: ["0x13","0x02"]` | join the bytes → `0x1302` |
| Certificate | property `cbom:sha256` (DER) | no fingerprint; `subjectName`, `notValidBefore`, public key `value` (SPKI) | compute the SHA-256 of the DER: `openssl x509 -in artifacts/cert_small.pem -outform DER \| openssl dgst -sha256` (`31cc381efd33…` = small, `4991285281e4…` = large) |
