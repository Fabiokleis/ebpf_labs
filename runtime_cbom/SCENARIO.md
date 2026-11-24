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

*small cert:*
```shell
openssl s_server -accept 4433 \
  -cert artifacts/cert_small.pem -key artifacts/key.pem \
  -cipher ECDHE-RSA-AES256-GCM-SHA384 \
  -ciphersuites TLS_AES_256_GCM_SHA384
```

*large cert*
```
openssl s_server -accept 4433 \
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
