# STCP and SUDP Server-Mediated Architecture & Cryptographic Threat Model

## 1. Executive Summary

Secret TCP (STCP) and Secret UDP (SUDP) are FRP proxy types designed to allow secure, portless service exposure between a target service client (`frpc`) and one or more authorized visitor clients (`frpc visitor`) mediated by the FRP server (`frps`).

Historically, users have frequently assumed STCP and SUDP provide true End-to-End Encryption (E2EE) where the central server acts solely as a blind bit relay. This document establishes the definitive cryptographic threat model, clarifies the hop-by-hop server-mediated encryption architecture, details encryption key separation, and outlines security recommendations for deploying STCP and SUDP in zero-trust environments.

---

## 2. Server-Mediated Architecture (Hop-by-Hop Relaying)

Rather than establishing an end-to-end cryptographic channel directly between the visitor and the client, STCP and SUDP employ a **server-mediated, hop-by-hop relay architecture**:

```
+--------------------+        Public / Untrusted Network        +--------------------+
|    Visitor Client  | ---------------------------------------> |     FRP Server     |
|       (frpc)       |    Hop 1: Encrypted with SecretKey (sk)   |       (frps)       |
+--------------------+                                          +--------------------+
                                                                          |
                                                               [Cleartext in Memory]
                                                               [  joinUserConnection  ]
                                                                          |
+--------------------+        Public / Untrusted Network                  v
|    Target Client   | <--------------------------------------- +--------------------+
|       (frpc)       |    Hop 2: Encrypted with Client Key / TLS |     FRP Server     |
+--------------------+                                          +--------------------+
```

### Hop 1: Visitor to Server (`VisitorManager.NewConn`)
1. **Authentication**: The visitor initiates a connection to `frps` with a `NewVisitorConn` message containing the proxy name, timestamp, signature (`SignKey = md5(sk + timestamp)`), and optional RunID.
2. **Access Control & Decryption**: FRPS verifies the timestamp freshness (within 60 seconds), validates the signature with constant-time equality against the configured `SecretKey` (`l.sk`), and confirms tenant permissions (`allowUsers`).
3. If `useEncryption` is enabled, FRPS wraps the connection with a symmetric stream cipher initialized with `l.sk` (`server/visitor/visitor.go:101`):
   ```go
   rwc, err = libio.WithEncryption(rwc, []byte(l.sk))
   ```
4. **Decryption to Plaintext**: As bytes are read from the visitor stream by FRPS, they are decrypted by FRPS into plaintext application data.

### Hop 2: Server to Target Client (`BaseProxy.handleUserTCPConnection`)
1. **Work Connection Retrieval**: FRPS obtains an active multiplexed work connection to the target client.
2. **Re-encryption**: In `server/proxy/proxy.go:371`, if proxy transport encryption is enabled, FRPS re-encrypts the stream to the client using `pxy.encryptionKey`:
   ```go
   local, err = libio.WithEncryption(local, pxy.encryptionKey)
   ```
   *(Note: If OIDC token authentication is used without a shared token secret, `pxy.encryptionKey` may be empty, and transport security relies on outer TLS/QUIC).*
3. **Stream Bridging**: In `joinUserConnection`, FRPS bridges `local` (to client) and `userConn` (from visitor) using `libio.Join`.

---

## 3. Cryptographic Threat Model & Cleartext Memory Exposure

### 3.1 Plaintext Exposure in Server Memory
Because FRPS terminates visitor decryption on Hop 1 before re-encrypting for Hop 2, **the unencrypted byte stream transiently exists in plaintext within `frps` process memory during bridging**:
- An attacker with root, kernel, debugger, or memory inspection access (e.g. `gcore`, `/proc/$PID/mem`) on the `frps` host can intercept and reconstruct cleartext payloads.
- If TLS is terminated before FRPS or if FRPS is compromised, confidentiality is lost at the server boundary.

### 3.2 Encryption Key Separation
- **Visitor Secret Key (`SecretKey`)**: Shared exclusively between the visitor client configuration and the proxy definition. It is used to authenticate the visitor to FRPS and encrypt Hop 1.
- **Client Transport Key (`encryptionKey`)**: Derived from the client's token or transport session. It protects Hop 2 between FRPS and the target client.
- FRPS holds or has access to both keys, acting as an intentional, authorized cryptographic intermediary.

---

## 4. Threat Matrix & Mitigations

| Threat | Vulnerability Level | Mitigation / Architecture Recommendation |
|---|---|---|
| **Public Network Eavesdropper** | Protected | Protected by AES/stream encryption on Hop 1 and Hop 2. Eavesdroppers cannot view payload. |
| **Unauthorized Visitor Connection** | Protected | Protected by constant-time signature verification (`SignKey`), 60s timestamp window, and tenant isolation (`allowUsers` / `RunID`). |
| **Compromised FRPS Host** | Vulnerable | FRPS has access to plaintext memory. Use Application-Layer TLS or XTCP. |
| **OIDC / Keyless Client Transport** | Potentially Vulnerable if Outer TLS Disabled | Enforce outer TLS (`transport.tls.force = true`) so Hop 2 is encrypted via TLS even when `encryptionKey` is empty. |

---

## 5. Deployment Recommendations for Zero-Trust Environments

1. **Application-Layer End-to-End Encryption (Recommended)**:
   For sensitive services (SSH, HTTPS, databases, internal APIs), always run application-layer encryption **inside** the STCP/SUDP tunnel:
   - For web services: Run HTTPS backends (e.g., visitor dials `https://localhost:<visitor_port>`).
   - For shell access: Run SSH over STCP. SSH provides authenticated, zero-trust cryptographic end-to-end security independent of FRPS.
2. **XTCP for Direct P2P Communication**:
   If true peer-to-peer transport without server memory mediation is required, use **XTCP** (NAT hole punching). Once the STUN punch succeeds, traffic flows directly peer-to-peer between `frpc` instances without traversing FRPS memory.
3. **Enforce Tenant RunID Isolation**:
   Always configure distinct `user` tenant namespaces. With CANON-100, unauthenticated visitors omitting `RunID` are rejected from accessing namespaced tenant proxies.
