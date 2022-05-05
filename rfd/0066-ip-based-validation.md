---
authors: Przemko Robakowski(przemko.robakowski@goteleport.com)
state: draft
---

# RFD 66 - IP-based validation

# Required Approvers

* Engineering @zmb3 && (@codingllama || @nklaassen )
* Product: (@xinding33 || @klizhentas )

## What

Additional validation based on client IP for creating and using certificates. User can define which IP addresses can
create certificates and from where they can be used.

## Why

It provides additional security against leaked credentials, if adversary gets hold of certificate he won't be able to
use them outside machine that created it. It also forms part of user identity.

Relevant issue: [#7081](https://github.com/gravitational/teleport/issues/7081)

## Details

### Configuration

New field will be added to role options definition:

* `pin_source_ip` - defines if certificate should be pinned to the IP of the client requesting it.

Example configuration:

```yaml
kind: role
metadata:
  name: dev
spec:
  options:
    pin_source_ip: true
```

### Implementation

Following definition will be added to `types.proto`:

```protobuf
message RoleOptions {
  // ...

  // PinSourceIP defines if certificate should be pinned to the IP of the client requesting it.
  bool PinSourceIP = 18 [(gogoproto.jsontag) = "pin_source_ip", (gogoproto.casttype) = "Bool"];
}
```

If any role has `PinSourceIP` set to `true` then IP of the client requesting certificate will be encoded depending on
certificate type:

* SSH certificate will encode IP using `source-address` critical option as defined
  by [OpenSSH](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD). This option is recognized
  by `sshd` from OpenSSH and also by Go's [ssh package](https://pkg.go.dev/golang.org/x/crypto/ssh), so it will be
  enforced automatically in Teleport.
* TLS certificates (used by DB, Kubernetes, Application and Desktop access) will encode IP in custom extension with OID
  from range `1.3.9999`, similar to `KubeUsers` and others in [tls/ca.go](tls/ca.go). It will be then decoded as part
  of `tlsca.Identity` and validated in authorization routines in respective services. It will be also stored in JWT
  token in Application access.

Encoding above will happen in all places we generate certificates: 
* `lib/auth/auth.go#generateUserCert`
* `lib/auth/join.go#generateCerts` (Machine ID)
* `lib/auth/auth_with_roles.go#generateUserCerts()` (renewals, impersonation etc)

### UX

This change should be mostly transparent for the user. Administrator will add relevant option to role definitions and
should work for all users.

If user tries to use certificate on other machine (different IP) `tsh` will force relogin as it currently does when
certificate expires.

### Security

This proposal does not protect against IP spoofing, but it should provide at least the same level of security as we have
today (as this additional protection, not replacement for user authentication).