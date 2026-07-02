# ADR 0001: Encryption scheme and key custody for R2 bug-report objects

- **Status:** Accepted
- **Date:** 2026-07-02
- **Deciders:** Maintainer (single-maintainer project)
- **Ticket:** [#5](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/5) — Decision: encryption scheme + key custody (Cloudflare Secret Manager)
- **Unblocks:** [#9](https://github.com/JMR-dev/LibreMail-Bug-Report-Ingest/issues/9) — encrypted-at-rest R2 storage
- **Related:** [JMR-dev/LibreMail#11](https://github.com/JMR-dev/LibreMail/issues/11) (open question: "Encryption scheme + key custody for R2 objects")

---

## Context

A Cloudflare Worker (Go, compiled with TinyGo to Wasm) ingests LibreMail debug bug-reports
over HTTPS, best-effort scrubs PII, and stores each scrubbed report in a Cloudflare R2
bucket. A scheduled job later reads the stored reports, decrypts them, and publishes each as
a GitHub issue on the LibreMail repo. Secrets live in Cloudflare Secrets Store (a.k.a.
Cloudflare Secret Manager). There is a single maintainer and the volume is low (individual
opt-in bug reports, published weekly).

**Why encryption at rest is not enough by default:** PII scrubbing is explicitly
*best-effort*. Reports can contain residual PII (log fragments, stack traces, free-text
descriptions, device identifiers, e-mail-shaped strings the scrubber missed). We therefore
need the stored objects to be **unreadable to anyone who obtains read access to the bucket
but who does not hold the maintainer's key**.

### Threat model

In scope — what we defend against:

1. **Bucket-read compromise.** A leaked or over-scoped R2 API token, an S3-credential leak,
   a bucket misconfiguration, or an accidentally public bucket. An attacker can `GET`/`LIST`
   objects but does not have the encryption key.
2. **Storage-layer / at-rest disclosure.** Access to the raw stored bytes (backups, disks,
   the R2 storage service) without the key.
3. **Object tampering / substitution.** An attacker who can write to the bucket swaps or
   mutates an object to corrupt or spoof a published issue.

Out of scope — explicitly *not* defended against (documented so we do not overclaim):

- **A fully compromised or malicious Cloudflare platform.** The Worker's compute runs on
  Cloudflare and the key is held in Cloudflare Secrets Store, so Cloudflare-the-platform is
  necessarily trusted with plaintext at processing time. Defending against the compute
  provider itself would require the app to never possess the key on Cloudflare (e.g.
  decrypt only on the maintainer's own hardware) and is not a goal here.
- **A compromised Worker isolate at runtime** (it legitimately holds plaintext and the key).
- **The published GitHub issues themselves** (post-publication confidentiality is a separate
  concern governed by scrubbing quality and repo visibility).

The meaningful, realistic win is category 1/2/3: the object bytes at rest are opaque and
tamper-evident to anyone without the key.

---

## Options evaluated

### Option A — R2 default encryption at rest (Cloudflare-managed keys)

R2 encrypts all objects at rest with AES-256 automatically; keys are managed by Cloudflare.
No code, nothing to configure.

- **Pros:** Zero effort, transparent, always on, no key to lose.
- **Cons:** Cloudflare holds the keys, and *any principal with bucket read access reads
  plaintext* (this is exactly threat #1). It protects only against raw-disk theft, which is
  not our primary threat. **Does not meet the requirement.**

### Option B — R2 SSE-C (server-side encryption, customer-provided key)

R2 supports SSE-C: the client supplies a 256-bit key on each `PUT`/`GET`; R2 encrypts with
it and **removes the key from memory after the operation** (Cloudflare cannot recover objects
without the key). Available via the Workers and S3 APIs.

- **Pros:** Objects at rest are encrypted under a key Cloudflare does not retain; protects
  against threat #1/#2. Very little code.
- **Cons:**
  - **Plaintext and the key are sent to the R2 service on every request** — R2 performs the
    crypto server-side. The plaintext-exposure surface at the storage boundary is larger than
    Option C, and you are trusting R2 to actually drop the key each time.
  - We do not control the ciphertext format, the integrity binding, or key-versioning; we
    inherit R2's behavior. Rotation means re-`PUT`ting objects under a new key.
  - The key must still be held by the caller (the Worker) anyway — so custody is no simpler
    than Option C, but we get less control.
  - Coupled to R2/Cloudflare; not portable.

### Option C — Worker-side authenticated encryption before write (chosen)

The Worker encrypts each scrubbed report with **AES-256-GCM** *before* writing to R2, using
key material from Cloudflare Secrets Store. Only ciphertext is ever handed to R2.

- **Pros:**
  - **R2 never receives plaintext or the key** — it only ever stores opaque bytes. Smallest
    storage-boundary exposure of the three options. Fully covers threats #1/#2.
  - **Authenticated encryption**: GCM's tag gives integrity + tamper detection (threat #3);
    additional authenticated data (AAD) binds the format and key version so objects cannot be
    silently downgraded or transplanted.
  - We own the format, key-versioning, and rotation → clean rotation without data loss.
  - Portable, standard primitive; not locked to any R2/Cloudflare crypto feature.
  - Defense-in-depth layered on top of best-effort scrubbing.
- **Cons:**
  - We must manage a key and its rotation (mitigations below).
  - **Key loss = permanent data loss** for not-yet-published reports (mitigated by an offline
    keyring backup).
  - Must implement AES-GCM in the TinyGo/Wasm environment (see the crypto-provider note).

> **Terminology.** The ticket calls this "envelope encryption." Strictly, envelope
> encryption means generating a per-object *data key* (DEK) and wrapping it with a *key
> encryption key* (KEK). At this scale we adopt the simpler equivalent: a single active
> AES-256 data key selected from a versioned keyring, applied directly with AEAD. The true
> per-object-DEK variant is discussed under [Alternatives considered](#alternatives-considered);
> it is not needed here and adds moving parts.

---

## Decision

**Adopt Option C: Worker-side AES-256-GCM authenticated encryption, applied in the Worker
before the object is written to R2, with the key held in Cloudflare Secrets Store as a
versioned keyring.**

Rationale: it is the only option where the R2 service never sees plaintext or the key, it
gives us cryptographic integrity we control, and it makes key rotation a first-class,
data-loss-free operation. Given the residual-PII sensitivity, that control is worth the
modest key-management burden. Option A fails the requirement outright; Option B meets
confidentiality but with a larger plaintext-exposure surface, no integrity guarantees we
own, and worse rotation ergonomics, for no custody saving.

---

## Concrete scheme (what #9 implements)

### Primitive

- **Algorithm:** AES-256-GCM (AEAD — confidentiality + integrity in one primitive).
- **Key size:** 256-bit (32 bytes).
- **Nonce/IV:** 96-bit (12 bytes), generated fresh per object from a CSPRNG. Never reused
  under the same key. (At this volume we are astronomically far from the ~2^32 random-nonce
  birthday bound for a single key; rotation further caps messages per key.)
- **Auth tag:** 128-bit (16 bytes), the standard GCM tag. This is what provides integrity.
- **Additional authenticated data (AAD):** the object *header* bytes (magic + format version
  + key id). AAD is authenticated but not encrypted; binding it means an attacker cannot flip
  the key id, downgrade the format, or splice a body under a different header without failing
  authentication.

### Crypto provider (TinyGo/Wasm constraint — important)

The Worker is Go compiled with **TinyGo → Wasm**. As of this writing, TinyGo's `crypto/aes`
and `crypto/cipher` are importable but **fail their test suites** (unimplemented reflection
paths), so the pure-Go AES-GCM implementation is not safe to rely on. `crypto/rand` *is*
supported.

**Recommendation:** perform AES-256-GCM via the Workers runtime's **Web Crypto API**
(`crypto.subtle.encrypt` / `crypto.subtle.decrypt` with `{ name: "AES-GCM", iv, additionalData,
tagLength: 128 }`) and draw random bytes from `crypto.getRandomValues`, called through JS
interop from the Go/Wasm Worker. This is the Cloudflare-idiomatic path and avoids shipping a
questionable pure-Go cipher into Wasm.

Crucially, **the on-disk wire format below is identical whether encryption is done via
SubtleCrypto or a Go AEAD** — both produce/consume `ciphertext || 16-byte-tag`. So #9 may
choose either provider without changing the object format; SubtleCrypto is the recommended
default. (Confirm current TinyGo status at implementation time; if pure-Go GCM has become
reliable, it is a drop-in alternative.)

### Stored R2 object layout

Each R2 object body is a single self-describing binary frame:

```
 offset  size  field
 ------  ----  -------------------------------------------------------------
   0      4    magic            = ASCII "LMB1"  (0x4C 0x4D 0x42 0x31)
   4      1    format_version   = 0x01
   5      2    key_id           = uint16, big-endian (keyring version used)
   7     12    nonce            = 96-bit random IV
  19      N    ciphertext       = AES-256-GCM(plaintext)
  19+N   16    auth_tag         = 128-bit GCM tag (appended by Seal/encrypt)
```

- **Header** = bytes `[0, 7)` = `magic || format_version || key_id`. The header is passed as
  the **AAD** to GCM (it is stored in the clear but is authenticated).
- The `nonce` is stored in the frame so the reader can supply it to GCM; GCM authenticates
  the nonce implicitly (a modified nonce produces a wrong tag).
- With Go's `crypto/cipher` AEAD and with SubtleCrypto alike, the tag is appended to the
  ciphertext, so `ciphertext || auth_tag` is one contiguous blob (`N + 16` bytes).

Encrypt (pseudocode; illustrative, not committed code):

```go
header := []byte{'L','M','B','1', 0x01}
header = append(header, byte(keyID>>8), byte(keyID))   // magic|ver|key_id  (AAD)

nonce := random(12)                                    // CSPRNG, unique per object
ct := aesGCM(activeKey).Seal(nil, nonce, plaintext, header)   // ct = ciphertext||tag

object := append(append(header, nonce...), ct...)      // full R2 body
// PUT object to R2 at key derived from a random report id
```

Decrypt (pseudocode):

```go
magic, ver, keyID := object[0:4], object[4], be16(object[5:7])
require(magic == "LMB1" && ver == 0x01)
header := object[0:7]                 // AAD
nonce  := object[7:19]
ctTag  := object[19:]                 // ciphertext||tag

key := keyring[keyID]                 // hard-fail if version unknown
plaintext, err := aesGCM(key).Open(nil, nonce, ctTag, header)
require(err == nil)                   // auth failure => reject (tamper/corruption)
```

### Integrity

Provided entirely by AES-GCM: any modification to the ciphertext, the nonce, or the
authenticated header causes `Open`/`decrypt` to fail. No separate HMAC is needed. Callers
**must** treat a decryption/authentication error as a hard failure (skip + alert), never as
"publish what we have."

### R2 custom metadata (optional, operational)

For at-a-glance ops (e.g. dashboards) it is fine to mirror `key_id` and a report id into R2
custom metadata, but note that **R2 custom metadata is neither encrypted nor authenticated**.
Therefore: never put anything sensitive there, and treat it as untrusted — the *authoritative*
`key_id` is the one inside the AAD-authenticated header, not the metadata copy.

---

## Key custody

### Where the key lives

The key material is a **versioned keyring** stored as a single account-level secret in
**Cloudflare Secrets Store**, bound to *both* the ingest Worker and the weekly publish job.
An account-level secret can be bound to multiple Workers, so both share one custody point.

Keyring secret value (JSON):

```json
{
  "active": 2,
  "keys": {
    "1": "<base64-std of 32 random bytes>",
    "2": "<base64-std of 32 random bytes>"
  }
}
```

- Each `keys[<version>]` is 32 random bytes (AES-256), base64-encoded.
- `active` is the version new objects are encrypted under.
- Version numbers are the `key_id` written into the object header (uint16 range; ample).

Suggested binding name: `BUGREPORT_ENC_KEYRING`.

`wrangler` binding (illustrative):

```toml
secrets_store_secrets = [
  { binding = "BUGREPORT_ENC_KEYRING", store_id = "<store-id>", secret_name = "bugreport-enc-keyring" }
]
```

### How the Worker retrieves it at runtime

Secrets Store secrets are read asynchronously through the `env` binding:

```
raw := await env.BUGREPORT_ENC_KEYRING.get()   // returns the secret string
keyring := parseJSON(raw)                        // {active, keys{ver: base64}}
// decode base64 -> map[uint16][32]byte; select keyring.keys[keyring.active] to encrypt
```

Handling rules:

- Decode once and hold the parsed keyring in memory only for the isolate/request lifetime.
- **Never** log it, include it in a response body, put it in an error message, or write it to
  R2. Redact it from any structured logging.
- Fetching happens inside the request/scheduled handler (the `get()` is async), not at module
  top-level.

### How the weekly publish job decrypts

**Recommended:** implement the weekly publisher as a **Cloudflare Worker on a Cron Trigger**
that shares the same `BUGREPORT_ENC_KEYRING` binding. It lists R2 objects, decrypts each
in-Worker (selecting the key by the header's `key_id`), creates the GitHub issue, and
optionally deletes/tombstones the published object. **The key never leaves Cloudflare.** The
GitHub credential it needs to open issues is a *separate* Secrets Store secret.

**Not recommended:** running decryption in a GitHub Actions job. That requires copying the
keyring into GitHub Actions secrets, widening key custody to a second provider and enlarging
the attack surface, for no benefit. (Note: using GitHub Actions to *deploy* the Workers is
fine and unrelated — the concern is only about where *decryption* runs.)

### Access control and backup

- Restrict Secrets Store access to the maintainer via Cloudflare RBAC; enable audit logging.
- **Critical:** losing the keyring means permanent, unrecoverable loss of all
  not-yet-published reports. Keep an **encrypted offline backup** of the keyring (e.g. a
  password manager or hardware-backed store), updated whenever a new version is added.

---

## Key rotation

Rotation must not lose access to already-stored objects. This is handled by the `key_id` in
each object header plus a keyring that retains old versions.

**To rotate (routine):**

1. Generate a new 32-byte key from a CSPRNG (offline).
2. Add it to the keyring under the next version number and set `active` to it, e.g.
   add `"3": "<base64>"` and set `"active": 3`.
3. Update the single Secrets Store secret (one atomic write via dashboard/API).
4. Allow propagation. Workers may cache a secret for the isolate's lifetime, so a new version
   fully takes over after isolates recycle (or after a redeploy, which forces it).

After rotation, new objects are written with `key_id = 3`; existing objects keep their
original `key_id` (1 or 2) and **still decrypt**, because those versions remain in the
keyring.

**Rules:**

- **Never remove a key version while any stored object still references it.** Removing a
  version that an object was encrypted under makes that object permanently undecryptable.
- Because reports are short-lived (stored, then published weekly and removed), a superseded
  key can be safely retired roughly a week or two after it stops being `active` — once no
  object references it. This bounds the rotation/retirement burden.
- **Optional explicit retirement / re-key:** run a one-off pass — `GET` each object, `Open`
  with its old key, re-`Seal` under the current `active` key (new nonce, updated `key_id`),
  `PUT` back — then drop the retired version from the keyring.

**Compromise response:** if a key version is suspected compromised, add-and-activate a fresh
version immediately so new writes are protected, then run the re-key pass above over existing
objects and remove the compromised version. The short object lifetime keeps this window small.

---

## Consequences

**Positive**

- Objects in R2 are opaque ciphertext; R2 never receives plaintext or the key. Anyone with
  only bucket read access (leaked/over-scoped R2 token, misconfig, accidental public bucket)
  gets nothing usable.
- GCM gives integrity and tamper-evidence; AAD binds format + key version, preventing
  downgrade/transplant.
- Defense-in-depth over best-effort PII scrubbing.
- Rotation is data-loss-free via the versioned keyring + `key_id` header.
- One custody system (Cloudflare Secrets Store) shared by both Workers; portable primitive.

**Negative / costs**

- Key loss = permanent loss of not-yet-published reports (mitigated by offline keyring backup).
- Must implement AES-GCM in TinyGo/Wasm; recommended path is host SubtleCrypto, which adds a
  little JS interop.
- Slight extra Worker CPU per report (negligible at this volume).
- Does **not** defend against a malicious Cloudflare platform (out of scope, by design).
- Unauthenticated R2 custom metadata (if used) must be treated as non-sensitive and untrusted.
- Rotation is a manual maintainer responsibility.

**Open questions to confirm at review**

1. **Where does the weekly publisher run?** Cron-Trigger Worker (recommended — key stays in
   Cloudflare) vs GitHub Action (would widen custody). This ADR assumes the Cron Worker.
2. **Crypto provider:** host SubtleCrypto (recommended) vs pure-Go AES-GCM once TinyGo
   support is verified reliable.
3. **Keyring shape/binding:** single JSON keyring secret (this ADR) vs one binding per
   version; confirm the binding name (`BUGREPORT_ENC_KEYRING`).
4. **Object lifecycle:** are R2 objects deleted after publication? Confirming this (and
   possibly an R2 lifecycle rule) bounds rotation/retirement work. Likely its own ticket.

---

## Alternatives considered

- **True per-object envelope encryption (DEK + KEK).** Generate a random 256-bit DEK per
  report, encrypt the payload with the DEK, and wrap the DEK with a KEK from Secrets Store;
  store the wrapped DEK in the frame. Benefits: each object has an isolated key, and a
  single-use DEK makes payload nonce handling trivial. Costs: more bytes and an extra
  wrap/unwrap per object. Not worth it here — the volume is tiny and single-key AEAD with a
  versioned keyring is simpler and equally safe at this scale. The frame's `format_version`
  leaves room to adopt this later if requirements change.
- **AES-KW / RFC 3394 for key wrapping** (if the DEK variant were adopted): rejected in
  favor of AES-GCM wrapping to stay on primitives available via SubtleCrypto.

## References

- Cloudflare R2 — Data security (default at-rest encryption): https://developers.cloudflare.com/r2/reference/data-security/
- Cloudflare R2 — Use SSE-C: https://developers.cloudflare.com/r2/examples/ssec/
- Cloudflare Secrets Store — Workers integration (`secrets_store_secrets`, `await env.BINDING.get()`): https://developers.cloudflare.com/secrets-store/integrations/workers/
- Cloudflare Workers — Secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- TinyGo — Packages supported by TinyGo (stdlib status incl. `crypto/aes`, `crypto/cipher`, `crypto/rand`): https://tinygo.org/docs/reference/lang-support/stdlib/
- NIST SP 800-38D — AES-GCM (nonce/usage guidance): https://csrc.nist.gov/pubs/sp/800/38/d/final
