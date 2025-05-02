# OrangeCheck Protocol
*A Bitcoin-anchored identity primitive*  
**White Paper – Draft 1.0 (May 2025)**  
_By. [@TheBTCViking](https://x.com/TheBTCViking)_

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Protocol Overview](#2-protocol-overview)
3. [Economic and Philosophical Rationale](#3-economic-and-philosophical-rationale)
4. [Adoption Pathways and Policies](#5-adoption-pathways-and-policies)
5. [Security and Threat Model](#4-security-and-threat-model)
6. [Formal Specification](#6-formal-specification)
   + 6.1 [Notation and Pre-requisites](#61-notation-and-pre-requisites)
   + 6.2 [Stake-Output Construction](#62-stake-output-construction)
     + 6.2.1 [Key-path Only](#621-key-path-only-minimal-form)
     + 6.2.2 [Key-path + CLTV Script-path](#622-key-path--cltv-script-path-timelocked-form)
   + 6.3 [Canonical Claim](#63-canonical-claim)
   + 6.4 [Signature Procedure](#64-signature-procedure)
   + 6.5 [Deterministic Verification Algorithm](#65-deterministic-verification-algorithm)
   + 6.6 [Weight Semantics (non-normative)](#66-weight-semantics-non-normative)
   + 6.7 [Revocation Semantics](#67-revocation-semantics)
   + 6.8 [Reference REST Envelope (optional)](#68-reference-rest-envelope-optional)
   + 6.9 [Extensibility](#69-extensibility)
   + 6.10 [Test Vectors](#610-test-vectors)
   + 6.11 [Linkability & Anti-Surveillance Best-Practices](#611-linkability-and-antisurveillance-best-practices)
   + 6.12 [Versioning and Change-Control](#612-versioning-and-change-control)

---

## 1. Abstract

> The web is flooded with cost-free identities, so their promises are priced at zero. **OrangeCheck** restores economic gravity and welds identity to live authentication by requiring every handle to be signed—and continuously controlled—by the key that locks a fresh 34-byte Taproot output, a standard P2TR UTXO that adds no witness overhead or `OP_RETURN` baggage, unlike Ordinal inscriptions whose multi-megabyte witness payloads swell block sizes toward the 4 MB ceiling and distract Bitcoin from its lean monetary purpose. A verifier needs only a BIP-322 challenge and a single `gettxout`: a valid signature plus an unspent coin proves presence and stake, while spending the coin dissolves this "badge" everywhere at once. Built solely from native Bitcoin primitives, OrangeCheck moves intact identities across sites, apps, and protocols without registrars, side-tokens, or personal data, inheriting proof-of-work finality and letting each community map stake to bond, weight, or quorum. It thus transforms portable, cross-platform identity into a first-class function of the world’s most secure ledger, forcing the economic cost of Sybil attacks to scale linearly with sats at risk, allowing committed voices to stand out against cost-free noise.

---

## 2. Protocol Overview

OrangeCheck reduces digital identity to two native Bitcoin facts: **(1)** a fresh pay-to-Taproot output that locks a deliberate sum of sats, and **(2)** a BIP-322 signature that binds that outpoint to a chosen handle. Because the *same* key that guards the stake can answer any BIP-322 challenge, the credential doubles as a reusable login token—identity **and** authentication in one primitive. These two artifacts—no more than a 34-byte `scriptPubKey` on-chain and a tweet-sized JSON blob off-chain—can be verified by any service with a single `gettxout`. The stake is ordinary, witness-free block weight; the claim travels wherever text can travel, so identity rides across websites, apps, and protocols without registrars, side-tokens, or personal data.  

### How it works

| Stage   | Action                                                                  | Purpose                                                          |
|---------|--------------------------------------------------------------------------|------------------------------------------------------------------|
| **Lock** | Fund a brand-new Taproot address (optionally timelocked)                | Create an on-chain bond priced in sats **and** time              |
| **Bind** | Sign `{handle, outpoint, timestamp}` with the same key                  | Prove original custody of the coins                              |
| **Verify** | Check the signature and call `gettxout`                               | Confirm the badge is genuine **and still funded**                |
| **Auth** | Wallet signs a one-time nonce with the stake key                        | Live login: proves the handle is controlled *right now*          |
| **Revoke** | Spend the coin                                                        | Credential auto-expires everywhere—no lists, no appeals          |

### Interpretation at the edge

The protocol exposes only two immutable facts—*value* and *liveness*—leaving each community free to set its own policy:

* **Badge** · valid ≥ threshold  
* **Weight** · linear, square-root, or timelock-boost  
* **Quorum** · sum of stake required for a vote  

Because cost rises linearly with sats locked, the economic price of Sybil attacks scales in step, while legitimate users stake once and reuse the same credential anywhere a Bitcoin RPC is reachable. Revocation is as simple, instant, and final as spending the coins. In short, OrangeCheck makes portable, cross-platform identity—and its authentication—a first-class, self-auditing function of Bitcoin itself.  

---

## 3. Economic & Philosophical Rationale  

Digital identity is usually weightless: an e-mail or username can be conjured, abandoned, or multiplied at near-zero cost, so its claims are equally disposable. OrangeCheck restores **ontological heft** by tying a handle to something that cannot be faked more cheaply than it is created—Bitcoin’s proof-of-work.  

### Identity as a Costly Signal  
Economist Michael Spence described “costly signals” as actions so expensive that only sincere actors perform them. Locking sats in a Taproot UTXO is exactly that signal. The stake is:  

* **Irreversible** – spending destroys the badge everywhere.  
* **Quantifiable** – the amount and (optional) timelock are on-chain facts.  
* **Universal** – 50,000 sats assert the same weight in Lagos as in San Francisco.  

Thus reputation emerges from physics, not from paperwork or corporate rent. Bureaucratic KYC binds a name to a body but at the price of surveillance; blue-check subscriptions bind a name to monthly rent but not to character. OrangeCheck binds a name to sacrificed optionality—skin in the game.

### Persistence without Custodians  
An identity should be *portable* and *intransient*: it must survive platform failures and political shifts. Because the stake lives on Bitcoin’s most censorship-resistant ledger, no registrar can confiscate it, and no nation can selectively invalidate it. The protocol needs:  

* **No oracle** – the UTXO itself testifies.  
* **No committee** – rules are fixed; interpretation is local.  
* **No personal dossier** – only coin and key matter.  

### Adaptive Meaning at the Edge  
OrangeCheck exports two immutable facts: *value* and *liveness*. Communities mold those into policy:

| Context | Example Rule | Result |
|---------|--------------|--------|
| Hobby forum | ≥ 10 000 sats | Anti-spam badge |
| Finance platform | ≥ 0.05 BTC & 6-month timelock | Regulatory-grade identity |
| DAO voting | weight = √(sats) | Whale-resistant quorum |

The cost of a Sybil attack now rises linearly with sats at risk, while honest users stake once and reuse the same credential anywhere a Bitcoin RPC is reachable.

**In essence:** OrangeCheck revives the ancient earnest-money pledge and fuses it with thermodynamic finality. Identity is no longer a label floating in zero gravity; it is anchored to expended energy—an indelible, economically truthful record of commitment.

---

## 4. Adoption Pathways and Policies  

Because the stake key can answer any BIP-322 challenge, an OrangeCheck badge is both **identity and login**. The table shows how three very different communities exploit that dual use.

| Actor & scale | Stake rule | Outcome (trust **+** auth) |
|---------------|------------|----------------------------|
| **Agora** – global social feed | ≥ 0.001 BTC, 6 conf | “Orange tick” + password-less sign-in; bot spam drops > 50 % because 10 k accounts now cost ≈ 10 BTC. |
| **Stacktown** – specialist forum | Vote weight = √(sats) with 100 k-sat floor | Whale influence fades; users log in by signing a nonce instead of storing site passwords. |
| **Common-Pool DAO** – treasury governance | ≥ 0.005 BTC, 6-month timelock | Second-chamber quorum resists flash loans; proposals and ballots are authenticated by stake key. |

Integration is trivial: import the verifier, set a threshold or curve, add a **“Sign with OrangeCheck”** button. No side token, no registry, and users stake once then reuse the same credential—and login secret—everywhere a Bitcoin RPC is reachable.

Edge cases follow the same rule of coin-truth: lose the key, re-stake; need a temporary badge, pick a short timelock; require anonymity, fund via CoinJoin. One question settles trust and authentication alike—*is the coin still there?*—and forging that answer costs at least as much work as the Bitcoin it anchors.

By pricing handles in sats and time **and** re-using the same key for live sign-in, OrangeCheck turns identity into a scarce, password-free resource: simple for honest speakers to hold, linearly expensive for spammers to fake.

---

## 5. Security & Threat Model  

OrangeCheck’s narrow waist—one UTXO, one signature—shrinks attack surface, but some risks (non-specific to the protocol) should be considered:

| Threat | Consequence | Mitigation |
|--------|-------------|------------|
| **Key theft** | Thief spends stake → badge evaporates; can impersonate until spend confirms. | Treat stake key like deep-cold storage or 2-of-2 multisig. |
| **Whale Sybil** | Rich actor slices balance into many outputs to gain influence. | Communities weight non-linearly (√ value, log) or raise thresholds. |
| **Custodial UTXO reuse** | Exchange re-signs or re-spends a customer’s stake. | Verifiers blacklist known custodial clusters; users fund from self-custody. |
| **Deep re-org** | Badge flickers if stake tx is rolled back. | Relying apps wait ≥ 12 confirmations when continuity critical. |
| **DoS via fake claims** | Verifiers flooded with look-ups. | Only process claims submitted through local channels; no global crawl. |
| **Quantum break** | secp256k1 compromised. | OrangeCheck upgrades in lock-step with any post-quantum Bitcoin fork. |

In every case failure degrades gracefully to first principles: if the coin is gone, the badge is gone; if cost is low, weight can be discounted. Security rises no higher—and sinks no lower—than Bitcoin’s UTXO model plus community policy.

---

## 6. Formal Specification

> This section freezes the invariant core of the protocol. Everything beyond these rules—gateways, weighting curves, user-interface conventions—is non-normative and may evolve without revision to the specification.

### 6.1 Notation and Pre-requisites

* **BTC** denotes the Bitcoin blockchain mainnet, consensus rules as of Taproot activation (BIP-341/342).
* **UTXO** = unspent transaction output.
* **BIP-340** Schnorr public keys are 32-byte X-only values.
* **BIP-322** “Generic Signatures” define how arbitrary messages are signed and verified against a script path or key path.
* **CLTV** refers to `OP_CHECKLOCKTIMEVERIFY`.
* **Big-endian hex** is used for all binary examples.

The verifier is assumed to possess:

1. A fully-validating Bitcoin node or trusted proxy that exposes the RPC method `gettxout(txid string, n int, include_mempool bool) -> json`.
2. A BIP-322 signature engine for both ECDSA (legacy) and Schnorr (preferred).

### 6.2 Stake Output Construction

The credential’s anchor is a Taproot key-path spend, optionally augmented by a CLTV script path to add a time cost.

#### 6.2.1 Key-path only (minimal form)

```text
scriptPubKey = OP_1 <32-byte-X-only-pubkey>
value        ≥  dust_limit + relay_fee
```

- `dust_limit` is the prevailing Core policy (currently 546 sats for P2TR).
- `relay_fee` is the node’s minimum feerate (e.g., 1 sat/vB).
- There is no `OP_CHECKLOCKTIMEVERIFY` branch; spendability is instant.

#### 6.2.2 Key-path + CLTV script-path (timelocked form)

The Taproot Merkle tree commits to one additional leaf:

```text
script_leaf = <lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
              <pubkey> OP_CHECKSIG
```

The TapTweak is computed per BIP-341; the key-path public key remains the same 32-byte X-only value exposed in `scriptPubKey`.

- `lock_height` is an absolute block height (not relative).
- The output is spendable via the script path only when `current_height ≥ lock_height`.
- Key-path spending remains possible at any time, but doing so will dissolve the badge.

Wallets MAY also set a transaction-level `nLockTime`; verifiers MUST ignore it when computing liveness or weight, because it ceases to matter once the funding transaction is mined.

### 6.3 Canonical Claim

A claim is a UTF-8 JSON document without extra whitespace; keys are sorted lexicographically. Version 1 has four keys:

```json
{
  "v":1,
  "h":"@alice",
  "u":"f0c1ad71ccad6885…1baf:0",
  "t":1717100000
}
```

- **v** Protocol version (integer).
- **h** Handle string, 1-64 UTF-8 bytes, MUST NOT contain control chars.
- **u** Outpoint string, `txid:vout` where `txid` is 32-byte big-endian hex and `vout` is a base-10 index.
- **t** UNIX timestamp (seconds, UTC) when the claim was produced.

The canonical serialisation C is produced by:

```
C = utf8_bytes(concat(
    '{"h":"', h,
    '","t":', t,
    ',"u":"', u,
    '","v":1}'
))
```

Notice the key order `h,t,u,v`. Version numbers other than `1` MUST cause the verifier to reject.

### 6.4 Signature Procedure (BIP-322)

Let **pk** be the X-only key that controls the _key-path_ of the stake output. The signature domain is:

```text
msg_hash = SHA256(C)
sig      = BIP322-SIGN(pk, msg_hash)
```

The resulting `sig` is 64 bytes for Schnorr or 71-73 bytes DER for ECDSA.

Publish **(C, sig)** together. For human-readable media (Twitter, Nostr) the signature should be base64url-encoded.

### 6.5 Deterministic Verification Algorithm

The following pseudocode is normative.

```
def verify_orange(handle, claim_json, sig, threshold_sat, height_now):
    # 1. Parse and basic-sanity
    obj = json.loads(claim_json)
    if obj["v"] != 1 or obj["h"] != handle:
        return Invalid("malformed or mismatched handle")

    txid, vout_str = obj["u"].split(":")
    vout = int(vout_str)

    # 2. Signature check (BIP-322)
    msg_hash = sha256(claim_json.encode("utf-8"))
    pk = extract_pubkey_from_utxo(txid, vout)   # see step 3
    if not bip322_verify(pk, msg_hash, sig):
        return Invalid("bad signature")

    # 3. On-chain status
    utxo = gettxout(txid, vout, include_mempool=False)
    if utxo is None:
        return Revoked()

    value_sat = satoshi(utxo["value"])
    if value_sat < threshold_sat:
        return Invalid("below weight threshold")

    cltv_height = parse_cltv_if_present(utxo["scriptPubKey"])
    if cltv_height and height_now >= cltv_height:
        return Invalid("timelock expired")

    weight = value_sat  # verifiers may apply non-linear transforms
    return Valid(weight, confirmations=utxo["confirmations"])
```

A verifier MUST treat any failure case as invalid except `utxo is None`, which is **revoked**.

### 6.6 Weight Semantics (Non-normative)

The protocol guarantees only the numeric value of the stake in satoshis. A relying service MAY map that to influence by:

- **Binary** (valid ≥ threshold ⇒ badge).
- **Linear** (weight = value).
- **Quadratic** weight = ⌊sqrt(value)⌋.
- **Timelock** bonus weight = value × (1 + months_locked/12).

Such transforms occur entirely off-chain; they do not affect interop.

### 6.7 Revocation Semantics

- Spending the output in any transaction—key path or script path—causes `gettxout` to return null.
- Re-orgs that drop the funding transaction result in immediate revocation until the transaction is re-mined.
- There is no grace period; credential liveness equals UTXO existence.

### 6.8 Reference REST Envelope (optional)

Gateways MAY expose a convenience API. The following schema is RECOMMENDED but not required for interoperability.

```
POST /oc/claim
{
  "claim": "<canonical JSON>",
  "sig"  : "<base64url>"
}

GET /oc/verify/@alice
→
{
"status" : "valid",
"weight" : "125000",
"confs"  : 9
}
```

No authentication is mandated. Gateways SHOULD rate-limit by IP and cache positive lookups for ≤ 10 seconds.

### 6.9 Extensibility 

- Unknown top-level keys in the JSON claim MUST cause a verifier to reject. Future versions increase `"v"` and document new keys.
- A `meta` field MAY be introduced in a later version to carry a SHA-256 of auxiliary data (avatar, credentials). Verifiers that do not understand it ignore that data while still validating stake.
- Post-quantum migration will follow whatever curve Bitcoin selects; the stake output then uses the new key type without altering higher layers.

### 6.10 Test Vectors

| Case        | txid : vout                                   | Value (sat) | CLTV height | Handle  | Canonical Hash (SHA-256, hex) | Signature (base64url, truncated) |
|-------------|-----------------------------------------------|----------|------------|---------|------------------------------|----------------------------------|
| Minimal     | `8c1f…6c3a:0`                                 | 100000   | —          | `@test` | `0be2c7…4a5d`                | `MEYCIQD…`                       |
| Timelocked  | `ab9d…09ff:1`                                 | 500000   | 840000     | `@lock` | `f1a6d4…219c`                | `AkEAh…`                         |
| Bad-sig     | *same outpoint as “Minimal”*                  | 100000   | —          | `@fake` | `7c94e1…b02a`                | — (invalid)                      |

A reference verifier in Rust and Python with the above vectors will be published in the `oc` repository. The test vectors are not normative but are provided to illustrate the protocol’s behaviour.

### 6.11 Linkability and Anti-Surveillance Best-Practices

1. **CoinJoin / PayJoin funding** – create the stake from mixed coins so the UTXO cannot be trivially traced backwards.  
2. **LN → on-chain submarine swap** – fund the Taproot output without revealing your source node.  
3. **One-time handles** – use separate stakes for unrelated personas (e.g., whistle-blowing vs. social).  
4. **MuSig2 / FROST multisig** – hide the signer set; chain observers see only one X-only key.  
5. **Avoid address reuse** – never post the same Taproot public key in other contexts.

Following these practices keeps OrangeCheck a *proof-of-cost* signal rather than a surveillance beacon.

### 6.12 Versioning and Change-Control

* **Semantic flag** – Every claim includes `"v": n`; verifiers **MUST** reject unknown majors.  
* **OCP process** – Changes are proposed as **OrangeCheck Proposals** (markdown + reference code) in the public repo. Three independent impl-reports required.  
* **Activation rule** – A new major version activates when ≥ 90 % of *weighted* live stakes have re-signed over 12 months. No committee can override; the community signals by moving its own coins.  
* **Narrow-waist mandate** – The core will *not* add global registries, alt-chains, or rent tokens. Such ideas fork into a brand-new major version.

---

> _The specification above constitutes the entire OrangeCheck protocol: build a Taproot stake, sign a canonical claim, and let every verifier on Earth rest its decision on a single, immutable fact—“does the coin still sit where the claim says it does?” All higher-order meaning flows from that fact and is free to evolve without another change to these rules._
