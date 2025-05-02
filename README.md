# OrangeCheck Protocol
*A Bitcoin-anchored identity primitive*  
**White Paper – Draft 1.0 (May 2025)**  
_By. [@TheBTCViking](https://x.com/TheBTCViking)_

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Protocol Overview](#2-protocol-overview)
3. [Economic & Philosophical Rationale](#3-economic--philosophical-rationale)
4. [Adoption Pathways & Policies](#4-adoption-pathways--policies)
5. [Formal Specification](#5-formal-specification)
   + 5.1 [Notation and Pre-requisites](#51-notation-and-pre-requisites)
   + 5.2 [Stake-Anchor Construction](#52-stake-anchor-construction)
     + 5.2.1 [Taproot Key-path Only](#521-taproot-key-path-only-minimal-form)
     + 5.2.2 [Taproot + CLTV Script-path (timelocked form)](#522-key-path--cltv-script-path-timelocked-form)
     + 5.2.3 [Lightning HOLD-HTLC anchor](#523-lightning-hold-htlc-anchor)
     + 5.2.4 [Delegated 2-of-2 option (non-mandatory)](#524-delegated-2-of-2-option-non-mandatory)
   + 5.3 [Canonical Claim](#53-canonical-claim)
   + 5.4 [Signature Procedure](#54-signature-procedure)
   + 5.5 [Deterministic Verification Algorithm](#55-deterministic-verification-algorithm)
   + 5.6 [Weight Semantics (non-normative)](#56-weight-semantics-non-normative)
   + 5.7 [Revocation Semantics](#57-revocation-semantics)
   + 5.8 [Reference REST Envelope (optional)](#58-reference-rest-envelope-optional)
   + 5.9 [Extensibility](#59-extensibility)
   + 5.10 [Test Vectors](#510-test-vectors)
   + 5.11 [Linkability & Anti-Surveillance Best-Practices](#511-linkability-and-antisurveillance-best-practices)
   + 5.12 [Versioning and Change-Control](#512-versioning-and-change-control)

---

## 1. Abstract

> OrangeCheck converts any username into a live, slash-able security deposit anchored by native Bitcoin primitives—either a 34-byte Taproot UTXO _or_ a Lightning HOLD invoice—so every handle carries thermodynamic weight instead of free-to-forge fluff without polluting block space. The on-chain variant is no more than a dust-threshold output that adds zero witness overhead and can be batch-revoked with any spend, while the Lightning path keeps even that footprint off-chain; thus millions of identities translate to only a few virtual bytes each. One BIP-322 signature plus a single `gettxout` (or an HTLC probe) proves both authorship and ongoing custody; spending the coin or settling the invoice dissolves the badge everywhere at once, with no registrars, side-tokens, or personal data. Stake value and uninterrupted tenure form a portable risk signal that forums can treat as an anti-spam badge, DAOs as quadratic voting weight, and marketplaces as on-the-spot credit—yet the core always stays “one bond, one sig,” leaving reputation math and slash policies to the edge. By forcing every Sybil to lock sats linearly with the noise they create while capping chain load at a few vbytes per identity, OrangeCheck restores economic gravity to digital identity without fueling block-bloat fears.

---

## 2. Protocol Overview

OrangeCheck now recognises **two equally native ways** to anchor a bond:

1. **Taproot UTXO** – a fresh dust-threshold Pay-to-Taproot output (34 bytes of `scriptPubKey`, zero witness overhead).  
2. **Lightning HTLC** – a *HOLD* invoice whose payment-hash sits in a pending HTLC; no on-chain bytes until the channel eventually closes.

In both cases a **single BIP-322 signature** from the same key that locks the bond binds a canonical claim (`{handle, anchor_id, timestamp}`). Because that key can answer any challenge, the bond doubles as a reusable password-less login. Verification needs only one RPC call—`gettxout` for the on-chain path, or a BOLT-12/onion probe for the Lightning path—so identity travels anywhere plain JSON can travel, without registrars, side-tokens, or personal data and **without block-bloat** (HTLC badges add _zero_ block weight; UTXO badges can be batch-spent).

### How it works

| Stage | On-chain anchor (Taproot) | Off-chain anchor (Lightning) | Purpose |
|-------|---------------------------|------------------------------|---------|
| **Lock** | Fund a brand-new Taproot address (optionally with a CLTV leaf) | Publish a HOLD invoice from the user’s node/LSP and withhold the pre-image | Create a bond priced in sats (and optionally time) |
| **Bind** | Sign `{handle, "<txid>:<vout>", t}` with the stake key | Sign `{handle, "<payment_hash>:ln", t}` with the same key | Prove initial custody |
| **Verify** | Check sig → `gettxout` | Check sig → HTLC-status probe | Confirm badge is genuine **and still funded** |
| **Auth** | Wallet signs a server-nonce with stake key | Same | Live login proves handle is controlled *right now* |
| **Revoke** | Spend the UTXO (can batch) | Settle or let HTLC timeout | Badge auto-expires everywhere—no lists, no appeals |

### Interpretation at the edge

OrangeCheck still exposes only two immutable facts—*value* and *liveness*—plus an easily derived *uptime* (block-height or CLTV age). Each community maps those into its own rules:

* **Badge** · valid ≥ threshold  
* **Weight** · linear, √value, stake × age, etc.  
* **Quorum / credit line** · sum of (stake × age) required for action  

Because the cost of a Sybil attack rises linearly with sats (and meter-time) locked, honest users stake once—on-chain or off-chain—and reuse the same credential and login secret anywhere a Bitcoin RPC or Lightning onion probe is reachable. Revocation is as simple, instant, and final as spending the coin or settling the invoice, keeping the core forever *one bond, one sig*.

---

## 3. Economic & Philosophical Rationale  

Digital identity is usually **weightless**: a handle or e-mail can be spawned, abandoned, or multiplied at near-zero cost, so its promises are priced at zero. OrangeCheck re-anchors identity to *expended energy* by making every handle sit atop a forfeitable Bitcoin bond—**either** a Taproot UTXO (hash-rate cost) **or** a Lightning HOLD HTLC (liquidity + routing-fee cost). In both paths the bond can be lost but never counterfeited more cheaply than it is created, reinstating economic gravity online.

### Identity as a Costly Signal  

Following Michael Spence’s theory, proof of sincerity must be **expensive to fake and cheap to verify**. Locking sats under one key that can be slashed on misconduct satisfies that requirement:

* **Forfeitable** – spend or settle the bond and the badge evaporates everywhere.  
* **Quantifiable** – stake amount and (optional) timelock/CLTV are on-chain or probe-read facts.  
* **Universal** – 50 000 sats or a 50 000-sat HOLD means the same in Lagos or San Francisco.  
* **Accretive** – uninterrupted block-height / CLTV age compounds the signal without new writes.

Thus reputation emerges from physics, not paperwork or corporate rent. Bureaucratic KYC ties a name to a body but leaks privacy; monthly blue-checks rent a badge but prove no skin in the game. OrangeCheck ties a name to *sacrificed optionality*—an earnest-money deposit that anyone can see but only its owner can reclaim.

### Persistence without Custodians  

A credible identity must survive platform failures, political shifts, and even block-space wars:

* **No oracle** – the UTXO or HTLC itself testifies.  
* **No committee** – rules are fixed; interpretation is local.  
* **No personal dossier** – only coin and key matter.  
* **No block bloat** – one 34-byte Taproot output per on-chain badge, zero bytes for Lightning badges until a channel closes.  

Because the bond lives on Bitcoin’s most censorship-resistant rails, no registrar can confiscate it and no nation can selectively invalidate it.

### Adaptive Meaning at the Edge  

OrangeCheck exports just two immutable facts—**value** and **liveness**—plus a derivable **uptime** (block or CLTV age). Every community is free to shape those into its own policy:

| Context | Example Rule | Result |
|---------|--------------|--------|
| Hobby forum | ≥ 10 000 sats (on-chain **or** HOLD) | Spam costs real money; badge = entry ticket |
| Social feed | Badge valid & uptime > 30 days | “Orange tick” filter nukes sock-puppets |
| Finance platform | ≥ 0.05 BTC + 6-month timelock | Regulatory-grade, password-less identity |
| DAO voting | weight = √(stake × days_alive) | Whale slicing diluted, long-term stakers boosted |
| Ride-share / SaaS | stake ≥ fare + 7-day uptime | On-the-spot credit without paperwork |

Because Sybil cost rises linearly with sats (and meter-time) locked, honest users stake once—on-chain or off-chain—and reuse the same credential anywhere a Bitcoin RPC or Lightning probe is reachable.

**In essence:** OrangeCheck revives the ancient earnest-money pledge and fuses it with thermodynamic finality. Identity is no longer a frictionless label floating in zero gravity; it is anchored to expended energy and time—an indelible, economically truthful record of commitment that platforms can read in a single RPC round-trip.

---

## 4. Adoption Pathways & Policies  

Because the same key that guards the bond can answer any BIP-322 challenge, an OrangeCheck badge is simultaneously **identity** *and* **login**—no passwords, no OAuth round-trips. The table shows how four very different ecosystems plug in:

| Actor & scale | Anchor + Rule | Outcome (trust **+** auth) |
|---------------|---------------|----------------------------|
| **WorldSquare** – global social feed | **≥ 20 000 sat** bond (Taproot **or** HOLD, ≥ 6 conf/24 h uptime) | “Orange tick” filter removes 80 % of bot replies; users sign a nonce for password-less login. |
| **GuildPad** – specialist dev forum | Vote weight = √(stake × days_alive) with **≥ 50 000 sat** floor (Taproot) | Whale slicing diluted; long-term contributors gain voice; login is BIP-322 challenge. |
| **HODLride** – P2P ride-share | HOLD invoice ≥ fare + 10 000 sat, uptime ≥ 1 day | Driver sees rider’s live deposit; no-show slashes bond; both parties authenticate with the same key. |
| **TreasuryDAO** – governed multisig | **≥ 0.01 BTC** + 6-month CLTV timelock | Second-chamber quorum resists flash-loan Sybils; proposals/ballots signed by stake key; badge expires automatically when funds unlock. |

### Drop-in integration

* **Client side** – call the 150-LoC `oc-verifier` (Rust/TS/Swift).  
* **Login** – use the *OC-OIDC* bridge so a BIP-322 sig satisfies the OIDC `id_token` flow.  
* **On-chain check** – one `gettxout`; **Lightning check** – one BOLT-12 onion probe.  
* **No side token, no registry** – users bond once then reuse the same badge (and login secret) everywhere a Bitcoin RPC *or* Lightning routing node is reachable.

### Operational guidelines

* **Lost key?** Re-stake and repost the claim.  
* **Short-term need?** Pick a small HOLD timeout or low CLTV.  
* **Anonymity?** CoinJoin funding or submarine-swap into Taproot keeps provenance dark.  
* **Sybil tuning?** If attack cost looks low, raise stake floor or demand longer uptime.

By pricing handles in sats **and** meter-time, then recycling the same key for live sign-in, OrangeCheck turns identity into a scarce, password-free resource—simple for honest users, linearly expensive for spammers.

---

## 5. Formal Specification

> This section freezes the invariant core of the protocol. Everything beyond these rules—gateways, weighting curves, user-interface conventions—is non-normative and may evolve without revision to the specification.

### 5.1 Notation and Pre-requisites

* **BTC** Bitcoin main-chain, consensus rules ≥ Taproot (BIP-341/342).  
* **LN** Lightning Network main-net, BOLT-spec v1.0 or later.  
* **UTXO** Unspent transaction output on BTC.  
* **HTLC** Hash-Time-Locked Contract pending in an LN channel; in OrangeCheck we use a *HOLD* HTLC (pre-image withheld).  
* **BIP-340** Schnorr public keys (32-byte X-only).  
* **BIP-322** Generic message signatures over either key- or script-path.  
* **CLTV** `OP_CHECKLOCKTIMEVERIFY`.  
* **BOLT-12** “Offers” and **onion-message** extensions (used for HTLC status probes).  
* **Big-endian hex** Encoding for binary examples.

A conforming **verifier** MUST have:

1. **Bitcoin view** – a fully-validating node *or* trusted proxy exposing  

   `gettxout(txid string, vout int, include_mempool bool) → json`.
   
3. **Lightning view** – access to any LN node (local or remote) that can  

   `lookup_htlc(payment_hash) → {state, value_msat, cltv_expiry}` where `state ∈ {PENDING, FORWARDED, SETTLED}`.
   
5. A BIP-322 signature engine for Schnorr (preferred) and legacy ECDSA.

> *Rationale:* Items 1 & 2 let a verifier ask the **same binary question**—“does the bond still exist?”—for either a Taproot UTXO or an LN HOLD HTLC.

---

### 5.2 Stake-Anchor Construction  

An OrangeCheck credential binds a handle to **exactly one live bond**, called the *anchor*.  
Two anchor types are recognised:

| Anchor type | Chain-footprint | Revocation event | Typical lifespan |
|-------------|-----------------|------------------|------------------|
| **Taproot UTXO** | 34-byte `scriptPubKey`, 0-byte witness | UTXO spent (any path) | hours → years |
| **Lightning HOLD HTLC** | *Zero* until channel closes | HTLC settled, forwarded, or timed-out | minutes → weeks |

Verifiers treat both forms identically: “badge is **valid** if anchor is **still unspent / unsettled**”.

#### 5.2.1 Key-path only (minimal form)

```text
scriptPubKey = OP_1 <32-byte-X-only-pubkey>
value        ≥ dust_limit + relay_fee
```

- `dust_limit` is the prevailing Core policy (currently 546 sats for P2TR).
- `relay_fee` is the node’s minimum feerate (e.g., 1 sat/vB).
- There is no `OP_CHECKLOCKTIMEVERIFY` branch; spendability is instant.

#### 5.2.2 Taproot + CLTV script-path (timelocked form)

```text
script_leaf = <lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
              <pubkey> OP_CHECKSIG
```

_Key-path spend at any time (early revocation) or script-path spend after `lock_height` (natural expiry)._

#### 5.2.3 Lightning HOLD-HTLC anchor

A badge may reference a pending HOLD invoice instead of a UTXO.

```text
payment_hash   = 32-byte SHA-256 pre-image hash (hex)
amount_msat    ≥ 1000          # 1 sat floor
cltv_expiry    = absolute block-height timeout in the channel
channel_id     = 64-bit short-channel-id containing the HTLC  (optional*)
```

_Generation_

1. User (or their LSP) issues a BOLT-12 invoice_request with features=HOLD.
2. Payer (usually the same user via internal loop) pays the invoice without revealing the pre-image.
3. The resulting pending HTLC constitutes the bond; its payment_hash becomes the anchor ID.

_Validity check_

```text
htlc = lookup_htlc(payment_hash)
valid if htlc.state == PENDING   # not SETTLED or FORWARDED
        and (block_height < htlc.cltv_expiry)
```

_Revocation_

- Settle – user reveals pre-image → `state = SETTLED` → badge invalid.
- Timeout / force-close – HTLC moves on-chain and times out → badge invalid.
- Forward (malicious LSP) → `state = FORWARDED` → badge invalid.

> *`channel_id` may be omitted; if present, verifiers can fall back to on-chain HTLC lookup on force-close.

#### 5.2.4 Delegated 2-of-2 option (non-mandatory)

For platforms that need seizure-for-cause, the anchor MAY be a 2-of-2 MuSig2 Taproot output or a 2-of-2 Lightning channel where the platform holds the second key. Verifiers ignore the extra key; only liveness matters.

### 5.3 Canonical Claim

A **claim** is a UTF-8 JSON document without extra whitespace; object keys **must** appear in the order shown below so the byte-string is deterministic.

| Key | Type | Purpose |
|-----|------|---------|
| `v` | `int` | Protocol major version (`1` for this spec). |
| `h` | `string` | Handle, 1–64 UTF-8 bytes, **no control chars**. |
| `u` | `string` | Anchor ID: *Taproot* `"<txid>:<vout>"` **or** *Lightning* `"<payment_hash>:ln"`. |
| `t` | `int` | UNIX epoch seconds when the claim was produced. |

> **Canonical serialisation**  
> Keys must appear in the sequence **h,t,u,v** to produce the byte-string `C` that is later signed.

```jsonc
// Taproot example
{"h":"@alice","t":1717100000,"u":"f0c1ad71ccad6885…1baf:0","v":1}

// Lightning example (bond = HOLD HTLC)
{"h":"@bob","t":1717100123,"u":"a4b0d2f8c0e7…9f12:ln","v":1}
```

If `v` is anything other than `1`, the verifier MUST reject. Unknown additional keys are forbidden in version 1; future versions will either increment `v` or introduce an explicit `meta` object.

### 5.4  Signature Procedure  (BIP-322)

Each claim is signed once with **pk**, a BIP-340 X-only public key controlled by the badge owner.

| Anchor type | Where verifier gets `pk` |
|-------------|--------------------------|
| **Taproot UTXO** | Extract the internal key from the output’s `scriptPubKey`. |
| **Lightning HTLC** | Read the hex string `k` that *must* accompany an `:ln` anchor inside the claim. |

> **Signature domain**

```text
msg_hash = SHA256(C)          # C = canonical-bytes of the claim
sig      = BIP322-SIGN(pk, msg_hash)
```

- `sig` is 64 bytes (Schnorr) or 71-73 bytes DER (legacy ECDSA).
- When anchor = `…:ln`, the claim MUST carry `"k":"<32-byte-hex-pubkey>"` directly after the `u` field, preserving the key order `h`,`t`,`u`,`k`,`v`.

Publish **(C, sig)** together. For human-readable media (Twitter, Nostr) the signature should be base64url-encoded.

### 5.5 Deterministic Verification Algorithm

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

### 5.6 Weight Semantics (Non-normative)

The protocol guarantees only the numeric value of the stake in satoshis. A relying service MAY map that to influence by:

- **Binary** (valid ≥ threshold ⇒ badge).
- **Linear** (weight = value).
- **Quadratic** weight = ⌊sqrt(value)⌋.
- **Timelock** bonus weight = value × (1 + months_locked/12).

Such transforms occur entirely off-chain; they do not affect interop.

### 5.7 Revocation Semantics

- Spending the output in any transaction—key path or script path—causes `gettxout` to return null.
- Re-orgs that drop the funding transaction result in immediate revocation until the transaction is re-mined.
- There is no grace period; credential liveness equals UTXO existence.

### 5.8 Reference REST Envelope (optional)

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

### 5.9 Extensibility 

- Unknown top-level keys in the JSON claim MUST cause a verifier to reject. Future versions increase `"v"` and document new keys.
- A `meta` field MAY be introduced in a later version to carry a SHA-256 of auxiliary data (avatar, credentials). Verifiers that do not understand it ignore that data while still validating stake.
- Post-quantum migration will follow whatever curve Bitcoin selects; the stake output then uses the new key type without altering higher layers.

### 5.10 Test Vectors

| Case        | txid : vout                                   | Value (sat) | CLTV height | Handle  | Canonical Hash (SHA-256, hex) | Signature (base64url, truncated) |
|-------------|-----------------------------------------------|----------|------------|---------|------------------------------|----------------------------------|
| Minimal     | `8c1f…6c3a:0`                                 | 100000   | —          | `@test` | `0be2c7…4a5d`                | `MEYCIQD…`                       |
| Timelocked  | `ab9d…09ff:1`                                 | 500000   | 840000     | `@lock` | `f1a6d4…219c`                | `AkEAh…`                         |
| Bad-sig     | *same outpoint as “Minimal”*                  | 100000   | —          | `@fake` | `7c94e1…b02a`                | — (invalid)                      |

A reference verifier in Rust and Python with the above vectors will be published in the `oc` repository. The test vectors are not normative but are provided to illustrate the protocol’s behaviour.

### 5.11 Linkability and Anti-Surveillance Best-Practices

1. **CoinJoin / PayJoin funding** – create the stake from mixed coins so the UTXO cannot be trivially traced backwards.  
2. **LN → on-chain submarine swap** – fund the Taproot output without revealing your source node.  
3. **One-time handles** – use separate stakes for unrelated personas (e.g., whistle-blowing vs. social).  
4. **MuSig2 / FROST multisig** – hide the signer set; chain observers see only one X-only key.  
5. **Avoid address reuse** – never post the same Taproot public key in other contexts.

Following these practices keeps OrangeCheck a *proof-of-cost* signal rather than a surveillance beacon.

### 5.12 Versioning and Change-Control

* **Semantic flag** – Every claim includes `"v": n`; verifiers **MUST** reject unknown majors.  
* **OCP process** – Changes are proposed as **OrangeCheck Proposals** (markdown + reference code) in the public repo. Three independent impl-reports required.  
* **Activation rule** – A new major version activates when ≥ 90 % of *weighted* live stakes have re-signed over 12 months. No committee can override; the community signals by moving its own coins.  
* **Narrow-waist mandate** – The core will *not* add global registries, alt-chains, or rent tokens. Such ideas fork into a brand-new major version.

---

> _The specification above constitutes the entire OrangeCheck protocol: build a Taproot stake, sign a canonical claim, and let every verifier on Earth rest its decision on a single, immutable fact—“does the coin still sit where the claim says it does?” All higher-order meaning flows from that fact and is free to evolve without another change to these rules._
