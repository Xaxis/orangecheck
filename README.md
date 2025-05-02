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
   + 5.6 [Weight & Credit Semantics (non-normative)](#56-weight--credit-semantics-non-normative)
   + 5.7 [Revocation Semantics](#57-revocation-semantics)
   + 5.8 [Reference REST Envelope (optional helper API)](#58-reference-rest-envelope-optional-helper-api)
     + 5.8.1 [POST `/oc/claim`](#581-post-oc-claim)
     + 5.8.2 [POST `/oc/verify/<handle>`](#582-post-oc-verify-handle) 
   + 5.9 [Extensibility](#59-extensibility)
   + 5.10 [Test Vectors](#510-test-vectors)
   + 5.11 [Linkability & Anti-Surveillance Best-Practices](#511-linkability-and-antisurveillance-best-practices)
   + 5.12 [Versioning and Change-Control](#512-versioning-and-change-control)

---

## 1. Abstract

> OrangeCheck converts any username into a live, slash-able security deposit anchored by native Bitcoin primitives—either a 34-byte Taproot UTXO _or_ a Lightning HOLD invoice—so every handle carries thermodynamic weight instead of free-to-forge fluff without polluting block space. The on-chain variant is no more than a dust-threshold output that adds zero witness overhead and can be batch-revoked with any spend, while the Lightning path keeps even that footprint off-chain; thus millions of identities translate to only a few virtual bytes each. One BIP-322 signature plus a single `gettxout` (or an HTLC probe) proves both authorship and ongoing custody; spending the coin or settling the invoice dissolves the badge everywhere at once, with no registrars, side-tokens, or personal data. Stake value and uninterrupted tenure form a portable risk signal that forums can treat as an anti-spam badge, DAOs as quadratic voting weight, and marketplaces as on-the-spot credit—yet the core always stays “one bond, one sig,” leaving reputation math and slash policies to the edge. By forcing every Sybil to lock sats linearly with the noise they create while capping chain load at a few vbytes per identity, OrangeCheck restores economic gravity to digital identity without fueling block-bloat fears.

---

## 2. Protocol Overview

OrangeCheck recognises **two equally native ways** to anchor a bond:

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

### 5.4 Signature Procedure  (BIP-322)

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

The verifier MUST execute the following steps exactly; any deviation risks accepting forged or revoked badges.

```python
def verify_orange(handle, claim_json, sig, threshold_sat, height_now):
    """
    Returns one of: Valid(weight, confs_or_expiry),
                    Revoked(),
                    Invalid(reason)
    """

    # 0. Parse & canonical-bytes recreation
    obj = json.loads(claim_json)
    C   = canonical_bytes(obj)             # h,t,u,(k,)v in order
    if obj.get("v") != 1 or obj["h"] != handle:
        return Invalid("malformed or mismatched handle")

    # 1. Extract anchor type
    anchor, suffix = obj["u"].split(":")
    is_ln  = (suffix == "ln")
    is_txo = not is_ln

    # 2. Obtain pubkey for sig-check
    if is_txo:
        txid, vout = anchor, int(suffix)   # (swap vars)
        pk = extract_pubkey_from_utxo(txid, vout)
    else:                                  # Lightning
        pk_hex = obj.get("k")
        if pk_hex is None or len(pk_hex) != 64:
            return Invalid("missing pubkey for ln claim")
        pk = bytes.fromhex(pk_hex)

    # 3. Signature check (BIP-322)
    msg_hash = sha256(C)
    if not bip322_verify(pk, msg_hash, sig):
        return Invalid("bad signature")

    # 4. Anchor liveness & value
    if is_txo:
        utxo = gettxout(txid, vout, include_mempool=False)
        if utxo is None:
            return Revoked()
        value_sat = satoshi(utxo["value"])
        if value_sat < threshold_sat:
            return Invalid("below weight threshold")

        cltv_height = parse_cltv_if_present(utxo["scriptPubKey"])
        if cltv_height and height_now >= cltv_height:
            return Invalid("timelock expired")

        weight = value_sat
        confid = utxo["confirmations"]
        return Valid(weight, confid)

    else:   # Lightning HOLD HTLC
        htlc = lookup_htlc(anchor)     # anchor == payment_hash
        if htlc is None or htlc["state"] != "PENDING":
            return Revoked()
        if height_now >= htlc["cltv_expiry"]:
            return Invalid("htlc expired")

        value_sat = htlc["value_msat"] // 1000
        if value_sat < threshold_sat:
            return Invalid("below weight threshold")

        weight = value_sat
        time_to_expiry = htlc["cltv_expiry"] - height_now
        return Valid(weight, time_to_expiry)
```

- Anchor not found (`utxo is None` or `htlc.state ∉ PENDING`) ⇒ `Revoked()`.
- Any parsing, signature, or threshold failure ⇒ `Invalid()`.
- `threshold_sat` is a policy input; verifiers MAY apply non-linear transforms to `weight` after acceptance.

### 5.6 Weight & Credit Semantics (Non-normative)

The protocol guarantees only two anchor facts—**stake value (sat)** and **liveness**—plus an easily derived **uptime**:

| Anchor | Stake (`S`) | Uptime (`U`) |
|--------|-------------|--------------|
| Taproot UTXO | `value_sat` | `height_now – funding_height`  (blocks ≈ ~10 min) |
| Lightning HOLD | `value_msat // 1000` | `cltv_expiry – height_now`  (blocks until timeout) |

Relying services are free to transform `S` and `U` into influence or credit. Examples:

| Transform | Formula | Use-case |
|-----------|---------|---------|
| **Binary badge** | valid `∧` (`S ≥ T`) | Spam filter |
| **Linear stake** | `W = S` | Simple pay-to-speak |
| **Quadratic** | `W = ⌊√S⌋` | DAO vote dilution |
| **Stake × Uptime** | `W = S × U` | Rewards long-held badges |
| **Whale-resistant credit** | `W = ⌊√(S × U)⌋` | On-the-spot micro-credit |
| **Timelock boost** | `W = S × (1 + months_locked / 12)` | Favour long CLTV |

All transforms are **off-chain** and can be changed without touching the core spec.

### 5.7 Revocation Semantics  

| Anchor type | Automatic-revocation trigger | Notes |
|-------------|-----------------------------|-------|
| **Taproot UTXO** | The output is spent in **any** transaction (key-path or script-path). | Batch spends are fine; badge disappears the moment `gettxout` returns `null`. |
| **Lightning HOLD HTLC** | `state ∉ PENDING` (i.e., `SETTLED`, `FORWARDED`, or timed-out) | A force-close moves the HTLC on-chain; if it times-out on chain the badge is revoked exactly the same way. |

Additional rules  

* **Re-orgs** – If the original funding transaction is rolled back, verifiers will see `gettxout == null`; badge is *temporarily* revoked until the tx confirms again.  
* **No grace period** – Credential liveness is a direct boolean view of the anchor.  
* **Delegated 2-of-2 anchors** – A unilateral close by either party counts as a spend/settle and thus revokes the badge.  

> In short: **coin (or HTLC) present → badge live; coin/HTLC gone → badge dead.** Nothing in between.

### 5.8 Reference REST Envelope *(optional helper API)*  

Implementers may expose a thin HTTP wrapper so front-ends can verify badges without bundling a full Bitcoin/LN stack.  
The schema below is **non-normative**—clients can skip it and talk to the verifier library directly.

#### 5.8.1 POST `/oc/claim`

Store or relay a new claim.

```json
{
  "claim": "{...canonical JSON...}",
  "sig"  : "Base64URL(BIP322-sig)"
}
```

Response `201 Created` or `400 Bad Request`.

#### 5.8.2 POST `/oc/verify/<handle>`

Return live status plus minimal context.

```json
// Taproot badge
{
  "status" : "valid",          // "valid" | "revoked" | "invalid"
  "weight" : "125000",         // sat
  "confs"  : 12,               // current confirmations
  "anchor" : "f0c1ad71…:0"
}

// Lightning badge
{
  "status"   : "valid",
  "weight"   : "25000",        // sat
  "blocks_to_expiry" : 720,    // remaining blocks before CLTV timeout
  "anchor"   : "a4b0d2f8…:ln"
}
```

**Behaviour guidelines**

* **No authentication required** – data are public; rate-limit by IP.  
* **Cache** – positive lookups **MAY** be cached up to 10 s; negative results (`revoked` / `invalid`) **SHOULD NOT** be cached.  
* **Lightning probes** – if the backend cannot reach an LN node, return `{ "status": "indeterminate" }` with HTTP `202`.

### 5.9 Extensibility  

| Aspect | Rule | Rationale |
|--------|------|-----------|
| **Top-level keys** | A verifier **MUST** reject any claim whose top-level keys differ from the allowed set for `v = 1`:<br>`{h, t, u, v}` for Taproot anchors;<br>`{h, t, u, k, v}` for Lightning anchors. | Keeps canonical-bytes deterministic and prevents silent feature creep. |
| **`meta` object** | Future versions MAY introduce an optional `"meta"` field that contains a SHA-256 hash of auxiliary off-chain data (e.g., avatar or credentials). Verifiers that do not recognise it **ignore** the data while still validating stake. | Allows richer credentials without bloating the core or harming old clients. |
| **Anchor types** | New anchor types (e.g., RGB, Ark) MUST be encoded as `"<anchor_id>:<suffix>"`, where `suffix` is a *reserved* string; acceptance requires a new major version **or** an explicit OCP (OrangeCheck Proposal) marked “minor-compatible”. | Clean namespace, no collisions with `:ln`. |
| **Message format** | Any change that alters canonical serialisation order or signature domain increments the **major** version (`v = 2`, `3`, …). Old verifiers MUST reject unknown majors. | Ensures downgrade safety. |
| **Crypto agility** | Post-quantum migration follows whatever curve or signature scheme Bitcoin adopts; the anchor will then use the new key type without modifying higher layers. | Keeps OrangeCheck aligned with Bitcoin consensus. |
| **Process** | All changes are proposed as **OCPs** (markdown + reference code) in the public repo. Three independent implementation reports are required before merging. | Transparent, no gatekeeper. |
| **Activation** | A new major version activates when **≥ 90 %** of *weighted* live stakes (by sat) have re-signed over a 12-month window. | User-driven upgrade path; no central switch-flip. |

### 5.10 Test Vectors  

| Case | Claim JSON (canonical, abridged) | Anchor live? | Expected result | Notes |
|------|----------------------------------|--------------|-----------------|-------|
| **Taproot · Minimal** | `{"h":"@mini","t":1718000000,"u":"8c1f…6c3a:0","v":1}` | UTXO unspent, value = 100 000 sat | `Valid(weight=100 000, confs=12)` | Key-path only, 12 confs |
| **Taproot · Timelock** | `{"h":"@lock","t":1718000100,"u":"ab9d…09ff:1","v":1}` | UTXO unspent, CLTV not reached, value = 500 000 sat | `Valid(weight=500 000, confs=6)` | Script-path CLTV = 840 000 |
| **Taproot · Spent** | *same claim as “Minimal”* | UTXO **spent** | `Revoked()` | Spend seen in chain |
| **Lightning · HOLD live** | `{"h":"@bob","t":1718000200,"u":"a4b0d2f8c0e7…9f12:ln","k":"02fd…a9c7","v":1}` | `HTLC.state = PENDING`, value = 25 000 sat, expiry = +720 blocks | `Valid(weight=25 000, blocks_to_expiry=720)` | HOLD invoice in user-run node |
| **Lightning · Settled** | *same claim as above* | `HTLC.state = SETTLED` | `Revoked()` | Pre-image revealed |
| **Lightning · Bad-sig** | JSON as above, but signature byte flipped | — | `Invalid("bad signature")` | Signature fails |

Reference verifier implementations (Rust, Python) and the full claim + signature strings are published in the `/test_vectors` directory of the repository. These vectors are **illustrative**, not normative; any implementation that passes them **and** the algorithm in § 5.5 is considered conformant.

### 5.11 Linkability and Anti-Surveillance Best-Practices


OrangeCheck is **pseudonymous** by default—no personal data is baked into the claim—but careless funding or routing can still leak linkage. Below are optional techniques to keep provenance dark.

| Anchor type | Threat | Mitigation |
|-------------|--------|------------|
| **Taproot UTXO** | Chain analysts trace the funding coins back to a KYC exchange. | 1. Fund via **CoinJoin / PayJoin**.<br>2. Use an LN-to-Taproot **submarine swap**, then broadcast the funding tx from your own node.<br>3. Never reuse the same X-only key in other contexts.<br>4. Hide signer set with **MuSig2 / FROST**. |
| **Lightning HOLD** | The source node ID or channel graph reveals your real-world IP / identity. | 1. Run your node behind **Tor** or an LSP that offers blinded paths.<br>2. Use **BOLT-12 offers** + **onion-message** so the public cannot query your node by pubkey.<br>3. Regenerate a fresh node alias (and HOLD invoice) per separate persona.<br>4. If maximum privacy is needed, loop funds out through a mixed on-chain output first, then back into a private channel. |
| **Both** | Same bond reused across unrelated personas links them. | Spin up distinct stakes (and keys) per persona or per context (e.g., whistle-blowing vs. social). |

Remember: verifiers see only the **anchor id**, never the funding path—but adversaries observing the chain or gossip network might still link you unless the above hygiene is followed.

### 5.12 Versioning and Change-Control  

OrangeCheck follows a **community-driven, coin-weighted upgrade path** that protects both users and integrators from surprise breakage.

| Item | Rule | Why |
|------|------|-----|
| **Semantic flag** | Every claim carries `"v": n`.<br>Verifiers **MUST** hard-fail on unknown majors. | Prevents downgrade and ambiguous parsing. |
| **Minor vs major** | *Minor* change = adds optional fields or new anchor **suffix** (`":ark"`). Old verifiers ignore.<br>*Major* change = alters canonical serialisation, signature domain, or verification logic. Requires `v++`. | Keeps the “narrow waist” stable. |
| **OrangeCheck Proposal (OCP)** | All spec changes are filed as Markdown + reference code PRs. Must cite security analysis and test vectors. | Open, auditable process similar to BIPs/BOLTs. |
| **Implementation reports** | An OCP is **eligible** after three independent, interoperable implementations pass the reference vectors. | Ensures real-world viability. |
| **Activation threshold** | A new **major** version activates when **≥ 90 %** of *weighted* live stakes (sat + msat // 1000) have re-signed to the new version during a 12-month look-back window. | Coin-weighted voting aligns with “skin-in-the-game.” |
| **Grace period** | Minor features become *recommended* immediately after merge; they never invalidate v-1 claims. | Optional adoption, zero churn. |
| **Narrow-waist mandate** | Core MUST remain: one bond, one sig, two liveness probes (`gettxout`, HTLC lookup). Any design that adds global registries, alt-tokens, or persistent gossip **forks** into a new major. | Preserves simplicity, avoids feature drag. |
| **Crypto agility** | If Bitcoin adopts a new signature scheme (e.g., post-quantum), OrangeCheck **inherits** it: anchors shift to the new key type; spec version only bumps **minor** as canonical order stays intact. | Future-proof without hard reset. |
| **Emergency bug-out** | If a consensus bug or catastrophic vuln requires revoking all v-1 badges, the recovery path is: ① spend/settle old anchors; ② re-issue claim with `v=1, rev=2` (hot-fix sub-field); ③ major rev follows standard process. | Gives operators an immediate kill-switch while preserving orderly upgrade governance. |

> **TL;DR –** The protocol is governed by *coins, code, and community*—no foundation, no trademark licence, no central veto. If you stake value on OrangeCheck, you automatically hold a vote.
