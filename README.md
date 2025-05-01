# OrangeCheck Protocol
*A Bitcoin-anchored identity primitive*  
**White Paper – Draft 1.0 (April 2025)**  
_By. [@TheBTCViking](https://x.com/TheBTCViking)_

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Protocol Overview](#2-protocol-overview)
   + 2.1 [Comparative Landscape](#21-comparative-landscape)
   + 2.2 [Economic and Philosophical Rationale](#22-economic-and-philosophical-rationale)
   + 2.3 [Security and Threat Model](#23-security-and-threat-model)
   + 2.4 [Sovereign and Critical-Infrastructure Applications](#24-sovereign-and-critical-infrastructure-applications)
3. [Adoption Pathways and Illustrative Policies](#3-adoption-pathways-and-illustrative-policies)
4. [Formal Specification](#4-formal-specification)
   + 4.1 [Notation and Pre-requisites](#41-notation-and-pre-requisites)
   + 4.2 [Stake-Output Construction](#42-stake-output-construction)
     + 4.2.1 [Key-path Only](#421-key-path-only-minimal-form)
     + 4.2.2 [Key-path + CLTV Script-path](#422-key-path--cltv-script-path-timelocked-form)
   + 4.3 [Canonical Claim](#43-canonical-claim)
   + 4.4 [Signature Procedure](#44-signature-procedure)
   + 4.5 [Deterministic Verification Algorithm](#45-deterministic-verification-algorithm)
   + 4.6 [Weight Semantics (non-normative)](#46-weight-semantics-non-normative)
   + 4.7 [Revocation Semantics](#47-revocation-semantics)
   + 4.8 [Reference REST Envelope (optional)](#48-reference-rest-envelope-optional)
   + 4.9 [Extensibility](#49-extensibility)
   + 4.10 [Test Vectors](#410-test-vectors)
   + 4.11 [Linkability & Anti-Surveillance Best-Practices](#411-linkability-and-antisurveillance-best-practices)
   + 4.12 [Versioning and Change-Control](#412-versioning-and-change-control)

---

## 1. Abstract

> The Internet is awash in identities that cost nothing to mint, nothing to burn, and therefore nothing to trust. Platforms respond by selling proprietary check-marks or by harvesting passports, turning spam into rent and privacy into collateral.
> OrangeCheck offers a simpler bargain: publish a name only if you are willing to lock a measure of Bitcoin behind it, and let the chain itself attest—without intermediaries, tokens, or personal documents—that the lock still holds. The mechanism is disarmingly small. One Taproot output, funded and left unspent, becomes the whole credential; a single BIP-322 signature binds that output to a chosen handle; and a lone `gettxout` query is enough for any service to decide, in real time, whether the bond endures. Should the coins move, the badge dissolves everywhere at once; should a community demand greater assurance, it need only raise the satoshi or timelock threshold it is willing to respect. Every facet of reputation—creation, weighting, and revocation—emerges from the ordinary physics of Bitcoin itself, not from a registrar or a smart-contract VM or separate utility token. By pricing identity in provable energy while leaving its interpretation to the edge, OrangeCheck restores economic gravity to online speech without exacting a toll of data or dependence. It is a protocol in the strict sense of the word: an invariant kernel small enough to fit on a postcard, open enough to be owned by no one, and sturdy enough to let truthful voices stand out against a background of cost-free noise.

---

## 2. Protocol Overview

The OrangeCheck protocol stands on a deceptively small foundation. An identity is nothing more than a single, unspent output on the Bitcoin blockchain—an amount of value that its owner has deliberately sequestered—and a brief, signed statement that publicly links that output to a chosen handle. Together, these two artifacts form a self-contained credential whose truth can be tested by anyone, anywhere, with one question to the ledger.

Creation begins when a user generates a fresh Taproot address and funds it with as many satoshis as she is willing to place at risk. Because the address is new and never reused, its sole purpose is to embody the identity; it carries no prior history and betrays no other information. If she wishes to signal a longer-term commitment she may embed a simple Check-Lock-Time instruction, preventing the coins from moving until a future block height. Nothing exotic is required: every modern wallet can craft such a transaction today.

Having planted this monetary flag, the user writes a tiny, canonical message—version number, handle, outpoint, timestamp—and signs it with the same key that can spend the stake. That signed blob may be published wherever she already speaks: appended to a Nostr note, tucked into a DNS-TXT record, pinned to IPFS, or left in the memory of a voluntary gateway. No global registry is introduced, nor is one needed; the claim is self-describing and the chain itself is the only scoreboard.

Verification is correspondingly austere. A relying service fetches the claim, checks the BIP-322 signature, and then asks a single question of a Bitcoin node: does the referenced outpoint remain unspent, and what value does it hold? If the answer returns a positive balance—and, where relevant, the timelock has not yet expired—the handle is immediately valid. Its “weight” is an objective on-chain fact, yet each application is free to interpret that fact as it pleases: a binary pass/fail, a linear reputation score, a square-root curve that tempers whales, or any future heuristic. Because the interpretation lives outside the protocol, the rules of OrangeCheck never change.

Revocation is automatic and irrevocable. The moment the owner spends the coins, or a deep re-organisation erases them, the next `gettxout` call returns nothing, and every verifier in the world simultaneously recognises the badge has evaporated. There are no blacklists to update, no support channels to petition, and no guardians to persuade. Liveness equals coin-ness: when the value moves, the identity dies, and the cost of resurrection is the cost of a brand-new stake.

_In four sentences: lock bitcoin; bind it, in public, to a name; let the network itself guarantee both authenticity and weight; and allow the ordinary act of spending to wipe the slate clean. This is the entirety of the OrangeCheck protocol._

### 2.1 Comparative Landscape

| Property | **OrangeCheck<br>(Bitcoin)** | ENS / Polygon | W3C DID + WebAuthn | PoS “ID tokens” | Worldcoin / Biometrics |
|----------|------------------------------|---------------|-------------------|-----------------|------------------------|
| **Anchor** | UTXO + PoW (irreversible) | ERC-721 (upgradable) | Vendor-hosted JSON & PKI | Validator quorum | Central iris DB |
| **Sybil cost** | Linear in sats locked; energy-priced | ≈ $0 (gas) | ≈ $0 | Buy stake token once | Free after KYC |
| **Revocation** | Spend coin → badge dies everywhere | `nameWrapper` only | Rotate endpoint keys | Cartel vote | Operator decree |
| **Custodian risk** | None (user key) | ENS DAO & L2 bridges | Hosting provider | Token issuer & stakers | Foundation custody |
| **Political neutrality** | Global bearer asset | Subject to USDC/USDT rails | Local regulation | Governance politics | Sanction lists |
| **Dependency stack** | Bitcoin Core only | Ethereum L1+L2 | Web PKI + browser CAs | Custom chain | Proprietary HW |

> **Take-away :** Every alternative re-introduces either a change-controlled contract, a rent-seeking token, or a political chokepoint. OrangeCheck’s sole dependency is the most censorship-resistant ledger on Earth.

---

### 2.2 Economic and Philosophical Rationale

The modern Internet was built on the assumption that identity should be frictionless. E-mail addresses and social-media handles spring into existence at effectively zero cost, and—because they can be discarded just as cheaply—nothing that is said or promised through them needs to be taken seriously. We have tried to patch this vacuum with two very different tools. At one extreme lie bureaucratic credentials: government photo IDs, selfies holding passports, scans of utility bills. These create a strong mapping from a digital handle to a flesh-and-blood citizen, yet the mapping is neither portable nor private. Each platform becomes a honeypot of sensitive information, and the citizen is forced to reveal more than the conversation actually demands. At the other extreme lie proprietary badges such as the blue check-mark, a brand rented from a private gatekeeper for a monthly fee. The badge signals something, but what it signals is mostly that the user is willing to pay—or to keep paying—a toll to speak. It is a marker of rent, not of commitment or authenticity.

OrangeCheck proposes a very different signal: the deliberate burning of opportunity cost. To lock a small quantity of Bitcoin in a fresh Taproot output is to surrender the liquidity of that value for as long as the lock endures. The locked coin is not abstract; it is the embodied residue of electricity that has already been transformed into proof-of-work. Behind every satoshi stands a slice of real energy and a thin column of entropy that could not be forged more cheaply elsewhere. The bond therefore functions as a miniature proof-of-burn, visible to the entire world and denominated in the hardest monetary unit humanity has yet discovered.

The philosophical elegance of this approach is that it needs no oracle, no custodian, and no committee to interpret what the stake means. It simply exists, or it doesn’t. Were the user to mint a thousand identities, she would have to immobilize a thousand times the capital; were she to misbehave egregiously, she would need to spend or abandon the stake and thereby lose the badge. The protocol is value-agnostic: it never opines on the morality or legality of speech, it only measures the willingness of a speaker to freeze real wealth in order to have that speech taken seriously. It enforces what economists call a costly signal, in the precise Spence-ian sense: a behaviour that low-value actors find prohibitively expensive, but that high-value actors can afford and therefore elect.

Contrast this with KYC. A passport proves that a government is willing to register your birth and issue you paperwork; it does not prove you will behave honorably, nor does it impose an ongoing cost when you do not. Indeed, once the selfie is uploaded the user pays no further price for spawning additional accounts. The economic marginal cost remains zero. The OrangeCheck bond, by forcing every additional handle to carry incremental opportunity cost, restores linearity to the economics of Sybil resistance. Ten thousand bots become ten thousand drains on the attacker’s balance sheet, and the only path to free spam is to counterfeit Bitcoin itself—an activity which, at scale, would be more expensive than simply speaking honestly.

Energy pricing is also apolitical. A citizen in Lagos or São Paulo can post the same 50,000-sat bond as a citizen in San Francisco, and the network will read precisely the same weight. No bank account or credit score is needed, merely access to an on-chain transaction. Because the mechanism is indifferent to jurisdiction, it resists both corporate capture and national sanction lists. The value staked has no issuer that can freeze it; the user need not beg a firm or a regulator for permission to take part in public discourse. In this way OrangeCheck honours the decentralist credo that Bitcoin itself introduced: rules, not rulers.

Finally, the protocol refrains from dictating how the stake must be interpreted. A small hobby forum may decide that 0.00001 BTC suffices, a global finance platform may require 0.05 BTC and a six-month timelock, and a DAO may square-root all weights to dampen plutocracy. Each of these policies is coherent, and each can evolve without a change to the underlying rules, because the protocol exposes only incontestable facts: coin, height, and lock. Interpretation belongs to the edge, where human communities can imbue those facts with the norms that suit them.

In short, OrangeCheck’s economic foundation is both ancient and modern. It revives the centuries-old idea of earnest money—a pledge visible to one’s peers—and weds it to the thermodynamic finality of proof-of-work. The result is a signal that cannot be counterfeited for less than it costs to create and that survives the collapse of every registry or corporation that might try to mediate it. It is a protocol of skin-in-the-game, expressed in the most neutral unit of skin we have.

---

### 2.3 Security and Threat Model

Any protocol that pretends to defend authenticity must be willing to stare its own adversaries in the eye. OrangeCheck’s simplicity is not an accident of omission but a deliberate attempt to reduce the surface upon which attackers can press. Yet certain categories of threat remain, and they deserve sober treatment rather than marketing gloss.

The first and most obvious attack is simple key theft. If an adversary steals the private key that governs the stake output, she can both transfer the Bitcoin and impersonate the handle until such time as the spend is confirmed and verifiers notice that the bond is gone. This window is small—six blocks under the canonical policy—but non-zero. The recommended mitigation is to encourage users to treat their identity key as they would any long-term cold stake: generated on an air-gapped machine, secured by hardware, and perhaps split into a two-of-two multisig so that no single compromise yields immediate control. By raising the operational bar for the adversary, the cost of theft approaches the cost of outright physical confiscation of cold storage, which no online system can entirely prevent.

A subtler threat is the whale Sybil. A wealthy actor may slice a large balance into hundreds of medium-sized outputs, spawning a legion of weighted identities that could sway a naïve “weight equals influence” platform. The defence is not cryptographic but economic. Because the protocol exports a raw datum—number of sats unspent—each community is free to transform that datum before granting power. A square-root or logarithmic curve dramatically diminishes marginal influence from the nth account, rendering the attack progressively uneconomic. It is cheaper for the whale simply to speak in her own name with one large bond than to fracture the stake into a thousand shards that confer little additional leverage. The protocol therefore hands the knife to the community: if you do not wish whales to dominate, do not weight them linearly.

Exchange output reuse is another avenue. Suppose a custodial service creates deposit addresses for customers and one customer signs a claim using such an address. The signature is valid, yet the key is not under her exclusive control; the exchange could reassign the same output to a different claimant, or spend it without notice. Verifiers can neutralise this by blacklisting known exchange clusters, a technique already employed by chain-analysis heuristics. Because OrangeCheck exposes only the outpoint, a verifier needs no new infrastructure: it can lean on existing “spent from exchange” indicators to refuse suspect stakes.

What about deep chain reorganisations? Because the validity check rests on `gettxout`, any re-org that removes the stake transaction will momentarily make the badge disappear until the user rebroadcasts or until the chain settles again. This is not a flaw but a reflection of reality: in a re-org, every transaction is in question, and OrangeCheck identities are no different. Applications that require absolute continuity can wait for twelve or even twenty-four confirmations before honouring a credential; the trade-off is latency. The protocol itself is agnostic, merely surfacing the coin’s observable state at the queried tip.

Denial-of-service risks must also be considered. Could a hostile network blanket the Internet with fake claims and force every verifier node to perform millions of `gettxout` calls? In theory yes, yet the defence is trivial: verifiers need only check claims that appear in their own feeds. A service such as a social network or forum naturally receives claims through its own submission channels and thus controls its ingest rate. There is no global crawler obliged to process every blob on IPFS. Scalability is, by architecture, an edge concern.

Finally, quantum adversaries occasionally rear their speculative heads. The day a practical quantum computer can break secp256k1 is the day Bitcoin itself must roll to a post-quantum signature scheme. Because OrangeCheck relies on exactly the same key material, it will migrate in lock-step with the base protocol. No separate upgrade path is required.

Taken together, these threats describe a protocol whose worst-case failure modes revert neatly to first principles. If the stake vanishes, the badge dies with mathematical certainty; if a key is stolen, economic pain follows the victim until the chain records the spend; if a whale attempts capture, policy can neuter her advantage without a line of change to the specification. OrangeCheck’s security is as strong—and no stronger—than Bitcoin’s UTXO model and the community’s willingness to interpret that model sensibly. That is a virtue, not a limit.

---

### 2.4 Sovereign and Critical-Infrastructure Applications

| Domain | OC Integration | Attack Prevented |
|--------|----------------|------------------|
| **Software-update signing** | Defence ministries anchor firmware manifests to a 0.5 BTC multisig stake. Field units verify OC before flashing. | Supply-chain hijack / fake binary |
| **Emergency broadcast** | Civil-defence agency stakes 0.5 BTC; cell & TV networks relay alerts only if OC live. | Spoofed evacuation orders |
| **Diplomatic cables** | Embassies accept messages signed by ≥ 5-of-7 keys whose Merkle root matches the on-chain stake. | Impersonation of foreign-service officials |
| **LEO satellite commands** | Ground packets must carry an OC proof bound to the satellite-owner stake. | Hostile take-over of space assets |

---

## 3. Adoption Pathways and Illustrative Policies

A protocol, however elegant, is sterile until breathed into by real users and the institutions that serve them. To make the discussion concrete, imagine three actors: a global social network we will call Agora, a themed discussion forum named Stacktown, and a decentralised treasury DAO referred to as Common-Pool. Each faces a swarm of low-cost identities and must decide how OrangeCheck can temper the noise without freezing out genuine voices.

Agora’s dilemma is scale. It handles hundreds of millions of daily log-ins and has already tried phone verification, only to find that SIM swaps and low-cost VoIP numbers merely shift the goal-posts. The product team defines a rule: any account with a 0.001 BTC stake confirmed six blocks deep is eligible for an orange tick beside its handle. They ship a ten-line patch: on log-in the client sends the claim; a backend Lambda calls `gettxout`; if `unspent` and ≥ `0.001` BTC the badge flag is set. Within a week the spam metrics fall by half: bot operators discover that fielding ten thousand accounts now costs roughly ten Bitcoin, whereas the expected advertising or scam revenue from those accounts lies orders of magnitude lower. Honest users, by contrast, need lock only once and enjoy frictionless posting everywhere Agora’s brand extends.

Stacktown operates at a smaller scale but with tighter community norms. It chooses to weight identity quadratically. Users who wish to vote on questions are required to post at least 100,000 satoshis, but their voting power rises with the square root of their posted value. A whale seeking to dominate all polls finds diminishing returns; two ordinary engineers with 0.1 BTC each out-vote a single baron with 0.4 BTC. The forum publishes its weighting curve in the FAQ and treats OrangeCheck weight as just another column in its reputation score. The policy lives at the edge, exactly as the protocol intends, and can be tuned as the culture of the forum evolves.

Common-Pool, the DAO, takes a different tack. Its treasury is substantial, and token governance alone has proven fragile to flash-loan attacks. The community institutes a second chamber where proposals require orange-weight quorum. Any address may lock 0.005 BTC for at least six months and then vote proportionally to that stake. Because 0.005 BTC is material but not prohibitive, the chamber organically accumulates a few hundred voices. More importantly, the economic cost of carpet-bombing proposals collapses: a malicious actor would have to immobilise millions in Bitcoin merely to inject noise. The DAO thus buys signal for its attention.

Integration for each of these entities required no change to their business model, no extra token, and no central authority to certify users. Each imported a small open-source verifier library, set threshold and curve in configuration files, and linked a “Connect OrangeCheck” button to an existing wallet standard. Because the claim is bound by a standard BIP-322 signature, mobile wallets rapidly add “Sign with OrangeCheck” flows, and the user experience converges on the familiar idiom of “connect wallet,” minus the risk of ERC-20 approvals and phishing pop-ups. Stake once, roam freely.

Edge cases inevitably arise. A journalist loses her hardware wallet and must re-stake. She posts a new claim and a short note explaining the spend; because the spend is visible, her followers can audit the continuity. A developer conference wants a temporary trust tier for ticket buyers; it instructs its registration link to accept claims with any value but at least a two-week timelock, thereby ensuring the badge remains live until the event concludes. A whistle-blower needs anonymity; he funds his stake through a CoinJoin and publishes only the handle and outpoint, never revealing a real-world identity yet still paying the economic price of speech.

Each scenario demonstrates the same pattern: OrangeCheck supplies a single, incorruptible fact—value locked in an unspent output—and a deterministic guarantee that the fact will invalidate itself the moment reality departs from the claim. Communities project their own social meanings onto that fact, whether it is the right to speak, to vote, or simply to appear with a badge that cannot be rented for fiat. The protocol does not adjudicate those meanings; it merely ensures that the underlying signal cannot be faked for less work than it took to create it.

In this sense OrangeCheck completes a circuit begun when Bitcoin first priced time and energy in hash-rate. Where proof-of-work made honest money expensive to counterfeit, OrangeCheck makes honest identity expensive to counterfeit. It is not a universal proof of personhood, nor does it aspire to be. What it offers—quietly, without ceremony—is a way to bind words to sacrifice, so that when we listen in the din of cyberspace we can once again hear which voices have something real at stake.

---

## 4. Formal Specification

> This section freezes the invariant core of the protocol. Everything beyond these rules—gateways, weighting curves, user-interface conventions—is non-normative and may evolve without revision to the specification.

### 4.1 Notation and Pre-requisites

* **BTC** denotes the Bitcoin blockchain mainnet, consensus rules as of Taproot activation (BIP-341/342).
* **UTXO** = unspent transaction output.
* **BIP-340** Schnorr public keys are 32-byte X-only values.
* **BIP-322** “Generic Signatures” define how arbitrary messages are signed and verified against a script path or key path.
* **CLTV** refers to `OP_CHECKLOCKTIMEVERIFY`.
* **Big-endian hex** is used for all binary examples.

The verifier is assumed to possess:

1. A fully-validating Bitcoin node or trusted proxy that exposes the RPC method `gettxout(txid string, n int, include_mempool bool) -> json`.
2. A BIP-322 signature engine for both ECDSA (legacy) and Schnorr (preferred).

### 4.2 Stake Output Construction

The credential’s anchor is a Taproot key-path spend, optionally augmented by a CLTV script path to add a time cost.

#### 4.2.1 Key-path only (minimal form)

```text
scriptPubKey = OP_1 <32-byte-X-only-pubkey>
value        ≥  dust_limit + relay_fee
```

- `dust_limit` is the prevailing Core policy (currently 546 sats for P2TR).
- `relay_fee` is the node’s minimum feerate (e.g., 1 sat/vB).
- There is no `OP_CHECKLOCKTIMEVERIFY` branch; spendability is instant.

#### 4.2.2 Key-path + CLTV script-path (timelocked form)

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

### 4.3 Canonical Claim

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

### 4.4 Signature Procedure (BIP-322)

Let **pk** be the X-only key that controls the _key-path_ of the stake output. The signature domain is:

```text
msg_hash = SHA256(C)
sig      = BIP322-SIGN(pk, msg_hash)
```

The resulting `sig` is 64 bytes for Schnorr or 71-73 bytes DER for ECDSA.

Publish **(C, sig)** together. For human-readable media (Twitter, Nostr) the signature should be base64url-encoded.

### 4.5 Deterministic Verification Algorithm

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

### 4.6 Weight Semantics (Non-normative)

The protocol guarantees only the numeric value of the stake in satoshis. A relying service MAY map that to influence by:

- **Binary** (valid ≥ threshold ⇒ badge).
- **Linear** (weight = value).
- **Quadratic** weight = ⌊sqrt(value)⌋.
- **Timelock** bonus weight = value × (1 + months_locked/12).

Such transforms occur entirely off-chain; they do not affect interop.

### 4.7 Revocation Semantics

- Spending the output in any transaction—key path or script path—causes `gettxout` to return null.
- Re-orgs that drop the funding transaction result in immediate revocation until the transaction is re-mined.
- There is no grace period; credential liveness equals UTXO existence.

### 4.8 Reference REST Envelope (optional)

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

### 4.9 Extensibility 

- Unknown top-level keys in the JSON claim MUST cause a verifier to reject. Future versions increase `"v"` and document new keys.
- A `meta` field MAY be introduced in a later version to carry a SHA-256 of auxiliary data (avatar, credentials). Verifiers that do not understand it ignore that data while still validating stake.
- Post-quantum migration will follow whatever curve Bitcoin selects; the stake output then uses the new key type without altering higher layers.

### 4.10 Test Vectors

| Case        | txid : vout                                   | Value (sat) | CLTV height | Handle  | Canonical Hash (SHA-256, hex) | Signature (base64url, truncated) |
|-------------|-----------------------------------------------|----------|------------|---------|------------------------------|----------------------------------|
| Minimal     | `8c1f…6c3a:0`                                 | 100000   | —          | `@test` | `0be2c7…4a5d`                | `MEYCIQD…`                       |
| Timelocked  | `ab9d…09ff:1`                                 | 500000   | 840000     | `@lock` | `f1a6d4…219c`                | `AkEAh…`                         |
| Bad-sig     | *same outpoint as “Minimal”*                  | 100000   | —          | `@fake` | `7c94e1…b02a`                | — (invalid)                      |

A reference verifier in Rust and Python with the above vectors will be published in the `oc` repository. The test vectors are not normative but are provided to illustrate the protocol’s behaviour.

### 4.11 Linkability and Anti-Surveillance Best-Practices

1. **CoinJoin / PayJoin funding** – create the stake from mixed coins so the UTXO cannot be trivially traced backwards.  
2. **LN → on-chain submarine swap** – fund the Taproot output without revealing your source node.  
3. **One-time handles** – use separate stakes for unrelated personas (e.g., whistle-blowing vs. social).  
4. **MuSig2 / FROST multisig** – hide the signer set; chain observers see only one X-only key.  
5. **Avoid address reuse** – never post the same Taproot public key in other contexts.

Following these practices keeps OrangeCheck a *proof-of-cost* signal rather than a surveillance beacon.

### 4.12 Versioning and Change-Control

* **Semantic flag** – Every claim includes `"v": n`; verifiers **MUST** reject unknown majors.  
* **OCP process** – Changes are proposed as **OrangeCheck Proposals** (markdown + reference code) in the public repo. Three independent impl-reports required.  
* **Activation rule** – A new major version activates when ≥ 90 % of *weighted* live stakes have re-signed over 12 months. No committee can override; the community signals by moving its own coins.  
* **Narrow-waist mandate** – The core will *not* add global registries, alt-chains, or rent tokens. Such ideas fork into a brand-new major version.

---

> _The specification above constitutes the entire OrangeCheck protocol: build a Taproot stake, sign a canonical claim, and let every verifier on Earth rest its decision on a single, immutable fact—“does the coin still sit where the claim says it does?” All higher-order meaning flows from that fact and is free to evolve without another change to these rules._
