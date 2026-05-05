# NH vs. peer-state DAO frameworks: comparison framework

A side-by-side matrix to ground the "what makes NH different from
Wyoming?" question raised in the design sprint. This is a working
template — entries marked **(verify)** need confirmation from primary
sources before quoting publicly. The NH column is filled in from the
RSA 301-B text and the reference implementation.

The point of this document is not to rank states. It is to surface the
architectural choices each state has made so that NH's choices are
deliberate.

## The matrix

| Dimension | NH (RSA 301-B) | Wyoming | Tennessee | Utah | Vermont | Arizona |
|---|---|---|---|---|---|---|
| **Year enacted** | 2026 | 2021 (DAO Supplement, W.S. 17-31) | 2022 (Decentralized Org. Act) (verify) | 2023 (DAO Act) (verify) | 2018 (BBLLC, 11 V.S.A. §4173) | 2018 (LLC blockchain provisions) (verify) |
| **Entity model** | Standalone DAO entity; partial LLC import only | LLC subtype ("DAO LLC") | LLC subtype (verify) | LLC subtype (verify) | LLC subtype ("BBLLC") | LLC blockchain provision (verify) |
| **Closest analog** | Cooperative-leaning (per Sam Nathans, partial LLC import = closer to co-op) | LLC | LLC | LLC | LLC | LLC |
| **Member liability** | TBD per statute reading | LLC-style limited liability | LLC-style (verify) | LLC-style (verify) | LLC-style | LLC-style (verify) |
| **Algorithmic vs. member-managed** | Both contemplated | Both (algorithmic explicit) | Both (verify) | Both (verify) | Both | Both (verify) |
| **Filing fee** | TBD; HB 639 / companion contemplates stablecoin payment | Standard LLC fee | LLC fee (verify) | LLC fee (verify) | LLC fee | LLC fee (verify) |
| **Stablecoin payment accepted** | Contemplated | No | No (verify) | No (verify) | No | No (verify) |
| **DID issuance for entity** | **Yes** (`did:web` per filing) | No | No | No (Utah VCs are for credentials, not entity ID — per Sam) | No | No |
| **Verifiable Credential of standing** | **Yes** (planned, this MVP) | No | No | Adjacent (state-issued VCs for licenses, not entities) | No | No |
| **Registered agent required** | **Yes**, NH physical street address, no PO box | Yes, WY agent | Yes (verify) | Yes (verify) | Yes | Yes (verify) |
| **Smart contract address mandatory** | **Yes** (RSA 301-B MVP eligibility) | Yes (DAO LLC operating agreement references) | TBD | TBD | TBD | TBD |
| **Chain-agnostic by design** | **Yes** (CAIP-2 chain identifiers; no preferred chain) | De facto chain-agnostic | TBD | TBD | TBD | TBD |
| **Public read access (no account)** | **Yes** (public DID resolution + record API) | Public business search | Public business search | Public business search | Public business search | Public business search |
| **Machine-readable filing record** | **Yes** (signed JSON-LD DID document, canonical hash, Verifiable Credential) | HTML/PDF business search; no signed JSON | Standard SoS data | Standard SoS data | Standard SoS data | Standard SoS data |
| **Cross-state pointer compatibility** | Designed for it (DID + alsoKnownAs); foreign filings can reference each other by DID | None | None | Adjacent (TrustOverIP-aligned in some pilots, verify) | None | None |
| **Hash anchor / public timestamp of record** | **Yes** (Polygon Amoy, evidence-only — SoS DB is authoritative) | No | No | TBD | No | No |
| **IPFS pinning of governance bytes** | **Yes** (mandatory) | No | No | No | No | No |
| **Open-source reference implementation** | **Yes** (this repo) | No | No | No | No | No |
| **Number of DAOs registered (as of writing)** | 0 (statute new) | 1,000s (verify current count) | TBD | TBD | "BBLLC" count low | TBD |
| **Cybersecurity-operated posture** | Aspirational (per design sprint discussion) | TBD | TBD | TBD | TBD | TBD |

## Where NH has a credible differentiator

Two columns above — **DID issuance** and **machine-readable signed
record (with VC of standing)** — are not present in any other state's
framework as far as the working group has identified. That combination
is what lets a NH-registered DAO be:

- queried by a smart contract on any chain via signed VC,
- cross-verified by a foreign SoS via portable DID,
- proven authentic by any vendor or bank without an SoS API key,
- audited by any member of the public without scraping a website.

This is the answer to web3iam.eth's question (msg 125): "what would
even be the reason why a DAO would pick one State over another?" The
answer is not "lower fees" or "less regulation" — every state can
race to the bottom on those. The answer is **portable, cryptographically
verifiable legal entity identity**, which actually lets a DAO operate
on-chain, off-chain, cross-chain, and across jurisdictions without
re-keying its identity at each boundary.

## Where NH has a copy-the-others choice to make

These are dimensions where the working group has a defensible choice
in either direction; the comparison just makes the choice visible:

- **Entity model.** WY/TN/UT/VT/AZ all chose "LLC subtype." NH's RSA
  301-B is a partial LLC import, leaving more room for co-op-style
  treatment. Sam's read (msg 112) is that this is closer to a
  cooperative; if so, that should be deliberate. If the legislature
  intended LLC-style, the partial import is a bug to fix.
- **Liability default.** LLC-style limited liability is the
  near-universal choice. Diverging requires articulated reasoning.
- **Algorithmic vs. member-managed.** Every state allows both. NH
  should too unless there's specific reason not to.

## Where NH's design is *bolder* than peers

These are choices made by the design sprint that are genuinely
different and may warrant attention or pushback in policy review:

- **`did:web` resolution required.** No other state issues a resolvable
  DID per registered entity. This is the strongest interop primitive
  but also a sustained operational commitment (the SoS website becomes
  the DID resolver).
- **Mandatory IPFS pinning of governance documents.** Every other state
  stores PDFs in their own filing system. Pinning to IPFS means the
  governance bytes are content-addressable and independently verifiable
  by any third party, but it adds a new infrastructure dependency.
- **Chain anchor as evidence.** Anchoring the canonical hash of each
  filing to a public chain creates an external timestamp that survives
  internal database failures. The SoS DB is still authoritative; the
  anchor is supplementary evidence of "this hash existed at this time."

## What this matrix does NOT settle

- **"Race to the bottom" risk.** If NH's bolder choices increase friction
  for filers, DAOs may simply file in WY. That's a policy/marketing
  question, not a tech question.
- **Long-term operational cost.** Running a DID resolver, an IPFS
  pinning service, and a chain anchor relayer is more infrastructure
  than a typical SoS office runs. The cybersecurity / open-source
  operational model in the principles doc is the proposed answer; it
  needs validation from someone who runs SoS infrastructure.
- **Whether RSA 301-B as-written is adequate.** The matrix surfaces
  what the statute *requires* vs. what the reference implementation
  *does*; reconciling those is a legislative-track activity.

## How to fill in the **(verify)** cells

For each peer state:

1. Pull the current statute text (Lexis / state legislative site).
2. Pull the SoS office's filing instructions (often more revealing
   than the statute).
3. Note the year of last amendment — this space moves fast.
4. Where possible, talk to someone who has filed a DAO entity in
   that state. The gap between statute and operational practice is
   often where the real differentiators live.

Sam Nathans noted contacts in WY and UT; web3iam.eth has practitioner
exposure across the space. They are the right reviewers for the verify
cells before this matrix goes external.
