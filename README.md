# LicenseGate

Three chained [GenLayer](https://docs.genlayer.com) Intelligent Contracts that decide whether a software release may ship, based on the open-source licenses of its dependencies.

Each contract is **constructed with the address of the one before it**, so the project is deployed as a chain:

```
LicensePolicy.py      what is allowed?                     (no constructor args)
      ^
      |  constructor arg: LicensePolicy address
PackageAuditor.py     does THIS package's license comply?  (AI-judged)
      ^
      |  constructor arg: PackageAuditor address
ReleaseGate.py        may THIS release ship?               (deterministic)
```

Nothing in the chain is payable and no contract holds GEN, so a reverted call costs nothing and can simply be retried.

## Why it needs GenLayer

"Is this license acceptable under our policy?" is a judgment over unstructured text, not a lookup. A conventional contract cannot read a license page or weigh it against a plain-language policy. Here validators fetch the license text themselves, a language model reads it against the policy, and consensus is reached on the **verdict** (not on the wording of the explanation).

## The three contracts

### 1. `LicensePolicy` - the versioned rulebook

- A policy is a short piece of **plain-language rules** plus optional literal **deny markers** (for example `GNU AFFERO GENERAL PUBLIC LICENSE`).
- Every amendment creates a new **immutable version**. Old versions stay readable forever.
- **No global admin.** Whoever creates a policy is its maintainer and only they can amend, retire or hand it over. Not even the deployer can touch another person's policy.
- **Names are first come, first served and are never released**, so a name does not prove who stands behind a policy. Consumers should pin the maintainer address (see `expected_maintainer` in ReleaseGate).
- A maintainer can hold at most 10 **active** policies. Retiring a policy frees its slot but not its name. Only an active policy can be handed over.
- Key views: `get_policy_state`, `get_active_bundle`, `get_rules(name, version)`.

### 2. `PackageAuditor` - AI audits, built on LicensePolicy

- Constructor takes the LicensePolicy address and **verifies it** (`get_config()` must look like a LicensePolicy), so a pasted wrong address fails at deploy time. The address is **immutable**: no owner, no setter, no pause switch.
- `audit_package(policy_name, package_id, license_url)` does this:
  1. Reads the policy's active bundle (version, rules, deny markers).
  2. Each validator independently fetches the license text from the `https://` URL.
  3. **Deterministic rule first:** if the **head** of the text (first 3000 characters, where a license names itself) contains a deny marker, the verdict is `DENIED` and the model is never called. A phrase that only appears deeper in a text, such as GPLv3 section 13 mentioning the Affero license, does not trigger a marker. Choose distinctive phrases, ideally the license title.
  4. Otherwise the model returns `ALLOWED`, `REVIEW` or `DENIED`. Two hard guards run afterwards: an `ALLOWED` with confidence below 65, or for a license the model could not identify, is **downgraded to `REVIEW`**. The pipeline can never auto-clear something it was unsure about.
  5. Validators re-run the same judgement and must land on the same **verdict and source** (`MARKER` or `MODEL`), so a leader cannot fake or hide a marker hit. They do not merely check that the leader's JSON is well-formed. The `confidence`, `license_id` and `reasoning` stored with an audit are reported by the leader and are **advisory**: they are shape-checked but not independently verified.
- License pages are treated as **untrusted data** in the prompt. Angle brackets are stripped from the page text before it is placed between the `<license_text>` delimiters, so a page cannot close the delimiter and append instructions of its own.
- Every audit remembers **which policy version** it was made under. When the policy is amended the audit becomes `STALE`.
- **Humans stay in the loop** through the policy's maintainer (read live from LicensePolicy, never copied):
  - `resolve_review(audit_id, approve, note)` decides an audit that came out as `REVIEW`.
  - `revoke_audit(audit_id, note)` voids the latest audit, for example when the URL turned out not to belong to the package.
  - **A human "no" sticks.** After a reject or a revoke, that package is **locked to the maintainer** for the current policy version: only the maintainer can audit it again, until the policy is amended. Otherwise anyone could resubmit the package with a different URL and overwrite the decision, because the latest audit always wins. `get_package_status` shows `maintainer_locked`.
- `evaluate_packages(policy_name, packages_csv)` returns the **standing** of a whole manifest in one call. This is what ReleaseGate is built on.

**Standing** of a package, computed live against the policy's *current* state:

| Standing | Meaning |
|---|---|
| `CLEARED` | Audited under the current policy version and effectively ALLOWED |
| `REVIEW_PENDING` | Model was unsure; waiting for the maintainer |
| `DENIED` | Denied by marker, by the model, or by the maintainer |
| `STALE` | Audited under an older policy version |
| `REVOKED` | The maintainer voided the audit |
| `UNAUDITED` | No audit exists yet |
| `POLICY_RETIRED` / `POLICY_MISSING` | The policy cannot be used |

### 3. `ReleaseGate` - the release decision, built on PackageAuditor

- Constructor takes the PackageAuditor address and verifies it. It never talks to LicensePolicy: the policy is just a name it forwards.
- `propose_release(project, version_tag, policy_name, packages_csv, expected_maintainer)` creates a `DRAFT`. The manifest is a pipe-separated list such as `requests@2.31.0|express@4.18.2`. `expected_maintainer` is optional: when given it must match the policy's maintainer now, publishing is refused if the maintainer later changes, and `get_release_health` reports such a change as drift. The reply always shows who maintains the policy.
- `preview_gate(release_id)` is a dry run of publishing and names every blocker.
- `publish_release(release_id)` succeeds only if **every package is `CLEARED` right now**. It then freezes a **bill of materials**: the policy version plus the id of the audit that cleared each package. A blocked attempt returns the list of blockers instead of failing.
- `get_release_health(release_id)` is the part that outlives publishing. It re-evaluates a published release against today's policy and returns `HEALTHY` or `DRIFTED`, so a release that *was* compliant when it shipped can be told apart from one that still is. Drift never rewrites the release record.
- Only the proposer can amend, publish or withdraw their release. No owner, no admin.

## Project layout

```
contracts/
  LicensePolicy.py
  PackageAuditor.py
  ReleaseGate.py
test/
  genlayer_stub.py             dependency-free stand-in for the GenVM SDK
  helpers.py                   wires the three REAL contracts together
  test_license_policy.py
  test_package_auditor.py
  test_release_gate.py
  test_chain_integration.py    full end-to-end scenario
README.md
```

## Deploy on Studionet

Studionet is the hosted development network, so nothing needs to be installed.

1. Open <https://studio.genlayer.com> and make sure the network is **Studionet**.
2. Load the three files from `contracts/` into the editor.
3. **Deploy `LicensePolicy.py`.** It has no constructor arguments. Wait until the transaction is **ACCEPTED** and copy the contract address. Call it `POLICY_ADDR`.
4. **Deploy `PackageAuditor.py`** with constructor argument `policy_address = POLICY_ADDR`. Wait for ACCEPTED and copy its address: `AUDITOR_ADDR`.
5. **Deploy `ReleaseGate.py`** with constructor argument `auditor_address = AUDITOR_ADDR`.

If a deployment fails with `no LicensePolicy answered at ...` or `no PackageAuditor answered at ...`, the previous contract was not ACCEPTED yet or the address was copied wrongly. Wait and retry. If it says `is not a LicensePolicy` or `is not a PackageAuditor`, the addresses are in the wrong order.

### Or with the CLI

```bash
npm install -g genlayer
genlayer network set studionet
genlayer deploy --contract contracts/LicensePolicy.py
genlayer deploy --contract contracts/PackageAuditor.py --args <POLICY_ADDR>
genlayer deploy --contract contracts/ReleaseGate.py    --args <AUDITOR_ADDR>
```

## Try it (copy-paste walkthrough)

Use one wallet as the policy maintainer and, if you like, a second one as the proposer.

**1. Create a policy** (`LicensePolicy.create_policy`)

| Argument | Value |
|---|---|
| `name` | `acme-oss` |
| `title` | `Acme open-source policy` |
| `rules` | `Permissive licenses such as MIT, BSD and Apache-2.0 are accepted. Strong copyleft such as GPL is forbidden. Weak copyleft such as MPL or LGPL needs a human decision.` |
| `deny_markers` | `GNU AFFERO GENERAL PUBLIC LICENSE\|Server Side Public License` |

**2. Audit some packages** (`PackageAuditor.audit_package`, policy `acme-oss`)

| `package_id` | `license_url` | Expected |
|---|---|---|
| `express@4.18.2` | `https://raw.githubusercontent.com/expressjs/express/master/LICENSE` | `ALLOWED` (MIT) |
| `requests@2.31.0` | `https://raw.githubusercontent.com/psf/requests/main/LICENSE` | `ALLOWED` (Apache-2.0) |
| `rhino@1.7.14` | `https://raw.githubusercontent.com/mozilla/rhino/master/LICENSE.txt` | `REVIEW` (MPL-2.0) |
| `grafana@10.0.0` | `https://raw.githubusercontent.com/grafana/grafana/main/LICENSE` | `DENIED` by deny marker, no model call |
| `kernel@6.1.0` | `https://raw.githubusercontent.com/torvalds/linux/master/COPYING` | `DENIED` (GPL-2.0) |

The verdicts for the model-judged rows come from a real language model, so borderline cases such as the last two can vary. Deny-marker outcomes are fully deterministic.

**3. Propose and try to publish** (`ReleaseGate`)

1. `propose_release("webshop", "1.0.0", "acme-oss", "express@4.18.2|requests@2.31.0|rhino@1.7.14", "<MAINTAINER_ADDRESS>")` (the last argument is optional)
2. `publish_release(1)` returns `ok: false` and names `rhino@1.7.14` as the blocker.
3. As the maintainer, call `PackageAuditor.get_pending_reviews("acme-oss")`, then `resolve_review(<audit_id>, true, "legal approved")`.
4. `publish_release(1)` now succeeds and returns the frozen bill of materials.

**4. Watch a release drift**

1. As the maintainer, call `LicensePolicy.amend_policy("acme-oss", "<stricter rules>", "<markers>", "tightened")`.
2. `ReleaseGate.get_release_health(1)` now returns `DRIFTED` with every package `STALE`.
3. Re-audit the packages under version 2 and the health recovers. `re_audited` shows which clearing audits were replaced.

## Tests

```bash
python3 -m unittest discover -s test -v
```

The tests import the **real** contract files and run them against a small stand-in for the SDK (`test/genlayer_stub.py`). The three real contracts are wired together through their real typed interfaces, so the chain behaviour is exercised end to end, and the stub runs each contract's real validator function against the leader's result.

The stub is not GenVM. It does not model consensus, appeals or fees. Contract validity against the real SDK is checked separately with the official linter:

```bash
pip install genvm-linter
genvm-lint check contracts/LicensePolicy.py
genvm-lint check contracts/PackageAuditor.py
genvm-lint check contracts/ReleaseGate.py
```

## Trust model and limits

- **URL provenance is not verified.** An audit certifies what the license text at the submitted URL says about the policy. It cannot prove that the URL belongs to the package. The submitter and URL are stored on every audit so the maintainer can check and revoke. Until a human has revoked or rejected a package, anyone can replace its latest audit by auditing it again with a different URL.
- **Use raw license URLs** (for example `raw.githubusercontent.com/...`), not HTML pages. Only the first 6000 characters of the text reach the model, and deny markers are matched against the first 3000.
- **Model verdicts can differ between validators** on borderline licenses. When they do, consensus fails and a new leader is tried, which is the intended safe behavior. Clear-cut licenses and deny markers are stable.
- **Policy rules are prose.** They are read by a language model, so write them plainly and put the clearest prohibitions in deny markers where an exact phrase exists.
- Limits are deliberately small: 20 packages per manifest, 10 active policies per maintainer, 10 open drafts per proposer, 50 versions per policy.
- This is an engineering aid, not legal advice.
