# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
from datetime import datetime, timezone
import json

# ============================================================================
# LicensePolicy -- link 1 of 3: the versioned rulebook everything else reads
# ============================================================================
#
# This is the CORE contract of the LicenseGate chain. It is deployed first,
# takes no constructor arguments, and never calls another contract. Two more
# contracts are then built on top of it, each one constructed with the
# on-chain address of the contract before it:
#
#     LicensePolicy   (this file)     what is allowed?
#          ^
#          |  constructor arg: LicensePolicy's address
#     PackageAuditor.py               does THIS package's license comply?
#          ^
#          |  constructor arg: PackageAuditor's address
#     ReleaseGate.py                  may THIS release ship?
#
# A policy is a short, plain-language statement of which open-source licenses
# an organisation accepts ("permissive is fine, GPL is not, MPL needs a human
# look"). It is deliberately written for people, not parsed by code: the AI
# validators in PackageAuditor read it verbatim. Two objective anchors sit
# next to the prose so that the clearest cases never depend on a language
# model at all:
#
#   * deny markers -- literal phrases (for example "GNU AFFERO GENERAL PUBLIC
#     LICENSE"). If a fetched license text contains one, PackageAuditor
#     records DENIED deterministically, with no LLM call.
#   * versions -- every amendment creates a new immutable version. Audits
#     remember which version they were made under, and become STALE the moment
#     the policy moves on. Old versions stay readable forever.
#
# Governance is per policy and there is NO global admin: whoever creates a
# policy is its maintainer, and only the maintainer can amend, retire, or hand
# it over. Nobody can touch anybody else's policy, including the deployer.
#
# Names are first come, first served and are never released: a retired policy
# keeps its name. A name therefore proves nothing about WHO stands behind a
# policy. Consumers that care should pin the maintainer address (ReleaseGate's
# propose_release takes an expected_maintainer for exactly this reason).
# A maintainer can hold at most MAX_POLICIES_PER_MAINTAINER ACTIVE policies;
# retiring a policy frees its slot.
#
# Nothing in this contract touches GEN and nothing is payable, so a reverted
# call costs nothing and can simply be retried.
# ============================================================================

STATUS_ACTIVE = "ACTIVE"
STATUS_RETIRED = "RETIRED"

MIN_NAME_LEN = 2
MAX_NAME_LEN = 32
MAX_TITLE_LEN = 80
MIN_RULES_LEN = 40
MAX_RULES_LEN = 1500
MAX_NOTE_LEN = 200
MAX_MARKERS = 8
MIN_MARKER_LEN = 4
MAX_MARKER_LEN = 60
MAX_VERSIONS_PER_POLICY = 50
MAX_POLICIES_PER_MAINTAINER = 10

MAX_PAGE = 40
MAX_SCAN = 200


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _clamp(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _slug(raw) -> str:
    """Canonical policy name: 2..32 chars of a-z, 0-9 and '-', not starting
    or ending with '-'. Returns "" when the input is not a valid name."""
    s = str(raw).strip().lower()
    if len(s) < MIN_NAME_LEN or len(s) > MAX_NAME_LEN:
        return ""
    for ch in s:
        if not (ch.isascii() and (ch.isalnum() or ch == "-")):
            return ""
    if s.startswith("-") or s.endswith("-"):
        return ""
    return s


def _split_markers(csv: str) -> list:
    parts = [p.strip() for p in str(csv).split("|")]
    return [p for p in parts if len(p) > 0]


def _vkey(name: str, version: int) -> str:
    return str(name) + "@" + str(int(version))


def _parse_address(raw) -> Address:
    try:
        return Address(str(raw))
    except Exception:
        raise gl.vm.UserError("not a valid address: " + str(raw)[:60])


@allow_storage
@dataclass
class Policy:
    name: str
    title: str
    maintainer: Address
    status: str
    current_version: u32
    created_epoch: u64
    updated_epoch: u64


@allow_storage
@dataclass
class PolicyVersion:
    version: u32
    rules: str
    deny_markers_csv: str
    note: str
    published_by: Address
    published_epoch: u64


class LicensePolicy(gl.Contract):
    policies: TreeMap[str, Policy]
    versions: TreeMap[str, PolicyVersion]
    policy_names: DynArray[str]
    maintainer_counts: TreeMap[Address, u32]

    count_policies: u32
    count_retired: u32
    count_versions: u32

    def __init__(self):
        self.count_policies = u32(0)
        self.count_retired = u32(0)
        self.count_versions = u32(0)

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _get_policy(self, name: str) -> Policy:
        p = self.policies.get(_slug(name))
        if p is None:
            raise gl.vm.UserError("unknown policy")
        return p

    def _require_maintainer(self, p: Policy) -> None:
        if str(gl.message.sender_address).lower() != str(p.maintainer).lower():
            raise gl.vm.UserError("only the policy maintainer can do this")

    def _clean_rules(self, rules: str) -> str:
        text = str(rules).strip()
        if len(text) < MIN_RULES_LEN or len(text) > MAX_RULES_LEN:
            raise gl.vm.UserError("rules must be " + str(MIN_RULES_LEN) + ".."
                + str(MAX_RULES_LEN) + " characters")
        return text

    def _clean_markers(self, raw: str) -> list:
        parts = _split_markers(raw)
        if len(parts) > MAX_MARKERS:
            raise gl.vm.UserError("at most " + str(MAX_MARKERS) + " deny markers are allowed")
        seen = []
        for m in parts:
            if len(m) < MIN_MARKER_LEN or len(m) > MAX_MARKER_LEN:
                raise gl.vm.UserError("each deny marker must be " + str(MIN_MARKER_LEN) + ".."
                    + str(MAX_MARKER_LEN) + " characters")
            low = m.lower()
            if low in seen:
                raise gl.vm.UserError("deny markers must be unique (case-insensitive): " + m)
            seen.append(low)
        return parts

    def _store_version(self, name: str, version: int, rules: str, markers: list,
            note: str, sender, now: int) -> None:
        v = self.versions.get_or_insert_default(_vkey(name, version))
        v.version = u32(version)
        v.rules = rules
        v.deny_markers_csv = "|".join(markers)
        v.note = note
        v.published_by = sender
        v.published_epoch = u64(now)
        self.count_versions = u32(int(self.count_versions) + 1)

    def _policy_json(self, p: Policy) -> dict:
        return {"name": str(p.name), "title": str(p.title), "maintainer": str(p.maintainer),
            "status": str(p.status), "current_version": int(p.current_version),
            "created_epoch": int(p.created_epoch), "updated_epoch": int(p.updated_epoch)}

    # ------------------------------------------------------------------ #
    # policy lifecycle -- every method is maintainer-scoped, no global admin
    # ------------------------------------------------------------------ #

    @gl.public.write
    def create_policy(self, name: str, title: str, rules: str, deny_markers: str = "") -> str:
        sender = gl.message.sender_address
        slug = _slug(name)
        if slug == "":
            raise gl.vm.UserError("name must be " + str(MIN_NAME_LEN) + ".." + str(MAX_NAME_LEN)
                + " characters of a-z, 0-9 and '-' (not starting or ending with '-')")
        if self.policies.get(slug) is not None:
            raise gl.vm.UserError("a policy named '" + slug + "' already exists")

        t = str(title).strip()
        if len(t) == 0 or len(t) > MAX_TITLE_LEN:
            raise gl.vm.UserError("title must be 1.." + str(MAX_TITLE_LEN) + " characters")

        owned = self.maintainer_counts.get(sender)
        if owned is not None and int(owned) >= MAX_POLICIES_PER_MAINTAINER:
            raise gl.vm.UserError("a maintainer can hold at most "
                + str(MAX_POLICIES_PER_MAINTAINER) + " active policies; retire one first")

        text = self._clean_rules(rules)
        markers = self._clean_markers(deny_markers)
        now = _now_epoch()

        p = self.policies.get_or_insert_default(slug)
        p.name = slug
        p.title = t
        p.maintainer = sender
        p.status = STATUS_ACTIVE
        p.current_version = u32(1)
        p.created_epoch = u64(now)
        p.updated_epoch = u64(now)
        self._store_version(slug, 1, text, markers, "initial version", sender, now)

        self.policy_names.append(slug)
        self.maintainer_counts[sender] = u32((int(owned) if owned is not None else 0) + 1)
        self.count_policies = u32(int(self.count_policies) + 1)
        return json.dumps({"ok": True, "name": slug, "version": 1, "status": STATUS_ACTIVE,
            "deny_markers": markers})

    @gl.public.write
    def amend_policy(self, name: str, rules: str, deny_markers: str = "", note: str = "") -> str:
        """Publishes a NEW immutable version and makes it current. Every audit
        made under an older version becomes STALE downstream."""
        sender = gl.message.sender_address
        p = self._get_policy(name)
        self._require_maintainer(p)
        if str(p.status) != STATUS_ACTIVE:
            raise gl.vm.UserError("policy is " + str(p.status) + ", not ACTIVE")

        cur = int(p.current_version)
        if cur >= MAX_VERSIONS_PER_POLICY:
            raise gl.vm.UserError("policy reached the limit of " + str(MAX_VERSIONS_PER_POLICY)
                + " versions")

        text = self._clean_rules(rules)
        markers = self._clean_markers(deny_markers)
        n = str(note).strip()
        if len(n) > MAX_NOTE_LEN:
            n = n[:MAX_NOTE_LEN]

        previous = self.versions.get(_vkey(str(p.name), cur))
        if previous is not None and str(previous.rules) == text \
                and str(previous.deny_markers_csv) == "|".join(markers):
            raise gl.vm.UserError("amendment is identical to the current version")

        now = _now_epoch()
        new_version = cur + 1
        self._store_version(str(p.name), new_version, text, markers, n, sender, now)
        p.current_version = u32(new_version)
        p.updated_epoch = u64(now)
        return json.dumps({"ok": True, "name": str(p.name), "version": new_version,
            "previous_version": cur})

    @gl.public.write
    def retire_policy(self, name: str) -> str:
        """Final. A retired policy accepts no new audits and blocks every
        release that still depends on it."""
        p = self._get_policy(name)
        self._require_maintainer(p)
        if str(p.status) != STATUS_ACTIVE:
            raise gl.vm.UserError("policy is already " + str(p.status))
        p.status = STATUS_RETIRED
        p.updated_epoch = u64(_now_epoch())
        held = self.maintainer_counts.get(p.maintainer)
        self.maintainer_counts[p.maintainer] = u32(max(0, (int(held) if held is not None else 1) - 1))
        self.count_retired = u32(int(self.count_retired) + 1)
        return json.dumps({"ok": True, "name": str(p.name), "status": STATUS_RETIRED})

    @gl.public.write
    def transfer_maintainer(self, name: str, new_maintainer: str) -> str:
        p = self._get_policy(name)
        self._require_maintainer(p)
        if str(p.status) != STATUS_ACTIVE:
            raise gl.vm.UserError("policy is " + str(p.status) + ", only an ACTIVE policy can be handed over")
        target = _parse_address(new_maintainer)
        if str(target).lower() == str(p.maintainer).lower():
            raise gl.vm.UserError("that address is already the maintainer")

        theirs = self.maintainer_counts.get(target)
        their_count = int(theirs) if theirs is not None else 0
        if their_count >= MAX_POLICIES_PER_MAINTAINER:
            raise gl.vm.UserError("the new maintainer already holds the maximum number of policies")

        mine = self.maintainer_counts.get(p.maintainer)
        my_count = int(mine) if mine is not None else 1
        self.maintainer_counts[p.maintainer] = u32(max(0, my_count - 1))
        self.maintainer_counts[target] = u32(their_count + 1)
        p.maintainer = target
        p.updated_epoch = u64(_now_epoch())
        return json.dumps({"ok": True, "name": str(p.name), "maintainer": str(target)})

    # ------------------------------------------------------------------ #
    # views -- this is the surface PackageAuditor.py is built against
    # ------------------------------------------------------------------ #

    @gl.public.view
    def get_policy_state(self, name: str) -> str:
        """The compact, cheap answer downstream contracts ask for on every
        call: does the policy exist, is it active, which version is current,
        and who is allowed to grant exceptions under it."""
        p = self.policies.get(_slug(name))
        if p is None:
            return json.dumps({"found": False})
        return json.dumps({"found": True, "name": str(p.name), "status": str(p.status),
            "version": int(p.current_version), "maintainer": str(p.maintainer)})

    @gl.public.view
    def get_active_bundle(self, name: str) -> str:
        """Everything PackageAuditor needs to run one audit: current version,
        the prose rules, and the pipe-separated deny markers."""
        p = self.policies.get(_slug(name))
        if p is None:
            return json.dumps({"found": False})
        pv = self.versions.get(_vkey(str(p.name), int(p.current_version)))
        if pv is None:
            return json.dumps({"found": False})
        return json.dumps({"found": True, "name": str(p.name), "status": str(p.status),
            "version": int(p.current_version), "rules": str(pv.rules),
            "deny_markers": str(pv.deny_markers_csv), "maintainer": str(p.maintainer)})

    @gl.public.view
    def get_policy(self, name: str) -> str:
        p = self.policies.get(_slug(name))
        if p is None:
            return json.dumps({"found": False})
        out = self._policy_json(p)
        out["found"] = True
        return json.dumps(out)

    @gl.public.view
    def get_rules(self, name: str, version: int = 0) -> str:
        """Any historical version stays readable. version 0 means current."""
        p = self.policies.get(_slug(name))
        if p is None:
            return json.dumps({"found": False})
        v = int(version)
        if v <= 0:
            v = int(p.current_version)
        pv = self.versions.get(_vkey(str(p.name), v))
        if pv is None:
            return json.dumps({"found": False})
        return json.dumps({"found": True, "name": str(p.name), "version": v,
            "is_current": v == int(p.current_version), "rules": str(pv.rules),
            "deny_markers": _split_markers(str(pv.deny_markers_csv)), "note": str(pv.note),
            "published_by": str(pv.published_by), "published_epoch": int(pv.published_epoch)})

    @gl.public.view
    def list_policies(self, offset: int = 0, limit: int = MAX_PAGE) -> str:
        total = len(self.policy_names)
        off = max(0, int(offset))
        lim = _clamp(int(limit), 1, MAX_PAGE)
        out = []
        i = off
        while i < total and len(out) < lim:
            p = self.policies.get(str(self.policy_names[i]))
            if p is not None:
                out.append(self._policy_json(p))
            i += 1
        return json.dumps({"total": total, "policies": out})

    @gl.public.view
    def get_policies_by_maintainer(self, maintainer: str, offset: int = 0, limit: int = MAX_PAGE) -> str:
        who = str(maintainer).lower()
        total = len(self.policy_names)
        off = max(0, int(offset))
        lim = _clamp(int(limit), 1, MAX_PAGE)
        out = []
        i = off
        scanned = 0
        while i < total and len(out) < lim and scanned < MAX_SCAN:
            p = self.policies.get(str(self.policy_names[i]))
            if p is not None and str(p.maintainer).lower() == who:
                out.append(self._policy_json(p))
            i += 1
            scanned += 1
        return json.dumps({"maintainer": str(maintainer), "next_offset": i, "policies": out})

    @gl.public.view
    def get_platform_stats(self) -> str:
        return json.dumps({"policies": int(self.count_policies), "retired": int(self.count_retired),
            "versions": int(self.count_versions)})

    @gl.public.view
    def get_config(self) -> str:
        return json.dumps({"max_policies_per_maintainer": MAX_POLICIES_PER_MAINTAINER,
            "max_versions_per_policy": MAX_VERSIONS_PER_POLICY, "max_markers": MAX_MARKERS,
            "min_rules_len": MIN_RULES_LEN, "max_rules_len": MAX_RULES_LEN,
            "policies": int(self.count_policies)})
