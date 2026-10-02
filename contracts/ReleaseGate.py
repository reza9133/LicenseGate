# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
from datetime import datetime, timezone
import json

# ============================================================================
# ReleaseGate -- link 3 of 3: turns package audits into a release decision
# ============================================================================
#
#     LicensePolicy.py                what is allowed?
#          ^
#          |
#     PackageAuditor.py               does THIS package's license comply?
#          ^
#          |  constructor arg: PackageAuditor's address   <-- you are here
#     ReleaseGate.py     (this file)  may THIS release ship?
#
# ReleaseGate only ever talks to PackageAuditor and contains no AI of its own.
# It never sees LicensePolicy directly: the policy is just a name it forwards.
# Everything it knows about compliance comes from ONE view call,
# PackageAuditor.evaluate_packages(), which reports a "standing" for every
# package of a manifest against the policy's CURRENT version.
#
# A release goes through three states:
#
#     DRAFT --publish--> PUBLISHED --withdraw--> WITHDRAWN
#       |                                             ^
#       +---------------withdraw----------------------+
#
#   * propose_release   records project, version tag, policy and the manifest
#                       (pipe-separated package ids such as "requests@2.31.0").
#   * publish_release   re-checks the manifest LIVE and succeeds only if every
#                       package is CLEARED right now. It then freezes a bill of
#                       materials: the policy version plus the id of the audit
#                       that cleared each package.
#   * get_release_health  is the part that outlives publishing. It re-evaluates
#                       a published release against today's policy and reports
#                       HEALTHY or DRIFTED, so a release that was compliant when
#                       it shipped can be told apart from one that still is.
#
# Policy names are first come, first served, so a name alone does not say who
# stands behind a policy. propose_release therefore accepts an optional
# expected_maintainer. When given, it must match the policy's maintainer now,
# and publishing is refused if the maintainer later changes. The release
# health view reports such a change as drift.
#
# Governance is per release: only the proposer can amend, publish or withdraw
# their own release. There is no owner, no admin and no pause switch, and the
# auditor address is immutable after deployment. Nothing here touches GEN and
# nothing is payable, so a reverted call costs nothing and can be retried.
# ============================================================================

STATUS_DRAFT = "DRAFT"
STATUS_PUBLISHED = "PUBLISHED"
STATUS_WITHDRAWN = "WITHDRAWN"

HEALTH_HEALTHY = "HEALTHY"
HEALTH_DRIFTED = "DRIFTED"
HEALTH_NOT_PUBLISHED = "NOT_PUBLISHED"

STANDING_CLEARED = "CLEARED"

MIN_NAME_LEN = 2
MAX_PROJECT_LEN = 40
MAX_TAG_LEN = 32
MAX_POLICY_LEN = 32
MIN_PACKAGE_LEN = 2
MAX_PACKAGE_LEN = 80
MAX_PACKAGES = 20
MAX_NOTE_LEN = 200
MAX_OPEN_DRAFTS_PER_PROPOSER = 10

MAX_PAGE = 40
MAX_SCAN = 200

NAME_EXTRA_CHARS = "._-"
TAG_EXTRA_CHARS = "._-+"
PACKAGE_EXTRA_CHARS = "._@/+-"


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _clamp(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _canon(raw, lo: int, hi: int, extra: str) -> str:
    s = str(raw).strip().lower()
    if len(s) < lo or len(s) > hi:
        return ""
    for ch in s:
        if not (ch.isascii() and (ch.isalnum() or ch in extra)):
            return ""
    return s


def _canon_manifest(raw) -> list:
    """Sorted, de-duplicated list of canonical package ids. Raises on any
    invalid entry so a typo never silently drops a dependency."""
    items = [p for p in str(raw).split("|") if len(p.strip()) > 0]
    if len(items) == 0:
        raise gl.vm.UserError("the manifest is empty")
    if len(items) > MAX_PACKAGES:
        raise gl.vm.UserError("a manifest can list at most " + str(MAX_PACKAGES) + " packages")
    out = []
    for p in items:
        c = _canon(p, MIN_PACKAGE_LEN, MAX_PACKAGE_LEN, PACKAGE_EXTRA_CHARS)
        if c == "":
            raise gl.vm.UserError("invalid package id: " + str(p).strip()[:60])
        if c in out:
            raise gl.vm.UserError("duplicate package in manifest: " + c)
        out.append(c)
    out.sort()
    return out


def _tag_key(project: str, tag: str) -> str:
    return str(project) + "|" + str(tag)


def _err_message(e) -> str:
    m = getattr(e, "message", None)
    return str(m) if m is not None else str(e)


@gl.contract_interface
class _PackageAuditor:
    class View:
        def evaluate_packages(self, policy_name: str, packages_csv: str) -> str: ...
        def get_config(self) -> str: ...

    class Write:
        pass


@allow_storage
@dataclass
class Release:
    release_id: u32
    project: str
    version_tag: str
    policy_name: str
    packages_csv: str
    proposer: Address
    status: str
    proposed_epoch: u64
    updated_epoch: u64
    published_epoch: u64
    frozen_policy_version: u32
    frozen_bom_json: str
    withdraw_note: str
    pinned_maintainer: str


class ReleaseGate(gl.Contract):
    auditor_address: Address

    releases: TreeMap[str, Release]
    release_by_tag: TreeMap[str, u32]
    open_drafts: TreeMap[Address, u32]

    count_releases: u32
    count_published: u32
    count_withdrawn: u32
    count_blocked_attempts: u32

    def __init__(self, auditor_address: str):
        try:
            target = Address(str(auditor_address).strip())
        except Exception:
            raise gl.vm.UserError("auditor_address is not a valid address")
        if str(target).lower() == "0x" + "0" * 40:
            raise gl.vm.UserError("auditor_address must not be the zero address")

        try:
            raw = _PackageAuditor(target).view().get_config()
            probe = json.loads(str(raw))
        except Exception:
            raise gl.vm.UserError("no PackageAuditor answered at " + str(target)
                + " (is the deployment transaction ACCEPTED yet?)")
        if not isinstance(probe, dict) or "policy_address" not in probe:
            raise gl.vm.UserError("the contract at " + str(target) + " is not a PackageAuditor")

        self.auditor_address = target
        self.count_releases = u32(0)
        self.count_published = u32(0)
        self.count_withdrawn = u32(0)
        self.count_blocked_attempts = u32(0)

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #

    def _evaluate(self, policy_name: str, packages_csv: str) -> dict:
        try:
            raw = _PackageAuditor(self.auditor_address).view().evaluate_packages(policy_name, packages_csv)
            data = json.loads(str(raw))
        except gl.vm.UserError as e:
            raise gl.vm.UserError("PackageAuditor refused the evaluation: " + _err_message(e))
        except Exception:
            raise gl.vm.UserError("could not read PackageAuditor at " + str(self.auditor_address))
        if not isinstance(data, dict) or "packages" not in data:
            raise gl.vm.UserError("PackageAuditor returned an unexpected answer")
        return data

    def _get_release(self, release_id: int) -> Release:
        r = self.releases.get(str(int(release_id)))
        if r is None:
            raise gl.vm.UserError("unknown release")
        return r

    def _require_proposer(self, r: Release) -> None:
        if str(gl.message.sender_address).lower() != str(r.proposer).lower():
            raise gl.vm.UserError("only the proposer of this release can do this")

    def _release_json(self, r: Release) -> dict:
        bom = []
        if len(str(r.frozen_bom_json)) > 0:
            try:
                bom = json.loads(str(r.frozen_bom_json))
            except Exception:
                bom = []
        return {"release_id": int(r.release_id), "project": str(r.project),
            "version_tag": str(r.version_tag), "policy_name": str(r.policy_name),
            "packages": [p for p in str(r.packages_csv).split("|") if len(p) > 0],
            "proposer": str(r.proposer), "status": str(r.status),
            "proposed_epoch": int(r.proposed_epoch), "updated_epoch": int(r.updated_epoch),
            "published_epoch": int(r.published_epoch),
            "frozen_policy_version": int(r.frozen_policy_version), "bom": bom,
            "withdraw_note": str(r.withdraw_note),
            "pinned_maintainer": str(r.pinned_maintainer)}

    def _release_draft_slot(self, who: Address, delta: int) -> None:
        cur = self.open_drafts.get(who)
        n = int(cur) if cur is not None else 0
        self.open_drafts[who] = u32(max(0, n + delta))

    # ------------------------------------------------------------------ #
    # release lifecycle -- every method is proposer-scoped
    # ------------------------------------------------------------------ #

    @gl.public.write
    def propose_release(self, project: str, version_tag: str, policy_name: str, packages_csv: str,
            expected_maintainer: str = "") -> str:
        sender = gl.message.sender_address
        proj = _canon(project, MIN_NAME_LEN, MAX_PROJECT_LEN, NAME_EXTRA_CHARS)
        if proj == "":
            raise gl.vm.UserError("project must be " + str(MIN_NAME_LEN) + ".." + str(MAX_PROJECT_LEN)
                + " characters of a-z, 0-9 and . _ -")
        tag = _canon(version_tag, 1, MAX_TAG_LEN, TAG_EXTRA_CHARS)
        if tag == "":
            raise gl.vm.UserError("version_tag must be 1.." + str(MAX_TAG_LEN)
                + " characters of a-z, 0-9 and . _ - +")
        pol = _canon(policy_name, MIN_NAME_LEN, MAX_POLICY_LEN, "-")
        if pol == "":
            raise gl.vm.UserError("invalid policy_name")
        manifest = _canon_manifest(packages_csv)

        key = _tag_key(proj, tag)
        existing_id = self.release_by_tag.get(key)
        if existing_id is not None:
            existing = self.releases.get(str(int(existing_id)))
            if existing is not None and str(existing.status) != STATUS_WITHDRAWN:
                raise gl.vm.UserError("release " + proj + " " + tag + " already exists as #"
                    + str(int(existing_id)) + " (" + str(existing.status) + ")")

        drafts = self.open_drafts.get(sender)
        if drafts is not None and int(drafts) >= MAX_OPEN_DRAFTS_PER_PROPOSER:
            raise gl.vm.UserError("at most " + str(MAX_OPEN_DRAFTS_PER_PROPOSER)
                + " open drafts per proposer; publish or withdraw one first")

        csv = "|".join(manifest)
        ev = self._evaluate(pol, csv)
        if not ev.get("policy_found"):
            raise gl.vm.UserError("policy '" + pol + "' does not exist")

        pinned = ""
        if len(str(expected_maintainer).strip()) > 0:
            try:
                pinned = str(Address(str(expected_maintainer).strip())).lower()
            except Exception:
                raise gl.vm.UserError("expected_maintainer is not a valid address")
            if str(ev.get("policy_maintainer", "")).lower() != pinned:
                raise gl.vm.UserError("policy '" + pol + "' is maintained by "
                    + str(ev.get("policy_maintainer", "")) + ", not by the expected maintainer")

        self.count_releases = u32(int(self.count_releases) + 1)
        rid = int(self.count_releases)
        now = _now_epoch()
        r = self.releases.get_or_insert_default(str(rid))
        r.release_id = u32(rid)
        r.project = proj
        r.version_tag = tag
        r.policy_name = pol
        r.packages_csv = csv
        r.proposer = sender
        r.status = STATUS_DRAFT
        r.proposed_epoch = u64(now)
        r.updated_epoch = u64(now)
        r.pinned_maintainer = pinned
        self.release_by_tag[key] = u32(rid)
        self._release_draft_slot(sender, 1)
        return json.dumps({"ok": True, "release_id": rid, "project": proj, "version_tag": tag,
            "policy_name": pol, "policy_maintainer": str(ev.get("policy_maintainer", "")),
            "pinned_maintainer": pinned, "packages": manifest, "status": STATUS_DRAFT,
            "cleared_now": int(ev.get("cleared", 0)), "total": len(manifest),
            "blockers": ev.get("blockers", [])})

    @gl.public.write
    def amend_manifest(self, release_id: int, packages_csv: str) -> str:
        r = self._get_release(release_id)
        self._require_proposer(r)
        if str(r.status) != STATUS_DRAFT:
            raise gl.vm.UserError("only a DRAFT release can be amended")
        manifest = _canon_manifest(packages_csv)
        csv = "|".join(manifest)
        if csv == str(r.packages_csv):
            raise gl.vm.UserError("the manifest is unchanged")
        ev = self._evaluate(str(r.policy_name), csv)
        r.packages_csv = csv
        r.updated_epoch = u64(_now_epoch())
        return json.dumps({"ok": True, "release_id": int(r.release_id), "packages": manifest,
            "cleared_now": int(ev.get("cleared", 0)), "total": len(manifest),
            "blockers": ev.get("blockers", [])})

    @gl.public.write
    def publish_release(self, release_id: int) -> str:
        """Succeeds only if every package is CLEARED right now. A blocked
        attempt is reported in the return value, not raised, so the caller
        sees exactly which packages stand in the way."""
        r = self._get_release(release_id)
        self._require_proposer(r)
        if str(r.status) != STATUS_DRAFT:
            raise gl.vm.UserError("release is " + str(r.status) + ", not DRAFT")

        ev = self._evaluate(str(r.policy_name), str(r.packages_csv))
        if str(r.pinned_maintainer) != "" \
                and str(ev.get("policy_maintainer", "")).lower() != str(r.pinned_maintainer):
            raise gl.vm.UserError("the maintainer of policy '" + str(r.policy_name)
                + "' is no longer the one pinned at proposal time")
        if not ev.get("all_cleared"):
            self.count_blocked_attempts = u32(int(self.count_blocked_attempts) + 1)
            return json.dumps({"ok": False, "release_id": int(r.release_id), "status": STATUS_DRAFT,
                "policy_status": str(ev.get("policy_status", "")),
                "policy_version": int(ev.get("policy_version", 0)),
                "cleared": int(ev.get("cleared", 0)), "total": int(ev.get("total", 0)),
                "blockers": ev.get("blockers", []), "packages": ev.get("packages", [])})

        bom = [{"package_id": str(row.get("package_id", "")), "audit_id": int(row.get("audit_id", 0))}
            for row in ev.get("packages", [])]
        now = _now_epoch()
        r.status = STATUS_PUBLISHED
        r.frozen_policy_version = u32(int(ev.get("policy_version", 0)))
        r.frozen_bom_json = json.dumps(bom)
        r.published_epoch = u64(now)
        r.updated_epoch = u64(now)
        self._release_draft_slot(r.proposer, -1)
        self.count_published = u32(int(self.count_published) + 1)
        return json.dumps({"ok": True, "release_id": int(r.release_id), "status": STATUS_PUBLISHED,
            "frozen_policy_version": int(ev.get("policy_version", 0)), "bom": bom})

    @gl.public.write
    def withdraw_release(self, release_id: int, note: str = "") -> str:
        r = self._get_release(release_id)
        self._require_proposer(r)
        if str(r.status) == STATUS_WITHDRAWN:
            raise gl.vm.UserError("release is already withdrawn")
        was_draft = str(r.status) == STATUS_DRAFT
        n = " ".join(str(note).split())
        if len(n) > MAX_NOTE_LEN:
            n = n[:MAX_NOTE_LEN]
        r.status = STATUS_WITHDRAWN
        r.withdraw_note = n
        r.updated_epoch = u64(_now_epoch())
        if was_draft:
            self._release_draft_slot(r.proposer, -1)
        self.count_withdrawn = u32(int(self.count_withdrawn) + 1)
        return json.dumps({"ok": True, "release_id": int(r.release_id), "status": STATUS_WITHDRAWN})

    # ------------------------------------------------------------------ #
    # views
    # ------------------------------------------------------------------ #

    @gl.public.view
    def get_auditor_address(self) -> str:
        return str(self.auditor_address)

    @gl.public.view
    def get_release(self, release_id: int) -> str:
        r = self.releases.get(str(int(release_id)))
        if r is None:
            return json.dumps({"found": False})
        out = self._release_json(r)
        out["found"] = True
        return json.dumps(out)

    @gl.public.view
    def get_release_by_tag(self, project: str, version_tag: str) -> str:
        proj = _canon(project, MIN_NAME_LEN, MAX_PROJECT_LEN, NAME_EXTRA_CHARS)
        tag = _canon(version_tag, 1, MAX_TAG_LEN, TAG_EXTRA_CHARS)
        rid = self.release_by_tag.get(_tag_key(proj, tag)) if proj != "" and tag != "" else None
        if rid is None:
            return json.dumps({"found": False})
        return self.get_release(int(rid))

    @gl.public.view
    def preview_gate(self, release_id: int) -> str:
        """Dry run of publish_release: the live standing of every package and
        whether publishing would succeed right now."""
        r = self._get_release(release_id)
        ev = self._evaluate(str(r.policy_name), str(r.packages_csv))
        pinned = str(r.pinned_maintainer)
        maintainer_ok = pinned == "" or str(ev.get("policy_maintainer", "")).lower() == pinned
        return json.dumps({"release_id": int(r.release_id), "status": str(r.status),
            "would_publish": str(r.status) == STATUS_DRAFT and bool(ev.get("all_cleared")) and maintainer_ok,
            "policy_maintainer": str(ev.get("policy_maintainer", "")),
            "pinned_maintainer": pinned, "maintainer_matches": maintainer_ok,
            "policy_status": str(ev.get("policy_status", "")),
            "policy_version": int(ev.get("policy_version", 0)),
            "cleared": int(ev.get("cleared", 0)), "total": int(ev.get("total", 0)),
            "blockers": ev.get("blockers", []), "packages": ev.get("packages", [])})

    @gl.public.view
    def get_release_health(self, release_id: int) -> str:
        """A published release re-evaluated against the policy as it is NOW.
        DRIFTED means at least one package is no longer CLEARED (policy
        amended, policy retired, audit revoked). re_audited lists packages
        whose clearing audit was replaced by a newer one since publishing."""
        r = self._get_release(release_id)
        if str(r.status) != STATUS_PUBLISHED:
            return json.dumps({"release_id": int(r.release_id), "health": HEALTH_NOT_PUBLISHED,
                "status": str(r.status)})

        ev = self._evaluate(str(r.policy_name), str(r.packages_csv))
        frozen = {}
        try:
            for row in json.loads(str(r.frozen_bom_json)):
                frozen[str(row.get("package_id", ""))] = int(row.get("audit_id", 0))
        except Exception:
            frozen = {}

        drift = []
        re_audited = []
        for row in ev.get("packages", []):
            pid = str(row.get("package_id", ""))
            was = int(frozen.get(pid, 0))
            now_id = int(row.get("audit_id", 0))
            if str(row.get("standing", "")) != STANDING_CLEARED:
                drift.append({"package_id": pid, "standing": str(row.get("standing", "")),
                    "frozen_audit_id": was, "current_audit_id": now_id})
            elif was != now_id:
                re_audited.append({"package_id": pid, "frozen_audit_id": was, "current_audit_id": now_id})
        current_version = int(ev.get("policy_version", 0))
        pinned = str(r.pinned_maintainer)
        maintainer_changed = pinned != "" and str(ev.get("policy_maintainer", "")).lower() != pinned
        return json.dumps({"release_id": int(r.release_id), "status": STATUS_PUBLISHED,
            "health": HEALTH_DRIFTED if (len(drift) > 0 or maintainer_changed) else HEALTH_HEALTHY,
            "pinned_maintainer": pinned, "maintainer_changed": maintainer_changed,
            "policy_status": str(ev.get("policy_status", "")),
            "frozen_policy_version": int(r.frozen_policy_version),
            "current_policy_version": current_version,
            "policy_changed_since_publish": current_version != int(r.frozen_policy_version),
            "drift": drift, "re_audited": re_audited})

    @gl.public.view
    def list_releases(self, offset: int = 0, limit: int = 20) -> str:
        """Newest first."""
        total = int(self.count_releases)
        off = max(0, int(offset))
        lim = _clamp(int(limit), 1, MAX_PAGE)
        out = []
        i = off
        while i < total and len(out) < lim:
            r = self.releases.get(str(total - i))
            if r is not None:
                out.append(self._release_json(r))
            i += 1
        return json.dumps({"total": total, "releases": out})

    @gl.public.view
    def get_releases_by_proposer(self, proposer: str, offset: int = 0, limit: int = 20) -> str:
        who = str(proposer).lower()
        total = int(self.count_releases)
        off = max(0, int(offset))
        lim = _clamp(int(limit), 1, MAX_PAGE)
        out = []
        i = off
        scanned = 0
        while i < total and len(out) < lim and scanned < MAX_SCAN:
            r = self.releases.get(str(total - i))
            if r is not None and str(r.proposer).lower() == who:
                out.append(self._release_json(r))
            i += 1
            scanned += 1
        return json.dumps({"proposer": str(proposer), "next_offset": i, "done": i >= total, "releases": out})

    @gl.public.view
    def get_platform_stats(self) -> str:
        return json.dumps({"releases": int(self.count_releases), "published": int(self.count_published),
            "withdrawn": int(self.count_withdrawn),
            "blocked_publish_attempts": int(self.count_blocked_attempts)})

    @gl.public.view
    def get_config(self) -> str:
        return json.dumps({"auditor_address": str(self.auditor_address),
            "max_packages": MAX_PACKAGES,
            "max_open_drafts_per_proposer": MAX_OPEN_DRAFTS_PER_PROPOSER,
            "releases": int(self.count_releases)})
