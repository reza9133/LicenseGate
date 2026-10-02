"""Tests for contracts/ReleaseGate.py -- the release decision, built on the auditor."""
import json
import unittest

import genlayer_stub as stub
from helpers import (ALICE, BOB, CAROL, DEPLOYER, MAINTAINER, AUDITOR_ADDR, POLICY_ADDR, ChainTestCase, send_as)


class ConstructorTests(ChainTestCase):
    def deploy_gate(self, arg):
        send_as(DEPLOYER)
        return stub.deploy_and_register(self.chain.gate_mod.ReleaseGate,
            stub.Address("0xb000000000000000000000000000000000000002"), arg)

    def test_rejects_bad_addresses(self):
        self.expect_error("not a valid address", self.deploy_gate, "nope")
        self.expect_error("zero address", self.deploy_gate, "0x" + "0" * 40)

    def test_rejects_nothing_behind_the_address(self):
        self.expect_error("no PackageAuditor answered", self.deploy_gate,
            "0xc000000000000000000000000000000000000009")

    def test_rejects_a_policy_passed_instead_of_an_auditor(self):
        self.expect_error("is not a PackageAuditor", self.deploy_gate, str(POLICY_ADDR))

    def test_auditor_address_is_stored_and_immutable(self):
        self.assertEqual(self.chain.gate.get_auditor_address(), str(AUDITOR_ADDR))
        for name in ("set_auditor_address", "set_auditor", "set_owner", "pause", "transfer_ownership"):
            self.assertFalse(hasattr(self.chain.gate, name), name)


class ProposeTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")

    def test_propose_creates_a_draft_and_reports_what_is_blocking(self):
        out = self.chain.propose(packages="bravo@2.0.0|alpha@1.0.0")
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "DRAFT")
        self.assertEqual(out["packages"], ["alpha@1.0.0", "bravo@2.0.0"], "manifest is stored sorted")
        self.assertEqual(out["cleared_now"], 1)
        self.assertEqual(out["blockers"], ["bravo@2.0.0"])
        rel = json.loads(self.chain.gate.get_release(out["release_id"]))
        self.assertEqual(rel["proposer"], str(ALICE))
        self.assertEqual(rel["bom"], [])

    def test_names_are_canonicalised_and_lookup_by_tag_works(self):
        self.chain.propose(project="  WebShop ", tag="V1.0.0-RC1+build5", packages="Alpha@1.0.0")
        rel = json.loads(self.chain.gate.get_release_by_tag("webshop", "v1.0.0-rc1+build5"))
        self.assertTrue(rel["found"])
        self.assertEqual(rel["project"], "webshop")
        self.assertFalse(json.loads(self.chain.gate.get_release_by_tag("webshop", "nope"))["found"])

    def test_input_validation(self):
        bad = self.chain.gate.propose_release
        self.expect_error("project must be", bad, "x", "1.0.0", "acme-oss", "alpha@1.0.0", sender=ALICE)
        self.expect_error("project must be", bad, "has space", "1.0.0", "acme-oss", "alpha@1.0.0", sender=ALICE)
        self.expect_error("version_tag must be", bad, "webshop", "", "acme-oss", "alpha@1.0.0", sender=ALICE)
        self.expect_error("version_tag must be", bad, "webshop", "v" * 33, "acme-oss", "alpha@1.0.0", sender=ALICE)
        self.expect_error("invalid policy_name", bad, "webshop", "1.0.0", "x", "alpha@1.0.0", sender=ALICE)
        self.expect_error("manifest is empty", bad, "webshop", "1.0.0", "acme-oss", " | ", sender=ALICE)
        self.expect_error("invalid package id", bad, "webshop", "1.0.0", "acme-oss", "alpha@1|bad one", sender=ALICE)
        self.expect_error("duplicate package", bad, "webshop", "1.0.0", "acme-oss",
            "alpha@1.0.0|ALPHA@1.0.0", sender=ALICE)
        self.expect_error("at most 20", bad, "webshop", "1.0.0", "acme-oss",
            "|".join("pkg%d@1" % i for i in range(21)), sender=ALICE)

    def test_unknown_policy_is_refused_up_front(self):
        self.expect_error("does not exist", self.chain.gate.propose_release,
            "webshop", "1.0.0", "ghost-policy", "alpha@1.0.0", sender=ALICE)

    def test_duplicate_project_and_tag_is_refused_until_withdrawn(self):
        first = self.chain.propose()
        self.expect_error("already exists", self.chain.gate.propose_release,
            "webshop", "1.0.0", "acme-oss", "alpha@1.0.0", sender=BOB)
        send_as(ALICE)
        self.chain.gate.withdraw_release(first["release_id"], "retrying")
        second = self.chain.propose(sender=BOB)
        self.assertGreater(second["release_id"], first["release_id"])
        self.assertEqual(json.loads(self.chain.gate.get_release_by_tag("webshop", "1.0.0"))["release_id"],
            second["release_id"])

    def test_open_draft_cap_is_per_proposer_and_freed_by_withdrawing(self):
        ids = []
        for i in range(10):
            ids.append(self.chain.propose(tag="1.0.%d" % i, packages="alpha@1.0.0")["release_id"])
        self.expect_error("open drafts", self.chain.gate.propose_release,
            "webshop", "1.0.99", "acme-oss", "alpha@1.0.0", sender=ALICE)
        self.assertTrue(self.chain.propose(tag="1.0.99", packages="alpha@1.0.0", sender=BOB)["ok"])
        send_as(ALICE)
        self.chain.gate.withdraw_release(ids[0], "")
        self.assertTrue(self.chain.propose(tag="1.0.98", packages="alpha@1.0.0")["ok"])


class AmendTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")
        self.release = self.chain.propose(packages="alpha@1.0.0|delta@1.0.0")["release_id"]

    def test_amend_changes_the_manifest_of_a_draft(self):
        send_as(ALICE)
        out = json.loads(self.chain.gate.amend_manifest(self.release, "alpha@1.0.0"))
        self.assertEqual(out["packages"], ["alpha@1.0.0"])
        self.assertEqual(out["blockers"], [])
        self.assertEqual(json.loads(self.chain.gate.get_release(self.release))["packages"], ["alpha@1.0.0"])

    def test_only_the_proposer_can_amend(self):
        self.expect_error("only the proposer", self.chain.gate.amend_manifest,
            self.release, "alpha@1.0.0", sender=BOB)
        self.expect_error("only the proposer", self.chain.gate.amend_manifest,
            self.release, "alpha@1.0.0", sender=MAINTAINER)

    def test_unchanged_or_invalid_manifests_are_refused(self):
        self.expect_error("unchanged", self.chain.gate.amend_manifest,
            self.release, "delta@1.0.0|alpha@1.0.0", sender=ALICE)
        self.expect_error("manifest is empty", self.chain.gate.amend_manifest, self.release, "", sender=ALICE)

    def test_published_releases_are_immutable(self):
        send_as(ALICE)
        self.chain.gate.amend_manifest(self.release, "alpha@1.0.0")
        self.chain.gate.publish_release(self.release)
        self.expect_error("only a DRAFT", self.chain.gate.amend_manifest,
            self.release, "alpha@1.0.0|bravo@2.0.0", sender=ALICE)


class PublishTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")
        self.chain.audit("bravo@2.0.0", "apache")
        self.chain.audit("delta@1.0.0", "gpl")
        self.chain.audit("charlie@1.0.0", "mpl")

    def test_publish_freezes_policy_version_and_audit_ids(self):
        rid = self.chain.propose()["release_id"]
        send_as(ALICE)
        out = json.loads(self.chain.gate.publish_release(rid))
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "PUBLISHED")
        self.assertEqual(out["frozen_policy_version"], 1)
        self.assertEqual(out["bom"], [{"package_id": "alpha@1.0.0", "audit_id": 1},
            {"package_id": "bravo@2.0.0", "audit_id": 2}])
        rel = json.loads(self.chain.gate.get_release(rid))
        self.assertEqual(rel["status"], "PUBLISHED")
        self.assertEqual(rel["bom"], out["bom"])
        self.assertGreater(rel["published_epoch"], 0)

    def test_blocked_publish_reports_blockers_and_changes_nothing(self):
        rid = self.chain.propose(packages="alpha@1.0.0|delta@1.0.0|charlie@1.0.0|ghost@9.9.9")["release_id"]
        send_as(ALICE)
        out = json.loads(self.chain.gate.publish_release(rid))
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "DRAFT")
        self.assertEqual(out["blockers"], ["charlie@1.0.0", "delta@1.0.0", "ghost@9.9.9"])
        self.assertEqual(out["cleared"], 1)
        self.assertEqual(json.loads(self.chain.gate.get_release(rid))["status"], "DRAFT")
        self.assertEqual(json.loads(self.chain.gate.get_platform_stats())["blocked_publish_attempts"], 1)

    def test_a_human_approval_unblocks_the_release(self):
        rid = self.chain.propose(packages="alpha@1.0.0|charlie@1.0.0")["release_id"]
        send_as(ALICE)
        self.assertFalse(json.loads(self.chain.gate.publish_release(rid))["ok"])
        send_as(MAINTAINER)
        self.chain.auditor.resolve_review(4, True, "legal signed off")
        send_as(ALICE)
        self.assertTrue(json.loads(self.chain.gate.publish_release(rid))["ok"])

    def test_policy_amendment_between_propose_and_publish_blocks(self):
        rid = self.chain.propose()["release_id"]
        preview = json.loads(self.chain.gate.preview_gate(rid))
        self.assertTrue(preview["would_publish"])
        self.chain.amend()
        preview = json.loads(self.chain.gate.preview_gate(rid))
        self.assertFalse(preview["would_publish"])
        self.assertEqual(preview["policy_version"], 2)
        send_as(ALICE)
        self.assertFalse(json.loads(self.chain.gate.publish_release(rid))["ok"])
        # re-auditing under v2 unblocks it, and the BOM records the NEW audits
        self.chain.audit("alpha@1.0.0", "mit")
        self.chain.audit("bravo@2.0.0", "apache")
        send_as(ALICE)
        out = json.loads(self.chain.gate.publish_release(rid))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frozen_policy_version"], 2)
        self.assertEqual([row["audit_id"] for row in out["bom"]], [5, 6])

    def test_retired_policy_blocks_publishing(self):
        rid = self.chain.propose()["release_id"]
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("acme-oss")
        send_as(ALICE)
        out = json.loads(self.chain.gate.publish_release(rid))
        self.assertFalse(out["ok"])
        self.assertEqual(out["policy_status"], "RETIRED")

    def test_only_the_proposer_publishes_and_only_drafts(self):
        rid = self.chain.propose()["release_id"]
        self.expect_error("only the proposer", self.chain.gate.publish_release, rid, sender=BOB)
        send_as(ALICE)
        self.chain.gate.publish_release(rid)
        self.expect_error("not DRAFT", self.chain.gate.publish_release, rid, sender=ALICE)

    def test_publishing_frees_a_draft_slot(self):
        for i in range(10):
            self.chain.propose(tag="2.0.%d" % i, packages="alpha@1.0.0")
        send_as(ALICE)
        self.chain.gate.publish_release(1)
        self.assertTrue(self.chain.propose(tag="2.0.99", packages="alpha@1.0.0")["ok"])

    def test_unknown_release(self):
        self.expect_error("unknown release", self.chain.gate.publish_release, 99, sender=ALICE)


class WithdrawTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")
        self.rid = self.chain.propose(packages="alpha@1.0.0")["release_id"]

    def test_withdraw_a_draft_and_a_published_release(self):
        send_as(ALICE)
        out = json.loads(self.chain.gate.withdraw_release(self.rid, "  changed   my mind "))
        self.assertEqual(out["status"], "WITHDRAWN")
        self.assertEqual(json.loads(self.chain.gate.get_release(self.rid))["withdraw_note"], "changed my mind")

        other = self.chain.propose(tag="2.0.0", packages="alpha@1.0.0")["release_id"]
        send_as(ALICE)
        self.chain.gate.publish_release(other)
        self.assertEqual(json.loads(self.chain.gate.withdraw_release(other, "recalled"))["status"], "WITHDRAWN")

    def test_only_the_proposer_can_withdraw_and_only_once(self):
        self.expect_error("only the proposer", self.chain.gate.withdraw_release, self.rid, "", sender=BOB)
        send_as(ALICE)
        self.chain.gate.withdraw_release(self.rid, "")
        self.expect_error("already withdrawn", self.chain.gate.withdraw_release, self.rid, "", sender=ALICE)

    def test_withdrawn_releases_cannot_be_published_or_health_checked(self):
        send_as(ALICE)
        self.chain.gate.withdraw_release(self.rid, "")
        self.expect_error("not DRAFT", self.chain.gate.publish_release, self.rid, sender=ALICE)
        self.assertEqual(json.loads(self.chain.gate.get_release_health(self.rid))["health"], "NOT_PUBLISHED")


class ReleaseHealthTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")
        self.chain.audit("bravo@2.0.0", "apache")
        self.rid = self.chain.propose()["release_id"]
        send_as(ALICE)
        self.chain.gate.publish_release(self.rid)

    def health(self):
        return json.loads(self.chain.gate.get_release_health(self.rid))

    def test_fresh_release_is_healthy(self):
        h = self.health()
        self.assertEqual(h["health"], "HEALTHY")
        self.assertEqual(h["drift"], [])
        self.assertEqual(h["re_audited"], [])
        self.assertFalse(h["policy_changed_since_publish"])

    def test_draft_is_not_published(self):
        draft = self.chain.propose(tag="9.9.9", packages="alpha@1.0.0")["release_id"]
        h = json.loads(self.chain.gate.get_release_health(draft))
        self.assertEqual(h["health"], "NOT_PUBLISHED")
        self.assertEqual(h["status"], "DRAFT")

    def test_policy_amendment_turns_a_shipped_release_drifted(self):
        self.chain.amend()
        h = self.health()
        self.assertEqual(h["health"], "DRIFTED")
        self.assertTrue(h["policy_changed_since_publish"])
        self.assertEqual(h["frozen_policy_version"], 1)
        self.assertEqual(h["current_policy_version"], 2)
        self.assertEqual({d["standing"] for d in h["drift"]}, {"STALE"})
        self.assertEqual(json.loads(self.chain.gate.get_release(self.rid))["status"], "PUBLISHED",
            "drift never rewrites the release itself")

    def test_re_auditing_under_the_new_policy_restores_health_and_is_reported(self):
        self.chain.amend()
        self.chain.audit("alpha@1.0.0", "mit")
        self.assertEqual(self.health()["health"], "DRIFTED")
        self.chain.audit("bravo@2.0.0", "apache")
        h = self.health()
        self.assertEqual(h["health"], "HEALTHY")
        self.assertTrue(h["policy_changed_since_publish"])
        self.assertEqual({r["package_id"] for r in h["re_audited"]}, {"alpha@1.0.0", "bravo@2.0.0"})

    def test_a_revoked_audit_drifts_only_that_package(self):
        send_as(MAINTAINER)
        self.chain.auditor.revoke_audit(2, "license url belongs to another project")
        h = self.health()
        self.assertEqual(h["health"], "DRIFTED")
        self.assertEqual([d["package_id"] for d in h["drift"]], ["bravo@2.0.0"])
        self.assertEqual(h["drift"][0]["standing"], "REVOKED")
        self.assertEqual(h["drift"][0]["frozen_audit_id"], 2)

    def test_retiring_the_policy_drifts_everything(self):
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("acme-oss")
        h = self.health()
        self.assertEqual(h["health"], "DRIFTED")
        self.assertEqual(h["policy_status"], "RETIRED")
        self.assertEqual({d["standing"] for d in h["drift"]}, {"POLICY_RETIRED"})


class PinnedMaintainerTests(ChainTestCase):
    """Policy names are first come, first served. Pinning the expected
    maintainer protects a release from a squatted or hijacked policy name."""

    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")

    def propose(self, expected, tag="1.0.0", sender=ALICE):
        send_as(sender)
        return json.loads(self.chain.gate.propose_release(
            "webshop", tag, "acme-oss", "alpha@1.0.0", expected))

    def test_propose_always_reports_who_maintains_the_policy(self):
        out = self.propose("")
        self.assertEqual(out["policy_maintainer"], str(MAINTAINER))
        self.assertEqual(out["pinned_maintainer"], "")

    def test_a_squatter_is_caught_when_the_maintainer_is_pinned(self):
        self.chain.make_policy(name="squatted-oss", sender=BOB)
        self.expect_error("not by the expected maintainer", self.chain.gate.propose_release,
            "webshop", "1.0.0", "squatted-oss", "alpha@1.0.0", str(MAINTAINER), sender=ALICE)

    def test_pin_is_stored_case_insensitively(self):
        out = self.propose(str(MAINTAINER).upper().replace("0X", "0x"))
        self.assertEqual(out["pinned_maintainer"], str(MAINTAINER).lower())
        self.assertEqual(json.loads(self.chain.gate.get_release(out["release_id"]))["pinned_maintainer"],
            str(MAINTAINER).lower())

    def test_invalid_pin_is_rejected(self):
        self.expect_error("expected_maintainer is not a valid address", self.chain.gate.propose_release,
            "webshop", "1.0.0", "acme-oss", "alpha@1.0.0", "not-an-address", sender=ALICE)

    def test_pinned_release_refuses_to_publish_after_a_maintainer_change(self):
        rid = self.propose(str(MAINTAINER))["release_id"]
        send_as(MAINTAINER)
        self.chain.policy.transfer_maintainer("acme-oss", str(CAROL))
        preview = json.loads(self.chain.gate.preview_gate(rid))
        self.assertFalse(preview["would_publish"])
        self.assertFalse(preview["maintainer_matches"])
        self.assertEqual(preview["policy_maintainer"], str(CAROL))
        self.expect_error("no longer the one pinned", self.chain.gate.publish_release, rid, sender=ALICE)

    def test_a_published_pinned_release_drifts_when_the_maintainer_changes(self):
        rid = self.propose(str(MAINTAINER))["release_id"]
        send_as(ALICE)
        self.chain.gate.publish_release(rid)
        h = json.loads(self.chain.gate.get_release_health(rid))
        self.assertEqual(h["health"], "HEALTHY")
        self.assertFalse(h["maintainer_changed"])
        send_as(MAINTAINER)
        self.chain.policy.transfer_maintainer("acme-oss", str(CAROL))
        h = json.loads(self.chain.gate.get_release_health(rid))
        self.assertEqual(h["health"], "DRIFTED")
        self.assertTrue(h["maintainer_changed"])
        self.assertEqual(h["drift"], [], "the packages themselves are still cleared")

    def test_unpinned_releases_are_not_affected_by_a_maintainer_change(self):
        rid = self.propose("")["release_id"]
        send_as(MAINTAINER)
        self.chain.policy.transfer_maintainer("acme-oss", str(CAROL))
        send_as(ALICE)
        self.assertTrue(json.loads(self.chain.gate.publish_release(rid))["ok"])
        self.assertEqual(json.loads(self.chain.gate.get_release_health(rid))["health"], "HEALTHY")


class ListingTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()
        self.chain.audit("alpha@1.0.0", "mit")

    def test_listing_newest_first_and_by_proposer(self):
        self.chain.propose(tag="1.0.0", packages="alpha@1.0.0", sender=ALICE)
        self.chain.propose(tag="1.1.0", packages="alpha@1.0.0", sender=BOB)
        self.chain.propose(tag="1.2.0", packages="alpha@1.0.0", sender=ALICE)
        page = json.loads(self.chain.gate.list_releases(0, 2))
        self.assertEqual(page["total"], 3)
        self.assertEqual([r["version_tag"] for r in page["releases"]], ["1.2.0", "1.1.0"])
        mine = json.loads(self.chain.gate.get_releases_by_proposer(str(ALICE), 0, 40))
        self.assertEqual([r["version_tag"] for r in mine["releases"]], ["1.2.0", "1.0.0"])
        self.assertTrue(mine["done"])

    def test_stats_and_config(self):
        a = self.chain.propose(tag="1.0.0", packages="alpha@1.0.0")["release_id"]
        b = self.chain.propose(tag="1.1.0", packages="alpha@1.0.0")["release_id"]
        send_as(ALICE)
        self.chain.gate.publish_release(a)
        self.chain.gate.withdraw_release(b, "")
        self.assertEqual(json.loads(self.chain.gate.get_platform_stats()),
            {"releases": 2, "published": 1, "withdrawn": 1, "blocked_publish_attempts": 0})
        self.assertEqual(json.loads(self.chain.gate.get_config())["auditor_address"], str(AUDITOR_ADDR))

    def test_get_release_unknown(self):
        self.assertFalse(json.loads(self.chain.gate.get_release(77))["found"])


if __name__ == "__main__":
    unittest.main()
