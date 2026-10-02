"""Tests for contracts/LicensePolicy.py -- the core, versioned rulebook."""
import json
import unittest

import genlayer_stub as stub
from helpers import (ALICE, BOB, DEPLOYER, MAINTAINER, DENY_MARKERS, RULES, ChainTestCase, send_as)


class CreatePolicyTests(ChainTestCase):
    def test_create_and_read_back(self):
        out = self.chain.make_policy()
        self.assertTrue(out["ok"])
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["deny_markers"], ["GNU AFFERO GENERAL PUBLIC LICENSE", "Server Side Public License"])

        state = json.loads(self.chain.policy.get_policy_state("acme-oss"))
        self.assertTrue(state["found"])
        self.assertEqual(state["status"], "ACTIVE")
        self.assertEqual(state["version"], 1)
        self.assertEqual(state["maintainer"], str(MAINTAINER))

        bundle = json.loads(self.chain.policy.get_active_bundle("acme-oss"))
        self.assertEqual(bundle["rules"], RULES)
        self.assertEqual(bundle["deny_markers"], DENY_MARKERS)

    def test_name_is_canonicalised(self):
        self.chain.make_policy(name="  Acme-OSS ")
        self.assertTrue(json.loads(self.chain.policy.get_policy_state("ACME-oss"))["found"])

    def test_bad_names_rejected(self):
        for bad in ["a", "x" * 33, "has space", "under_score", "-lead", "trail-", "caf\u00e9-x"]:
            self.expect_error("name must be", self.chain.policy.create_policy,
                bad, "Title", RULES, "", sender=MAINTAINER)

    def test_duplicate_name_rejected(self):
        self.chain.make_policy()
        self.expect_error("already exists", self.chain.policy.create_policy,
            "acme-oss", "Other", RULES, "", sender=BOB)

    def test_rules_length_bounds(self):
        self.expect_error("rules must be", self.chain.policy.create_policy,
            "short-rules", "T", "too short", "", sender=MAINTAINER)
        self.expect_error("rules must be", self.chain.policy.create_policy,
            "long-rules", "T", "x" * 1501, "", sender=MAINTAINER)

    def test_title_bounds(self):
        self.expect_error("title must be", self.chain.policy.create_policy,
            "no-title", "   ", RULES, "", sender=MAINTAINER)

    def test_deny_marker_rules(self):
        self.expect_error("at most 8", self.chain.policy.create_policy,
            "many-markers", "T", RULES, "|".join("marker-%d-x" % i for i in range(9)), sender=MAINTAINER)
        self.expect_error("each deny marker", self.chain.policy.create_policy,
            "tiny-marker", "T", RULES, "abc", sender=MAINTAINER)
        self.expect_error("unique", self.chain.policy.create_policy,
            "dup-marker", "T", RULES, "Some Marker|some marker", sender=MAINTAINER)

    def test_maintainer_cap(self):
        for i in range(10):
            self.chain.make_policy(name="policy-%d" % i)
        self.expect_error("at most 10 active policies", self.chain.policy.create_policy,
            "policy-10", "T", RULES, "", sender=MAINTAINER)
        # a different maintainer is unaffected
        self.assertTrue(self.chain.make_policy(name="policy-x1", sender=BOB)["ok"])


class AmendPolicyTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()

    def test_amend_creates_new_version_and_keeps_history(self):
        out = self.chain.amend(rules=RULES + " Dual licensed code must satisfy both.", note="dual license")
        self.assertEqual(out["version"], 2)
        self.assertEqual(out["previous_version"], 1)

        v1 = json.loads(self.chain.policy.get_rules("acme-oss", 1))
        v2 = json.loads(self.chain.policy.get_rules("acme-oss", 2))
        current = json.loads(self.chain.policy.get_rules("acme-oss", 0))
        self.assertEqual(v1["rules"], RULES)
        self.assertFalse(v1["is_current"])
        self.assertTrue(v2["is_current"])
        self.assertEqual(current["version"], 2)
        self.assertEqual(v2["note"], "dual license")

    def test_only_maintainer_can_amend(self):
        self.expect_error("only the policy maintainer", self.chain.policy.amend_policy,
            "acme-oss", RULES + " Sneaky change.", "", "", sender=BOB)
        # not even the deployer: there is no global admin
        self.expect_error("only the policy maintainer", self.chain.policy.amend_policy,
            "acme-oss", RULES + " Sneaky change.", "", "", sender=DEPLOYER)

    def test_identical_amendment_rejected(self):
        self.expect_error("identical", self.chain.policy.amend_policy,
            "acme-oss", RULES, DENY_MARKERS, "", sender=MAINTAINER)

    def test_marker_only_change_is_a_real_amendment(self):
        out = self.chain.amend(rules=RULES, markers="Business Source License")
        self.assertEqual(out["version"], 2)

    def test_unknown_policy(self):
        self.expect_error("unknown policy", self.chain.policy.amend_policy,
            "nope-nope", RULES, "", "", sender=MAINTAINER)

    def test_version_limit(self):
        for i in range(49):
            self.chain.amend(rules=RULES + " rev %d" % i)
        self.expect_error("limit of 50 versions", self.chain.policy.amend_policy,
            "acme-oss", RULES + " one too many", "", "", sender=MAINTAINER)

    def test_long_note_is_truncated(self):
        self.chain.amend(note="n" * 500)
        note = json.loads(self.chain.policy.get_rules("acme-oss", 2))["note"]
        self.assertEqual(len(note), 200)


class RetireAndTransferTests(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain.make_policy()

    def test_retire_is_final(self):
        send_as(MAINTAINER)
        out = json.loads(self.chain.policy.retire_policy("acme-oss"))
        self.assertEqual(out["status"], "RETIRED")
        self.assertEqual(json.loads(self.chain.policy.get_policy_state("acme-oss"))["status"], "RETIRED")
        self.expect_error("already RETIRED", self.chain.policy.retire_policy, "acme-oss", sender=MAINTAINER)
        self.expect_error("not ACTIVE", self.chain.policy.amend_policy,
            "acme-oss", RULES + " late edit", "", "", sender=MAINTAINER)

    def test_only_maintainer_can_retire(self):
        self.expect_error("only the policy maintainer", self.chain.policy.retire_policy,
            "acme-oss", sender=BOB)

    def test_transfer_hands_over_all_rights(self):
        send_as(MAINTAINER)
        out = json.loads(self.chain.policy.transfer_maintainer("acme-oss", str(ALICE)))
        self.assertEqual(out["maintainer"], str(ALICE))

        self.expect_error("only the policy maintainer", self.chain.policy.amend_policy,
            "acme-oss", RULES + " old maintainer", "", "", sender=MAINTAINER)
        self.assertEqual(self.chain.amend(sender=ALICE)["version"], 2)

    def test_transfer_validations(self):
        self.expect_error("not a valid address", self.chain.policy.transfer_maintainer,
            "acme-oss", "not-an-address", sender=MAINTAINER)
        self.expect_error("already the maintainer", self.chain.policy.transfer_maintainer,
            "acme-oss", str(MAINTAINER), sender=MAINTAINER)
        self.expect_error("only the policy maintainer", self.chain.policy.transfer_maintainer,
            "acme-oss", str(BOB), sender=BOB)

    def test_transfer_respects_receiver_cap_and_updates_counts(self):
        for i in range(10):
            self.chain.make_policy(name="bob-policy-%d" % i, sender=BOB)
        self.expect_error("maximum number of policies", self.chain.policy.transfer_maintainer,
            "acme-oss", str(BOB), sender=MAINTAINER)
        # the sender's slot is freed by a successful transfer
        send_as(MAINTAINER)
        self.chain.policy.transfer_maintainer("acme-oss", str(ALICE))
        self.assertEqual(int(self.chain.policy.maintainer_counts[MAINTAINER]), 0)
        self.assertEqual(int(self.chain.policy.maintainer_counts[ALICE]), 1)


class RetireFreesSlotTests(ChainTestCase):
    def test_retiring_frees_a_maintainer_slot_but_not_the_name(self):
        for i in range(10):
            self.chain.make_policy(name="slot-policy-%d" % i)
        self.expect_error("retire one first", self.chain.policy.create_policy,
            "slot-policy-10", "T", RULES, "", sender=MAINTAINER)
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("slot-policy-0")
        self.assertTrue(self.chain.make_policy(name="slot-policy-10")["ok"])
        # the retired name stays taken forever
        self.expect_error("already exists", self.chain.policy.create_policy,
            "slot-policy-0", "T", RULES, "", sender=BOB)

    def test_retired_policy_cannot_be_handed_over(self):
        self.chain.make_policy()
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("acme-oss")
        self.expect_error("only an ACTIVE policy", self.chain.policy.transfer_maintainer,
            "acme-oss", str(ALICE), sender=MAINTAINER)

    def test_counts_never_go_negative(self):
        self.chain.make_policy()
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("acme-oss")
        self.assertEqual(int(self.chain.policy.maintainer_counts[MAINTAINER]), 0)


class ViewTests(ChainTestCase):
    def test_unknown_policy_views_report_not_found(self):
        self.assertFalse(json.loads(self.chain.policy.get_policy_state("ghost-policy"))["found"])
        self.assertFalse(json.loads(self.chain.policy.get_active_bundle("ghost-policy"))["found"])
        self.assertFalse(json.loads(self.chain.policy.get_rules("ghost-policy", 1))["found"])

    def test_missing_version_not_found(self):
        self.chain.make_policy()
        self.assertFalse(json.loads(self.chain.policy.get_rules("acme-oss", 9))["found"])

    def test_listing_and_pagination(self):
        for i in range(5):
            self.chain.make_policy(name="list-policy-%d" % i, sender=MAINTAINER if i % 2 == 0 else BOB)
        page = json.loads(self.chain.policy.list_policies(0, 2))
        self.assertEqual(page["total"], 5)
        self.assertEqual([p["name"] for p in page["policies"]], ["list-policy-0", "list-policy-1"])
        rest = json.loads(self.chain.policy.list_policies(2, 40))
        self.assertEqual(len(rest["policies"]), 3)

        mine = json.loads(self.chain.policy.get_policies_by_maintainer(str(MAINTAINER), 0, 40))
        self.assertEqual([p["name"] for p in mine["policies"]],
            ["list-policy-0", "list-policy-2", "list-policy-4"])

    def test_stats(self):
        self.chain.make_policy(name="stats-one")
        self.chain.amend(name="stats-one")
        send_as(MAINTAINER)
        self.chain.policy.retire_policy("stats-one")
        stats = json.loads(self.chain.policy.get_platform_stats())
        self.assertEqual(stats, {"policies": 1, "retired": 1, "versions": 2})

    def test_get_config_is_the_auditor_probe(self):
        cfg = json.loads(self.chain.policy.get_config())
        self.assertIn("max_policies_per_maintainer", cfg)


if __name__ == "__main__":
    unittest.main()
