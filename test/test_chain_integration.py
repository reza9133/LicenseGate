"""End-to-end scenario across all three REAL contracts, wired exactly the way
the README deploys them: LicensePolicy -> PackageAuditor -> ReleaseGate."""
import json
import unittest

import genlayer_stub as stub
from helpers import (ALICE, BOB, MAINTAINER, AUDITOR_ADDR, GATE_ADDR, POLICY_ADDR, URLS, ChainTestCase, send_as)


class ChainIntegrationTests(ChainTestCase):
    def test_the_address_chain_is_wired_end_to_end(self):
        self.assertEqual(self.chain.auditor.get_policy_address(), str(POLICY_ADDR))
        self.assertEqual(self.chain.gate.get_auditor_address(), str(AUDITOR_ADDR))
        # the gate never stores or needs the policy address
        self.assertFalse(hasattr(self.chain.gate, "policy_address"))

    def test_full_release_story(self):
        c = self.chain

        # 1. a policy maintainer writes the rulebook
        self.assertEqual(c.make_policy()["version"], 1)

        # 2. dependencies are audited; a mix of outcomes
        self.assertEqual(c.audit("webframework@4.18.2", "mit")["verdict"], "ALLOWED")
        self.assertEqual(c.audit("httpclient@2.31.0", "apache")["verdict"], "ALLOWED")
        self.assertEqual(c.audit("jsengine@1.7.14", "mpl")["verdict"], "REVIEW")
        self.assertEqual(c.audit("dashboard@10.0.0", "agpl")["source"], "MARKER")
        self.assertEqual(c.audit("kernelmod@6.1.0", "gpl")["verdict"], "DENIED")

        # 3. a release is proposed with a blocking manifest
        rid = c.propose(project="webshop", tag="2.0.0",
            packages="webframework@4.18.2|httpclient@2.31.0|jsengine@1.7.14|dashboard@10.0.0")["release_id"]
        send_as(ALICE)
        blocked = json.loads(c.gate.publish_release(rid))
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["blockers"], ["dashboard@10.0.0", "jsengine@1.7.14"])

        # 4. the maintainer approves the MPL package; the AGPL one must go
        send_as(MAINTAINER)
        c.auditor.resolve_review(3, True, "file-level copyleft only, legal approved")
        send_as(ALICE)
        still_blocked = json.loads(c.gate.publish_release(rid))
        self.assertEqual(still_blocked["blockers"], ["dashboard@10.0.0"])
        c.gate.amend_manifest(rid, "webframework@4.18.2|httpclient@2.31.0|jsengine@1.7.14")

        # 5. publish: a bill of materials is frozen
        published = json.loads(c.gate.publish_release(rid))
        self.assertTrue(published["ok"])
        self.assertEqual(published["frozen_policy_version"], 1)
        self.assertEqual({row["package_id"] for row in published["bom"]},
            {"webframework@4.18.2", "httpclient@2.31.0", "jsengine@1.7.14"})
        self.assertEqual(json.loads(c.gate.get_release_health(rid))["health"], "HEALTHY")

        # 6. months later the policy tightens: the shipped release is now DRIFTED
        c.tick(90 * 86400)
        c.amend(rules="Only MIT and BSD are accepted from now on. Everything else needs a human decision.",
            note="legal tightened the rules")
        health = json.loads(c.gate.get_release_health(rid))
        self.assertEqual(health["health"], "DRIFTED")
        self.assertTrue(health["policy_changed_since_publish"])
        self.assertEqual(len(health["drift"]), 3)

        # 7. re-auditing under v2 recovers the packages the new policy still allows
        stub.set_llm(lambda prompt: (
            {"verdict": "ALLOWED", "license_id": "MIT", "confidence": 93, "reasoning": "MIT is accepted"}
            if "MIT License" in prompt.split("<license_text>")[1]
            else {"verdict": "REVIEW", "license_id": "Other", "confidence": 80, "reasoning": "needs a human"}))
        c.audit("webframework@4.18.2", "mit")
        c.audit("httpclient@2.31.0", "apache")
        c.audit("jsengine@1.7.14", "mpl")
        health = json.loads(c.gate.get_release_health(rid))
        self.assertEqual(health["health"], "DRIFTED")
        self.assertEqual({d["package_id"] for d in health["drift"]}, {"httpclient@2.31.0", "jsengine@1.7.14"})
        self.assertEqual([r["package_id"] for r in health["re_audited"]], ["webframework@4.18.2"])

        # 8. and the original record of what shipped is untouched
        original = json.loads(c.gate.get_release(rid))
        self.assertEqual(original["status"], "PUBLISHED")
        self.assertEqual(original["frozen_policy_version"], 1)

    def test_two_teams_share_one_auditor_but_keep_separate_governance(self):
        c = self.chain
        c.make_policy(name="team-a-policy", sender=MAINTAINER)
        c.make_policy(name="team-b-policy", sender=BOB)
        c.audit("webframework@4.18.2", "mpl", policy="team-a-policy")
        c.audit("webframework@4.18.2", "mpl", policy="team-b-policy")

        # each maintainer can only rule on their own policy's audits
        self.expect_error("only the policy maintainer", c.auditor.resolve_review, 2, True, "", sender=MAINTAINER)
        self.expect_error("only the policy maintainer", c.auditor.resolve_review, 1, True, "", sender=BOB)
        send_as(MAINTAINER)
        c.auditor.resolve_review(1, True, "fine for team A")
        self.assertEqual(c.status("webframework@4.18.2", policy="team-a-policy")["standing"], "CLEARED")
        self.assertEqual(c.status("webframework@4.18.2", policy="team-b-policy")["standing"], "REVIEW_PENDING")

        ra = c.propose(project="team-a-app", policy="team-a-policy", packages="webframework@4.18.2")
        rb = c.propose(project="team-b-app", policy="team-b-policy", packages="webframework@4.18.2")
        send_as(ALICE)
        self.assertTrue(json.loads(c.gate.publish_release(ra["release_id"]))["ok"])
        self.assertFalse(json.loads(c.gate.publish_release(rb["release_id"]))["ok"])

    def test_nothing_in_the_chain_is_payable_or_moves_value(self):
        for contract in (self.chain.policy, self.chain.auditor, self.chain.gate):
            for name in dir(contract):
                self.assertNotIn("payable", name)
                self.assertNotIn("withdraw_funds", name)
                self.assertNotIn("balance", name.lower())


if __name__ == "__main__":
    unittest.main()
