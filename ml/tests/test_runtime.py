"""Guards for the runtime scoring layer (popularity guard + model-driven reasons)."""
import io
import json
import sys
import tarfile
import unittest
import importlib.util
from pathlib import Path

SC = Path(__file__).resolve().parents[1] / "supplychain"
sys.path.insert(0, str(SC))
spec = importlib.util.spec_from_file_location("sc_runtime", SC / "runtime.py")
runtime = importlib.util.module_from_spec(spec)
sys.modules["sc_runtime"] = runtime
spec.loader.exec_module(runtime)


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeScorer:
    eco = "npm"

    def __init__(self, tier, proba, popular=(), drivers=None):
        self._res = {"suspicionProba": proba, "tier": tier, "anomalyScore": 0.5, "reconstructionError": 1.0,
                     "drivers": drivers if drivers is not None else []}
        self.popular = set(popular)

    def known_malicious(self, name, version):
        return None

    def score_features(self, row):
        return dict(self._res)


ARCHIVE = tgz({"package.json": json.dumps({"name": "x", "version": "1.0.0"}), "index.js": "module.exports=1"})


class PopularityGuardTests(unittest.TestCase):
    def test_popular_package_is_never_high_confidence(self):
        out = runtime.score_package(FakeScorer("HIGH_CONFIDENCE", 0.73, popular={"react-router"}),
                                    "react-router", "7.0.0", archive=ARCHIVE)
        self.assertEqual(out["tier"], "REVIEW")
        self.assertEqual(out["tierBeforePopularityGuard"], "HIGH_CONFIDENCE")
        self.assertTrue(out["popularPackage"])
        self.assertIn("très populaire", out["reasons"][0])

    def test_popular_package_with_overwhelming_score_stays_high(self):
        out = runtime.score_package(FakeScorer("HIGH_CONFIDENCE", 0.97, popular={"mistralai"}),
                                    "mistralai", "1.2.3", archive=ARCHIVE)
        self.assertEqual(out["tier"], "HIGH_CONFIDENCE")
        self.assertIsNone(out["tierBeforePopularityGuard"])
        self.assertIn("très populaire", out["reasons"][0])  # still told, never hidden

    def test_unknown_package_keeps_its_tier(self):
        out = runtime.score_package(FakeScorer("HIGH_CONFIDENCE", 0.9, popular={"react-router"}),
                                    "evil-pkg", "1.0.0", archive=ARCHIVE)
        self.assertEqual(out["tier"], "HIGH_CONFIDENCE")
        self.assertFalse(out["popularPackage"])
        self.assertIsNone(out["tierBeforePopularityGuard"])

    def test_low_tier_has_no_reasons_even_when_popular(self):
        out = runtime.score_package(FakeScorer("LOW", 0.001, popular={"lodash"}), "lodash", "4.0.0", archive=ARCHIVE)
        self.assertEqual(out["tier"], "LOW")
        self.assertEqual(out["reasons"], [])

    def test_known_malicious_ignores_the_guard(self):
        class Known(FakeScorer):
            def known_malicious(self, name, version):
                return {"id": "MAL-1", "scope": "THIS_VERSION"}
        out = runtime.score_package(Known("LOW", 0.0, popular={"chalk"}), "chalk", "5.6.1", archive=ARCHIVE)
        self.assertEqual(out["tier"], "KNOWN_MALICIOUS")


class DriverReasonTests(unittest.TestCase):
    def test_only_real_positive_drivers_become_reasons(self):
        drivers = [{"feature": "name_char_score", "impact": 3.1, "value": 0.9},
                   {"feature": "n_text_files", "impact": 1.2, "value": 4.0},
                   {"feature": "has_readme", "impact": 0.05, "value": 1.0}]  # too small to be shown
        reasons = runtime.reasons_from_drivers(drivers)
        self.assertEqual(reasons[0], "Le nom ressemble à ceux de paquets malveillants connus")
        self.assertEqual(len(reasons), 2)
        self.assertFalse(any("README" in r for r in reasons))

    def test_features_with_the_same_meaning_are_merged(self):
        drivers = [{"feature": "n_text_files", "impact": 0.6, "value": 1},
                   {"feature": "n_files_total", "impact": 0.5, "value": 1}]
        self.assertEqual(len(runtime.reasons_from_drivers(drivers)), 1)

    def test_behavioural_features_have_readable_labels(self):
        self.assertIn("exécute du code", runtime.label_for("hook_pipe_to_shell"))
        self.assertIn("réseau", runtime.label_for("hook_target_network"))
        self.assertTrue(runtime.label_for("some_unknown_feature"))

    def test_drivers_are_empty_for_models_without_contributions(self):
        class Dummy:
            bundle = {"model": object()}
            model_cols = []
        self.assertEqual(runtime.Scorer._drivers(Dummy(), None), [])


class KnownMaliciousScopeTests(unittest.TestCase):
    """A false KNOWN_MALICIOUS is the worst false alarm: scope must be honoured exactly as OSSF states it."""

    FSEVENTS = {"id": "MAL-2023-462", "all": False, "versions": [],
                "ranges": [[{"introduced": "1.0.0"}, {"fixed": "1.2.11"}]]}

    def scorer(self, known):
        s = runtime.Scorer.__new__(runtime.Scorer)
        s.eco, s.known = "npm", known
        return s

    def test_interval_covers_old_versions_but_not_the_fixed_one(self):
        e = self.FSEVENTS
        for bad in ("1.0.0", "1.2.9", "1.2.10"):
            self.assertTrue(runtime.version_in_scope(bad, e), bad)
        for good in ("1.2.11", "2.0.0", "2.3.3", "0.9.0"):
            self.assertFalse(runtime.version_in_scope(good, e), good)

    def test_fsevents_2_3_3_is_not_reported_but_1_2_9_is(self):
        s = self.scorer({"fsevents": self.FSEVENTS})
        self.assertIsNone(s.known_malicious("fsevents", "2.3.3"))
        self.assertEqual(s.known_malicious("fsevents", "1.2.9")["scope"], "THIS_VERSION")

    def test_explicit_version_list_and_last_affected(self):
        self.assertTrue(runtime.version_in_scope("5.6.1", {"versions": ["5.6.1"], "ranges": []}))
        self.assertFalse(runtime.version_in_scope("5.6.2", {"versions": ["5.6.1"], "ranges": []}))
        last = {"versions": [], "ranges": [[{"introduced": "2.0.0"}, {"last_affected": "2.4.0"}]]}
        self.assertTrue(runtime.version_in_scope("2.4.0", last))
        self.assertFalse(runtime.version_in_scope("2.4.1", last))

    def test_whole_package_malicious_matches_any_version_even_unspecified(self):
        s = self.scorer({"evil": {"id": "MAL-1", "all": True, "versions": [], "ranges": []}})
        self.assertEqual(s.known_malicious("evil", "9.9.9")["scope"], "ALL_VERSIONS")
        self.assertEqual(s.known_malicious("evil", None)["scope"], "ALL_VERSIONS")

    def test_npm_security_holding_placeholder_is_not_malware(self):
        s = self.scorer({"fs": {"id": "MAL-X", "all": True, "versions": [], "ranges": []}})
        self.assertIsNone(s.known_malicious("fs", "0.0.1-security"))
        self.assertIsNotNone(s.known_malicious("fs", "0.0.2"))

    def test_scoped_package_without_a_version_is_never_claimed_malicious(self):
        s = self.scorer({"fsevents": self.FSEVENTS})
        self.assertIsNone(s.known_malicious("fsevents", None))
        self.assertIsNone(s.known_malicious("fsevents", ""))

    def test_builder_reads_open_interval_as_every_version_and_ignores_git_only_scope(self):
        ossf = runtime.F  # noqa: F841  (keeps the import graph honest)
        import ossf_extract
        rows = [
            {"id": "A", "name": "whole", "versions": None, "ranges": [[{"introduced": "0"}]], "git_only": False},
            {"id": "B", "name": "scoped", "versions": None,
             "ranges": [[{"introduced": "1.0.0"}, {"fixed": "1.2.11"}]], "git_only": False},
            {"id": "C", "name": "gitonly", "versions": None, "ranges": None, "git_only": True},
            {"id": "D", "name": "@s@pkg", "versions": ["1.0.0"], "ranges": None, "git_only": False},
        ]
        known = ossf_extract.build_known(rows, "npm")
        self.assertTrue(known["whole"]["all"])
        self.assertFalse(known["scoped"]["all"])
        self.assertNotIn("gitonly", known)
        self.assertIn("@s/pkg", known)  # DataDog-style scoped spelling normalised


if __name__ == "__main__":
    unittest.main()
