"""Guards for the secret-triage pipeline. Run from ml/: python -m unittest discover -s tests"""
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

import importlib  # noqa: E402

SECRETS_DIR = str(Path(__file__).resolve().parents[1] / "secrets")


def _isolated_import():
    """ml/secrets and ml/supplychain both have modules named features / runtime / data: import ours in isolation so a
    single `unittest discover` run does not mix them up."""
    names = ("data", "features", "evaluate", "runtime")
    saved = {n: sys.modules.pop(n) for n in names if n in sys.modules}
    sys.path.insert(0, SECRETS_DIR)
    try:
        return {n: importlib.import_module(n) for n in names}
    finally:
        sys.path.remove(SECRETS_DIR)
        for n in names:
            sys.modules.pop(n, None)
        sys.modules.update(saved)


_M = _isolated_import()
D, E, F, R = _M["data"], _M["evaluate"], _M["features"], _M["runtime"]


def row(**kw):
    base = {"RepoName": "r1", "FilePath": "data/r1/test/a.py", "LineStart": "2", "LineEnd": "2", "GroundTruth": "T",
            "ValueStart": "11", "ValueEnd": "21", "Category": "Password", "PredefinedPattern": "", "CryptographyKey": ""}
    base.update(kw)
    return base


LINES = ["import os", 'password = "hunter2xyz"', "print(x)"]


class DataTests(unittest.TestCase):
    def test_value_span_and_context(self):
        rec = D.build_record(row(), LINES)
        self.assertEqual(rec["value"], '"hunter2xy')
        self.assertFalse(rec["whole_line"])
        self.assertEqual(rec["before"], "import os")
        self.assertEqual(rec["after"], "print(x)")

    def test_whole_line_markup_flagged_and_dropped(self):
        rec = D.build_record(row(ValueStart="", ValueEnd="", GroundTruth="F"), LINES)
        self.assertTrue(rec["whole_line"])
        df = pd.DataFrame([rec])
        self.assertEqual(len(D.clean(df)), 0)  # a span-less False row would leak the label
        self.assertEqual(len(D.clean(df, require_span=False)), 1)

    def test_missing_line_is_skipped(self):
        self.assertIsNone(D.build_record(row(LineStart="99", LineEnd="99"), LINES))
        self.assertIsNone(D.build_record(row(), []))

    def test_labels_and_dedup(self):
        a = D.build_record(row(), LINES)
        b = D.build_record(row(GroundTruth="X"), LINES)
        df = pd.DataFrame([a, a, b])
        out = D.clean(df)
        self.assertEqual(sorted(out["y"].tolist()), [0, 1])  # duplicate T dropped, X counted as not real
        self.assertEqual(len(D.clean(df, drop_unknown=True)), 1)


class FeatureTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(F.shannon_entropy(""), 0.0)
        self.assertAlmostEqual(F.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(F.shannon_entropy("abcd"), 2.0)

    def test_placeholder_and_reference_values(self):
        self.assertEqual(F.value_features("<YOUR_PASSWORD>")["v_placeholder"], 1)
        self.assertEqual(F.value_features("${DB_PASS}")["v_var_ref"], 1)
        self.assertEqual(F.value_features("xxxxxxxx")["v_all_same"], 1)
        self.assertEqual(F.value_features("AKIAIOSFODNN7EXAMPLE")["v_known_prefix"], 1)

    def test_hash_and_uuid_shapes(self):
        self.assertEqual(F.value_features("d41d8cd98f00b204e9800998ecf8427e")["v_hexlen_hash"], 1)
        self.assertEqual(F.value_features("123e4567-e89b-12d3-a456-426614174000")["v_is_uuid"], 1)

    def test_quotes_are_stripped_before_measuring(self):
        self.assertEqual(F.value_features('"abcdef12"')["v_len"], 8)

    def test_path_flags(self):
        f = F.path_features("data/r/test/example/x.py", ".py")
        self.assertEqual(f["p_test"], 1)
        self.assertEqual(f["p_example"], 1)
        self.assertEqual(f["p_ext_code"], 1)

    def test_featurize_is_numeric_and_has_no_label_column(self):
        rec = D.build_record(row(), LINES)
        X = F.featurize(pd.DataFrame([rec]))
        self.assertTrue(np.isfinite(X.to_numpy()).all())
        self.assertFalse({"y", "truth", "whole_line"} & set(X.columns))

    def test_masked_text_hides_the_secret(self):
        rec = D.build_record(row(), LINES)
        self.assertNotIn("hunter2xy", F.masked_text(rec))
        self.assertIn("<SECRET>", F.masked_text(rec))


class EvaluationTests(unittest.TestCase):
    def test_threshold_keeps_target_recall(self):
        y = np.array([1] * 100 + [0] * 100)
        s = np.concatenate([np.linspace(0.5, 1.0, 100), np.linspace(0.0, 0.6, 100)])
        thr = E.threshold_for_recall(y, s, 0.98)
        op = E.operating_point(y, s, thr)
        self.assertGreaterEqual(op["recall_reel"], 0.98)
        self.assertGreater(op["faux_positifs_ecartes"], 0.5)

    def test_operating_point_counts(self):
        op = E.operating_point(np.array([1, 1, 0, 0]), np.array([0.9, 0.2, 0.8, 0.1]), 0.5)
        self.assertEqual((op["tp"], op["fn"], op["fp"], op["tn"]), (1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.R = R
        cls.bundle = R.DEFAULT_BUNDLE
        if cls.bundle.exists():
            cls.triage = R.SecretTriage()

    def need_bundle(self):
        if not self.bundle.exists():
            self.skipTest("bundle not exported (python secrets/export.py)")

    def test_finding_conversion(self):
        rec = self.R.finding_to_record({"RuleID": "generic-api-key", "File": "/w/repo/config/env/test.js",
                                        "Match": 'zapApiKey: "abc"', "Secret": "abc"})
        self.assertEqual(rec["ext"], ".js")
        self.assertEqual(rec["value"], "abc")
        self.assertEqual(rec["before"], "")

    def test_scope_and_priority(self):
        self.assertEqual(self.R.path_scope("/w/docs/config.rst", ".rst"), "TEST_OR_DOC")
        self.assertEqual(self.R.path_scope("/w/src/app/settings.py", ".py"), "PRODUCTION")
        for p, e in (("/w/frontend/app/oauth.component.spec.ts", ".ts"), ("/w/web/e2e/login.ts", ".ts"),
                     ("/w/app/__mocks__/api.js", ".js"), ("/w/src/user.test.js", ".js")):
            self.assertEqual(self.R.path_scope(p, e), "TEST_OR_DOC", p)
        self.assertLess(self.R.priority("LIKELY_REAL", "PRODUCTION"), self.R.priority("LIKELY_REAL", "TEST_OR_DOC"))
        self.assertLess(self.R.priority("REVIEW", "PRODUCTION"), self.R.priority("LIKELY_FALSE_POSITIVE", "PRODUCTION"))

    def test_bundle_columns_match_featurizer(self):
        self.need_bundle()
        X = self.R.featurize_findings([{"File": "a/b.py", "Match": 'x = "y"', "Secret": "y"}], self.triage.columns)
        self.assertEqual(list(X.columns), self.triage.columns)
        self.assertTrue(np.isfinite(X.to_numpy()).all())

    def test_obvious_cases(self):
        self.need_bundle()
        res = self.triage.score([
            {"File": "/r/src/db.py", "Match": 'password = "<YOUR_PASSWORD>"', "Secret": "<YOUR_PASSWORD>"},
            {"File": "/r/src/aws.py", "Match": 'aws_key = "AKIAQ3RT7XK2M9WZP4LD"', "Secret": "AKIAQ3RT7XK2M9WZP4LD"},
        ])
        self.assertEqual(res[0]["verdict"], "LIKELY_FALSE_POSITIVE")
        self.assertEqual(res[1]["verdict"], "LIKELY_REAL")
        self.assertTrue(all(0.0 <= r["probaReal"] <= 1.0 for r in res))

    def test_empty_input(self):
        self.need_bundle()
        self.assertEqual(self.triage.score([]), [])

    def test_runtime_matches_direct_prediction(self):
        """Same row through the runtime path and through the training path gives the same score."""
        self.need_bundle()
        import joblib
        b = joblib.load(self.bundle)
        finding = {"File": "/r/app/conf.py", "Match": 'api_key = "9fQ2xLmP7vZk3TnB8aWd"', "Secret": "9fQ2xLmP7vZk3TnB8aWd"}
        X = F.featurize(pd.DataFrame([self.R.finding_to_record(finding)]), use_rule=False).reindex(columns=b["columns"], fill_value=0.0)
        direct = float(b["isotonic"].predict(b["model"].predict_proba(X)[:, 1])[0])
        self.assertAlmostEqual(direct, self.triage.score([finding])[0]["probaReal"], places=4)


class MatchFallbackTests(unittest.TestCase):
    def test_value_from_stored_match(self):
        self.assertEqual(R.value_from_match('zapApiKey: "v9dn0balpqas1pcc281tn5ood1"'), "v9dn0balpqas1pcc281tn5ood1")
        self.assertEqual(R.value_from_match("SECRET_KEY = 'abc123def'"), "abc123def")
        self.assertEqual(R.value_from_match('JWT_SECRET=Gm1rJ3w3lryS3cr3t'), "Gm1rJ3w3lryS3cr3t")
        self.assertEqual(R.value_from_match("-----BEGIN RSA PRIVATE KEY-----\nMIIC"), "-----BEGIN RSA PRIVATE KEY-----\nMIIC")
        self.assertEqual(R.value_from_match("AKIAQ3RT7XK2M9WZP4LD"), "AKIAQ3RT7XK2M9WZP4LD")
        self.assertEqual(R.value_from_match(""), "")

    def test_record_without_secret_uses_match(self):
        rec = R.finding_to_record({"File": "/r/a.js", "Match": 'token: "zzz999"'})
        self.assertEqual(rec["value"], "zzz999")


class ExplainTests(unittest.TestCase):
    def test_unset_flags_are_never_quoted_and_texts_are_unique(self):
        cols = ["p_test", "v_len", "v_log_len", "v_entropy", "v_placeholder"]
        contribs = np.array([-2.0, 1.5, 1.4, 1.2, -1.0])
        values = np.array([0.0, 24.0, 3.2, 4.1, 1.0])
        out = R.explain(contribs, cols, values, top=3)
        self.assertNotIn("fichier de test", out)               # flag not set: not a reason
        self.assertEqual(len(out), len(set(out)))               # v_len and v_log_len share one text
        self.assertIn("la valeur ressemble à un placeholder (exemple, xxx, changeme…)", out)

    def test_numeric_conditions(self):
        out = R.explain(np.array([-2.0]), ["v_frac_digit"], np.array([0.1]))
        self.assertEqual(out, [])
        out = R.explain(np.array([-2.0]), ["v_frac_digit"], np.array([0.9]))
        self.assertEqual(out, ["valeur essentiellement numérique"])


class NoiseRuleTests(unittest.TestCase):
    def rec(self, match, value, path, ext=None):
        return R.finding_to_record({"File": path, "Match": match, "Secret": value})

    def test_rules_catch_the_noise_seen_on_real_repositories(self):
        cases = [
            ('{F76350B1-EE96-4D39-9BD0-B337EF7D4D9E}.Debug|x86', "F76350B1-EE96-4D39-9BD0-B337EF7D4D9E", "/r/a/App.sln"),
            ('"transactionId": "eb8c8930-f675-4ab2-912d-cb2970080dda"', "eb8c8930-f675-4ab2-912d-cb2970080dda", "/r/d/x.json"),
            ('S3Key": "7e5f48d1e79c915595d938c932b6f0101715a162780d01a55845367aa8fdd99a"',
             "7e5f48d1e79c915595d938c932b6f0101715a162780d01a55845367aa8fdd99a", "/r/x.json"),
            ('token=abc123def456', "abc123def456", "/r/README.md"),
            ('"password": "md5$niTI8Z7A9XvV$641ae74c7472d5c907c66994b2289314"', "md5$niTI8Z7A9XvV$641ae74c7472d5c907c66994b2289314", "/r/u.json"),
            ("file detected: /w/server-truststore.p12", "", "/w/server-truststore.p12"),
            ("Girish Sontakke <girishsontakke7@gmail.com>", "girishsontakke7", "/r/AUTHORS"),
            ("email: 'chandlervasquez@zillactic.com',", "chandlervasquez", "/r/test/data/payload.ts"),
            ('S3Key": "dd5711540f04e06aa955d7f4862fc04e8cdea464cb590dae91ed2976bb78098e.zip"',
             "dd5711540f04e06aa955d7f4862fc04e8cdea464cb590dae91ed2976bb78098e.zip", "/r/Expected.json"),
        ]
        for match, value, path in cases:
            self.assertIsNotNone(R.noise_reason(self.rec(match, value, path)), match)

    def test_rules_never_hide_real_looking_secrets(self):
        keep = [
            ('api_key = "9fQ2xLmP7vZk3TnB8aWd"', "9fQ2xLmP7vZk3TnB8aWd", "/r/app/conf.py"),
            ('client_secret = "123e4567-e89b-12d3-a456-426614174000"', "123e4567-e89b-12d3-a456-426614174000", "/r/app/conf.py"),
            ('AWS_KEY = "AKIAQ3RT7XK2M9WZP4LD"', "AKIAQ3RT7XK2M9WZP4LD", "/r/aws.py"),
            ("-----BEGIN RSA PRIVATE KEY-----\nMIIC", "-----BEGIN RSA PRIVATE KEY-----\nMIIC", "/r/server.key"),
            ('password = "p@ssw0rd"', "p@ssw0rd", "/r/db.php"),
            ("DATABASE_URL=postgres://admin:S3cretPw@db.example.com/app", "S3cretPw", "/r/.env"),
            ('secret = "8f14e45fceea167a5a36dedd4bea2543"', "8f14e45fceea167a5a36dedd4bea2543", "/r/app.py"),
        ]
        for match, value, path in keep:
            self.assertIsNone(R.noise_reason(self.rec(match, value, path)), match)
