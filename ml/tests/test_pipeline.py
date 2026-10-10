"""Guards for the ML pipeline methodology. Run: python -m unittest discover -s tests (from ml/)."""
import json
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import predict  # noqa: E402
import train  # noqa: E402


def frame(rows):
    return pd.DataFrame(rows, columns=["canonical_id", "first_seen_at"]).assign(
        first_seen_at=lambda d: pd.to_datetime(d["first_seen_at"]), sla_breached=0)


class SplitTests(unittest.TestCase):
    def setUp(self):
        # CVE-A recurs late in another repo: one train CVE with a row after the test start.
        rows = [(f"CVE-{i}", f"2026-01-{i + 1:02d}") for i in range(20)]
        rows.append(("CVE-0", "2026-03-01"))
        self.df = frame(rows)

    def test_cve_never_split_across_sets(self):
        tr, va, te = train.grouped_chronological_split(self.df)
        sets = [set(x["canonical_id"]) for x in (tr, va, te)]
        self.assertFalse(sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2])

    def test_default_keeps_overlap_and_reports_it(self):
        tr, va, te = train.grouped_chronological_split(self.df)
        self.assertGreaterEqual(tr.attrs["overlap_rows"], 1)
        self.assertEqual(tr.attrs["purged_rows"], 0)

    def test_purge_makes_split_strictly_chronological(self):
        tr, va, te = train.grouped_chronological_split(self.df, purge=True)
        self.assertLess(tr["first_seen_at"].max(), te["first_seen_at"].min())
        self.assertLess(va["first_seen_at"].max(), te["first_seen_at"].min())
        self.assertGreaterEqual(tr.attrs["purged_rows"], 1)


class SelectionTests(unittest.TestCase):
    def test_external_needs_to_strictly_win(self):
        val = {train.CONFIG_INTERNAL: {"roc_auc": 0.9}, train.CONFIG_EXTERNAL: {"roc_auc": 0.9}}
        self.assertEqual(train.select_config(val, "roc_auc", True)[0], train.CONFIG_INTERNAL)
        val[train.CONFIG_EXTERNAL]["roc_auc"] = 0.95
        self.assertEqual(train.select_config(val, "roc_auc", True)[0], train.CONFIG_EXTERNAL)

    def test_lower_is_better_for_mae(self):
        val = {train.CONFIG_INTERNAL: {"mae": 3.0}, train.CONFIG_EXTERNAL: {"mae": 2.0}}
        self.assertEqual(train.select_config(val, "mae", False)[0], train.CONFIG_EXTERNAL)

    def test_falls_back_to_cv_when_validation_unusable(self):
        val = {train.CONFIG_INTERNAL: {"roc_auc": None}, train.CONFIG_EXTERNAL: {"roc_auc": None}}
        cv = {train.CONFIG_INTERNAL: {"roc_auc": 0.7}, train.CONFIG_EXTERNAL: {"roc_auc": 0.8}}
        self.assertEqual(train.select_config(val, "roc_auc", True, cv)[0], train.CONFIG_EXTERNAL)
        self.assertEqual(train.select_config(val, "roc_auc", True)[0], train.CONFIG_INTERNAL)


class EvaluateTests(unittest.TestCase):
    def test_single_class_gives_null_not_zero(self):
        m = train.evaluate(None, pd.DataFrame({"a": [1, 2]}), pd.Series([0, 0]), "x")
        self.assertTrue(m["skipped"])
        self.assertIsNone(m["roc_auc"])
        self.assertEqual(m["n_negative"], 2)

    def test_small_minority_class_is_warned(self):
        warns = train.split_warnings({"cfg": {"n_positive": 1, "n_negative": 80}}, {})
        self.assertTrue(any("not statistically meaningful" in w for w in warns))


class PredictTests(unittest.TestCase):
    def test_labels_are_stripped_from_features(self):
        row = predict.prepare_features({"cvss_score": 7.0, "days_to_fix": 3, "sla_breached": True}, [])
        self.assertNotIn("days_to_fix", row)
        self.assertNotIn("sla_breached", row)
        self.assertEqual(set(row), set(train.INFERENCE_COLUMNS))

    def test_unreliable_mae_is_not_exposed(self):
        d = Path(__file__).parent
        metrics = d / "_tmp_metrics.json"
        reg = d / "_tmp_reg.joblib"
        try:
            metrics.write_text(json.dumps({"mae": 0.0, "mae_reliable": False}))
            reg.write_bytes(b"")
            import joblib
            joblib.dump("dummy", reg)
            _, mae = predict.load_regressor(reg, metrics)
            self.assertIsNone(mae)
            metrics.write_text(json.dumps({"mae": 1.5, "mae_reliable": True}))
            _, mae = predict.load_regressor(reg, metrics)
            self.assertEqual(mae, 1.5)
        finally:
            metrics.unlink(missing_ok=True)
            reg.unlink(missing_ok=True)

    def test_band_boundaries(self):
        self.assertEqual(predict.remediation_band(0.1, 0.3, 0.6), "FAIBLE")
        self.assertEqual(predict.remediation_band(0.3, 0.3, 0.6), "MOYEN")
        self.assertEqual(predict.remediation_band(0.6, 0.3, 0.6), "ELEVE")


if __name__ == "__main__":
    unittest.main()
