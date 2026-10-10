"""
Improvement 3 - what KIND of malicious package is it?

DataDog only says "malicious intent" or "compromised library". We refine that with transparent
RULES on the package content. These types are our ESTIMATE (heuristic, not ground truth); they are
used to REPORT where the detector is strong or weak, never to train it.

Order matters: the first matching rule wins.
  empty_placeholder     almost no code and no install script (a squatted name, nothing inside)
  dependency_confusion  absurd version (999.9.9) or a tiny script that phones home with host info
  credential_stealer    reads secrets (env, ~/.ssh, tokens) AND talks to the network
  downloader_dropper    pipes a download into a shell / fetches from an unknown host at install time
  obfuscated_payload    hex-named identifiers, dynamic require/eval, very high entropy / long lines
  spam_farm             generated-looking name, no malicious behaviour in the code
  other_malicious       none of the above
"""
import math

import pandas as pd

TYPES = ["empty_placeholder", "dependency_confusion", "credential_stealer", "downloader_dropper",
         "obfuscated_payload", "spam_farm", "other_malicious"]


def _g(row, key, default=0.0):
    v = row.get(key)
    return default if v is None or (isinstance(v, float) and math.isnan(v)) else v


def assign_type(row) -> str:
    code_bytes = _g(row, "code_bytes")
    has_script = _g(row, "has_install_script") == 1

    if _g(row, "version_absurd_high") == 1:
        return "dependency_confusion"
    if code_bytes < 300 and not has_script:
        return "empty_placeholder"
    if _g(row, "hook_target_exfil_domain") > 0 and code_bytes < 4000 and _g(row, "n_code_files") <= 3:
        return "dependency_confusion"
    secret = _g(row, "hook_target_sensitive") + _g(row, "n_sensitive_path") + _g(row, "ast_secret_reads") \
        + _g(row, "hook_target_env")
    sink = _g(row, "hook_target_network") + _g(row, "n_network_module") + _g(row, "ast_network_calls") \
        + _g(row, "n_exfil_domain")
    if _g(row, "ast_source_and_sink_in_function") > 0 or (secret > 0 and sink > 0):
        return "credential_stealer"
    if _g(row, "hook_pipe_to_shell") == 1 or _g(row, "n_download_exec") > 0 \
            or (_g(row, "hook_url_unknown_host") > 0 and _g(row, "hook_known_build_tool") == 0):
        return "downloader_dropper"
    if _g(row, "n_obfuscator_ident") >= 5 or _g(row, "ast_dynamic_require") + _g(row, "ast_dynamic_eval") > 0 \
            or _g(row, "code_entropy") > 5.5 or _g(row, "pct_long_lines") > 0.2 or _g(row, "ast_hex_ident_ratio") > 0.05:
        return "obfuscated_payload"
    if _g(row, "name_spam_shape") == 1 or (_g(row, "name_tokens_with_digits") >= 1 and not has_script):
        return "spam_farm"
    return "other_malicious"


def add_types(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["mal_type"] = [assign_type(r) if r["label"] == 1 else "benign" for r in df.to_dict("records")]
    return df
