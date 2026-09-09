import importlib.util

import pytest

from traceforge.evaluation.baseline_contract import ROOT


@pytest.fixture(scope="session")
def harness():
    spec = importlib.util.spec_from_file_location(
        "capture_harness", ROOT / "scripts/generate_cipherloop_baseline.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def captures(tmp_path_factory, harness):
    parent = tmp_path_factory.mktemp("capture")
    outputs = [parent / "first", parent / "second"]
    for output in outputs:
        harness.generate(ROOT.parent / "CipherLoop", output)
    return outputs


@pytest.fixture
def bundle(tmp_path, captures):
    import shutil

    shutil.copytree(captures[0], tmp_path / "bundle")
    return tmp_path / "bundle"
