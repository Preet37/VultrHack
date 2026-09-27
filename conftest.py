"""Pytest-wide setup.

Keep the suite deterministic and offline. A real ``VULTR_INFERENCE_API_KEY`` in
a local ``.env`` would otherwise make the finder and scan tests call *live* Vultr
Serverless Inference on every run -- slow, network-dependent, and
non-deterministic (triage confidence can vary run to run, so a confirmed-count
assertion could flake). Force the offline heuristic so every run exercises the
same deterministic path regardless of what is in the local ``.env``. The live
inference path is verified manually, not in unit tests.
"""

import pytest


@pytest.fixture(autouse=True)
def _force_offline_inference(monkeypatch):
    monkeypatch.setattr("finder.inference._load_inference_key", lambda: None)
