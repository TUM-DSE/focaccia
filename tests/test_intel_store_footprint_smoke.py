"""Opt-in runtime regression: real extra-store evidence must be rejected.

FOCACCIA_FOOTPRINT_QEMU/FOCACCIA_FOOTPRINT_PLUGIN select the packaged binaries.
The separate probe preserves its JSON and optimized TCG logs beside --output.
"""
import os
from pathlib import Path
import runpy

import pytest


@pytest.mark.skipif(
    not (os.environ.get('FOCACCIA_FOOTPRINT_QEMU') and
         os.environ.get('FOCACCIA_FOOTPRINT_PLUGIN')),
    reason='packaged QEMU store-footprint runtime opt-in required',
)
def test_actual_unpredicted_store_rejected_by_live_helper(tmp_path, monkeypatch):
    probes = Path(__file__).parent / 'probes'
    monkeypatch.syspath_prepend(str(probes))
    probe = runpy.run_path(str(probes / 'intel_store_footprint_smoke.py'))
    result = probe['run'](
        os.environ['FOCACCIA_FOOTPRINT_QEMU'],
        os.environ['FOCACCIA_FOOTPRINT_PLUGIN'],
        tmp_path / 'store-footprint.json', True,
    )
    assert result['events'][1]['spans'] == [(0x402000, 1), (0x402001, 1)]
    assert result['unexpected_store_negative_control'] == (
        'unexpected actual store byte at 0x402001'
    )
