from __future__ import annotations

import inspect
from openline_half_life import reference_replay


def test_reference_replay_does_not_import_compactor():
    source = inspect.getsource(reference_replay)
    assert "from .compaction" not in source
    assert "import compaction" not in source
