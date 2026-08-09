from pathlib import Path

from scripts.release_check import is_generated_release_path


def test_editable_install_metadata_is_not_release_source():
    assert is_generated_release_path(Path("src/openline_half_life.egg-info/PKG-INFO"))
    assert is_generated_release_path(Path("src/openline_half_life.egg-info/requires.txt"))
    assert not is_generated_release_path(Path("src/openline_half_life/pipeline.py"))
    assert not is_generated_release_path(Path("tests/test_pipeline.py"))
