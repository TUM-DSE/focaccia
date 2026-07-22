from hashlib import sha256

import pytest

from focaccia.utils import file_hash


def test_file_hash_uses_a_fresh_algorithm_for_every_call(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first payload")
    second.write_bytes(b"second payload")

    expected_first = sha256(first.read_bytes()).hexdigest()
    expected_second = sha256(second.read_bytes()).hexdigest()

    assert file_hash(first) == expected_first
    assert file_hash(second) == expected_second
    assert file_hash(first) == expected_first


def test_file_hash_rejects_nonpositive_chunk_sizes(tmp_path):
    data = tmp_path / "data.bin"
    data.write_bytes(b"payload")

    with pytest.raises(ValueError, match="positive"):
        file_hash(data, chunksize=0)
