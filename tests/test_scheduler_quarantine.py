from pathlib import Path

import pytest

from focaccia.qemu.concurrency import (
    UnsupportedConcurrencyError,
    reject_thread_creating_effect,
    require_event_thread,
    require_single_inferior,
)
from focaccia.tools.validate_qemu import make_argparser


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_schedule_option_is_absent_from_supported_cli():
    parser = make_argparser()

    assert "--schedule" not in parser.format_help()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--symb-trace",
                "/tmp/trace",
                "--remote",
                "localhost:1234",
                "--schedule",
            ]
        )


def test_scheduler_prototype_is_preserved_only_in_experimental_namespace():
    prototype = PROJECT_ROOT / "src/focaccia/experimental/scheduler.py"

    assert prototype.is_file()
    text = prototype.read_text()
    assert "class PtraceSchedulerPrototype" in text
    assert "class GDBSchedulerPrototypeMixin" in text
    assert "experimental-scheduler" in text


def test_multiple_inferior_or_event_threads_fail_closed():
    require_single_inferior(0)
    require_single_inferior(1)
    require_event_thread(7, 7, context="test event")

    with pytest.raises(UnsupportedConcurrencyError, match="2 live threads"):
        require_single_inferior(2)
    with pytest.raises(UnsupportedConcurrencyError, match="0x7.*0x8"):
        require_event_thread(7, 8, context="test event")


def test_thread_creating_effect_fails_closed():
    with pytest.raises(UnsupportedConcurrencyError, match="clone.*another task"):
        reject_thread_creating_effect("clone")
