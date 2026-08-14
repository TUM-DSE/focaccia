"""Disabled compatibility stub for the quarantined scheduler prototype.

The preserved implementation now lives in ``focaccia.experimental.scheduler``.
It is intentionally not imported here because normal project environments do
not install the experimental ptrace dependency.
"""


def main() -> None:
    raise RuntimeError(
        "The scheduler prototype is quarantined and has no supported entry point."
    )


if __name__ == "__main__":
    main()
