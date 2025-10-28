"""Parsing of JSON files containing snapshot data."""

import os
from typing import Union

import brotli

try:
    import capnp
    rr_trace = capnp.load(file_name='./rr/src/rr_trace.capnp',
                          imports=[os.path.dirname(p) for p in capnp.__path__])
except Exception as e:
    print(f'Cannot load RR trace loader: {e}')
    exit(2)

Frame = rr_trace.Frame
TaskEvent = rr_trace.TaskEvent
MMap = rr_trace.MMap
SerializedObject = Union[Frame, TaskEvent, MMap]

class DeterministicLog:
    def __init__(self, log_dir: str):
        self.base_directory = log_dir

    def events_file(self) -> str:
        return os.path.join(self.base_directory, 'events')

    def tasks_file(self) -> str:
        return os.path.join(self.base_directory, 'tasks')

    def mmaps_file(self) -> str:
        return os.path.join(self.base_directory, 'mmaps')

    def _read(self, file, obj: SerializedObject) -> list[SerializedObject]:
        with open(file, 'rb') as f:
            f.read(8)
            data = brotli.decompress(f.read())
            return obj.read_multiple_bytes_packed(data)

    def events(self):
        return self._read(self.events_file(), Frame)

    def tasks(self):
        return self._read(self.tasks_file(), TaskEvent)

    def mmaps(self):
        return self._read(self.mmaps_file(), MMap)

