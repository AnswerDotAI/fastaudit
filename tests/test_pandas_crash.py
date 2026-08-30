import sys

import pytest
from fastcore.test import expect_fail


@pytest.mark.skip(reason='CPython 3.13 can segfault when a monitored CALL succeeds before a later invocation is denied')
def test_pandas_json_crash():
    import pandas as pd
    deny = False
    def call_cb(code, off, fn, arg0):
        if deny and getattr(fn, '__qualname__', '')=='ChunkedArray.to_numpy': raise PermissionError
    mon,tid = sys.monitoring,3
    mon.use_tool_id(tid, 'repro')
    mon.register_callback(tid, mon.events.CALL, call_cb)
    mon.set_events(tid, mon.events.CALL)
    df = pd.DataFrame({'a':[1]})
    def dump(): return df.to_json()
    try:
        dump()
        deny = True
        with expect_fail(PermissionError): dump()
    finally:
        mon.set_events(tid, 0)
        mon.register_callback(tid, mon.events.CALL, None)
        mon.free_tool_id(tid)
