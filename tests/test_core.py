import asyncio, contextvars, fastaudit.core as core, importlib, nbformat, numpy as np, orjson, os, pytest, regex, shutil, subprocess, sys, tempfile, threading, traceback
from exhash import file_exhash
from exhash.exhash import line_hash as native_line_hash
from fastcore.basics import Self
from fastcore.foundation import working_directory
from fastcore.test import expect_fail
from fastaudit.core import active_calls,audit_state,mk_audit,track_call
from functools import lru_cache,partial
from importlib.metadata import EntryPoint,entry_points


@pytest.fixture(scope='session', autouse=True)
def _pin_entrypoints():
    "Pin entry points before the irreversible process-wide hook is installed."
    groups = dict(fastaudit_safe_native=('_regex','numpy','orjson','rpds','regex._regex'), fastaudit_import_allow=('entry_import_ok',),
        fastaudit_monitor_hook=('fastaudit.hooks:lxml_monitor',), fastaudit_audit_hook=('test_core:allow_test_audit_event',))
    core.entry_points = lambda group: tuple(EntryPoint(v, v, group) for v in groups.get(group, ()))
    yield
    core.entry_points = entry_points

def allow_test_audit_event(event, args, frame, msg, data, calls): return event=='fastaudit.test_hook' and args==('ok',)
def echo(msg='hi'): return subprocess.run(['echo', msg], capture_output=True, text=True).stdout

def denial(fn, *args):
    with pytest.raises(PermissionError) as exc: fn(*args)
    return exc.value


def test_filesystem_scope(tmp_path, monkeypatch):
    allowed,cwd,outside = tmp_path/'allowed',tmp_path/'cwd',tmp_path/'outside.txt'
    allowed.mkdir()
    (cwd/'child').mkdir(parents=True)
    outside.write_text('outside')
    monkeypatch.setenv('HOME', str(tmp_path))
    audit = mk_audit(('~/allowed','.'), monitor_calls=False)
    permissive = mk_audit(None, monitor_calls=False)
    inside = allowed/'inside.txt'

    with working_directory(cwd), audit():
        assert outside.read_text() == 'outside'
        fd = os.open(outside, os.O_RDONLY)
        os.close(fd)
        with expect_fail(PermissionError): os.open(outside, os.O_WRONLY)
        with expect_fail(PermissionError): outside.unlink()
        shutil.copyfile(outside, inside)
        with expect_fail(PermissionError): shutil.copyfile(inside, outside)
        with expect_fail(PermissionError): outside.rename(allowed/'moved.txt')
        with expect_fail(PermissionError): inside.rename(outside)
        assert inside.read_text() == outside.read_text() == 'outside'
        inside.unlink()

        # NamedTemporaryFile audits the directory itself; ordinary writes check its parent.
        with tempfile.NamedTemporaryFile(dir=allowed) as f: f.write(b'x')
        with tempfile.TemporaryFile(dir=allowed) as f: f.write(b'x')
        with expect_fail(PermissionError): tempfile.NamedTemporaryFile(dir=tmp_path)
        (cwd/'local.txt').write_text('local')
        with expect_fail(PermissionError): (cwd/'../sibling.txt').write_text('no')
        os.chdir('child')
        (cwd/'child/nested.txt').write_text('nested')
        with expect_fail(PermissionError): os.chdir(tmp_path)

        err = denial(echo)
        assert 'subprocess.Popen blocked in sandbox' in str(err) and 'Audit context entered' not in str(err)
        assert not any(f.filename.endswith('fastaudit/core.py') for f in traceback.extract_tb(err.__traceback__))
        with expect_fail(PermissionError): mk_audit(None, monitor_calls=False)
        with expect_fail(PermissionError), permissive(): pass

    assert outside.read_text() == 'outside' and (cwd/'child/nested.txt').read_text() == 'nested'
    outside.write_text('host')
    assert echo() == 'hi\n'


def test_native_enforcement(tmp_path):
    from lxml import etree
    notebook = tmp_path/'test.ipynb'
    nbformat.write(nbformat.v4.new_notebook(cells=[nbformat.v4.new_code_cell('1+1')]), notebook)
    with mk_audit([tmp_path])():
        def f(): pass
        with expect_fail(PermissionError, 'object.__setattr__ blocked in sandbox'): f.__code__ = f.__code__
        class Plain: pass
        class PyCallable:
            def __call__(self): return 'ok'
        class MyList(list):
            def append(self, x): super().append(x)
        assert isinstance(Plain(), Plain) and PyCallable()() == 'ok'
        ml = MyList()
        ml.append(1)
        assert ml == [1]
        s = Self.split(',')
        state = vars(s).copy()
        assert (~s)('a,b') == ['a', 'b'] and vars(s) == state
        @lru_cache(maxsize=8)
        def cached(): return 'ok'
        assert cached() == partial(cached)() == 'ok'

        assert orjson.dumps({'a': 1}) == b'{"a":1}'
        assert np.array([1, 2, 3]).sum() == 6 and regex.compile('a').match('a')
        assert nbformat.read(notebook, as_version=4).cells[0].source == '1+1'
        xml = etree.fromstring(b'<root><x>1</x></root>')
        tree = etree.ElementTree(xml)
        style = etree.XML(b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>')
        assert xml.find('x').text == '1'
        with expect_fail(PermissionError, 'lxml.etree._ElementTree.write'): tree.write('lxml-write.xml')
        with expect_fail(PermissionError, 'lxml.etree._ElementTree.write_c14n'): tree.write_c14n('lxml-c14n.xml')
        with expect_fail(PermissionError, 'lxml.etree.xmlfile'): etree.xmlfile('lxml-file.xml')
        with expect_fail(PermissionError, 'lxml.etree._XSLTResultTree.write_output'): etree.XSLT(style)(xml).write_output('lxml-xslt.xml')
        with expect_fail(PermissionError, 'exhash.file_exhash -> exhash.exhash.edit_files'): file_exhash('exhash.txt', ('0|AA|', 'a', 'x'), inplace=True)
        with expect_fail(PermissionError): partial(native_line_hash, 'x')()


def test_host_policy_transitions(tmp_path):
    def trusted_echo(): return echo()
    def before_deny(event, args, frame, msg, data, calls):
        if event=='subprocess.Popen' and args[1][:1]==['echo']:
            while frame:
                if frame.f_code in data: return True
                frame = frame.f_back
        return event=='fastaudit.ddl' and args==('ok',) or event=='os.putenv' and os.fsdecode(args[0])=='PATH'
    def on_call(caller, callee, fn, code, off, data, calls):
        if callee.startswith('exhash.'): return sys.monitoring.DISABLE

    audit = mk_audit([tmp_path], before_deny=before_deny, on_call=on_call, data=frozenset((trusted_echo.__code__,)))
    with audit():
        f = tmp_path/'exhash.txt'
        file_exhash(str(f), ('0|AA|', 'a', 'x'), inplace=True)
        assert f.read_text().strip() == 'x'
        sys.audit('gc.get_objects', 0)
        sys.audit('fastaudit.test_hook', 'ok')
        sys.audit('fastaudit.ddl', 'ok')
        with expect_fail(PermissionError): sys.audit('fastaudit.dml', 'delete')
        os.putenv('FASTAUDIT_ENV_OK', '1')
        os.unsetenv('FASTAUDIT_ENV_OK')
        with expect_fail(PermissionError): os.putenv('PYTHONPATH', 'x')
        os.putenv('PATH', os.environ.get('PATH', ''))
        assert trusted_echo() == 'hi\n'
        with expect_fail(PermissionError): echo()
        with expect_fail(PermissionError): subprocess.run(['ls'])
        with expect_fail(PermissionError): audit.set_data(frozenset())
    audit.set_data(frozenset())
    with audit():
        with expect_fail(PermissionError): trusted_echo()


def test_trusted_import_lifecycle(tmp_path, monkeypatch):
    for nm in ('entry_import_ok','runtime_import_ok','blocked_import'):
        (tmp_path/f'{nm}.py').write_text('def f(): pass\nf.__code__ = f.__code__\ndef mutate(): f.__code__ = f.__code__\n')
    def import_mod(nm):
        sys.modules.pop(nm, None)
        importlib.invalidate_caches()
        return importlib.import_module(nm)
    monkeypatch.syspath_prepend(str(tmp_path))
    with mk_audit([tmp_path])():
        mod = import_mod('entry_import_ok')
        assert mod.f() is None
        with expect_fail(PermissionError): mod.mutate()
        with expect_fail(PermissionError): import_mod('blocked_import')
    audit = mk_audit([tmp_path], allow_imports=('runtime_import_ok',), monitor_calls=False)
    with audit():
        assert import_mod('runtime_import_ok').f() is None
        with expect_fail(PermissionError): audit.add_imports('blocked_import')
    audit.add_imports('blocked_import')
    with audit(): assert import_mod('blocked_import').f() is None


def test_context_lifecycles(tmp_path):
    audit = mk_audit([tmp_path])
    audit_only = mk_audit([tmp_path], monitor_calls=False)
    tid = audit_state()['tool_id']
    assert sys.monitoring.get_events(tid) == 0
    with audit():
        assert sys.monitoring.get_events(tid) == sys.monitoring.events.CALL
        with audit():
            with expect_fail(PermissionError): echo()
        with expect_fail(PermissionError): echo()
        with expect_fail(PermissionError): native_line_hash('x')
        assert sys.monitoring.get_events(tid) == sys.monitoring.events.CALL
    assert sys.monitoring.get_events(tid) == 0 and echo() == 'hi\n'
    with expect_fail(RuntimeError): mk_audit([tmp_path], on_call=lambda *args: None, monitor_calls=False)
    with audit_only():
        assert sys.monitoring.get_events(tid) == 0 and native_line_hash('x')
        with expect_fail(PermissionError): echo()
        snap = contextvars.copy_context()
    errors = []
    thread = threading.Thread(target=lambda: errors.append(str(snap.run(denial, echo))))
    thread.start()
    thread.join(timeout=2)
    assert errors and 'Audit context entered in thread' in errors[0]
    assert 'test_context_lifecycles' in errors[0].split('Audit context entered')[1]

    async def run():
        wait = asyncio.Event()
        async def plain_echo(): return echo()
        async def inherited_context():
            await wait.wait()
            return str(denial(echo)),active_calls()
        @track_call
        async def trusted_echo(msg, loud=False):
            task = asyncio.create_task(inherited_context())
            return echo(msg.upper() if loud else msg),task
        def before_deny(event, args, frame, msg, data, calls):
            return event=='subprocess.Popen' and any(c.qualname.endswith('trusted_echo') and c.args==('hi',) and c.kwargs=={'loud':True}
                for c in calls)
        unrestricted = asyncio.create_task(plain_echo())
        with mk_audit([tmp_path], before_deny=before_deny)():
            assert await unrestricted == 'hi\n'
            assert await asyncio.get_running_loop().run_in_executor(None, lambda: 'ok') == 'ok'
            out,task = await trusted_echo('hi', loud=True)
            assert out == 'HI\n' and active_calls() == ()
            with expect_fail(PermissionError): echo()
        wait.set()
        msg,calls = await task
        assert calls == () and 'Audit context entered in thread' in msg
    asyncio.run(run())
