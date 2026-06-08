import asyncio, importlib, nbformat, numpy as np, orjson, os, pytest, regex, shutil, subprocess, sys, traceback
from exhash import exhash_file
from exhash.exhash import line_hash as native_line_hash
from fastcore.basics import Self
from fastcore.foundation import working_directory
from fastcore.test import expect_fail
from fastaudit.core import active_calls,audit_state,mk_audit,track_call
from functools import lru_cache,partial
from lxml import etree
from os.path import join,realpath,expanduser


@pytest.fixture(scope='session', autouse=True)
def _safe_native_entrypoints(tmp_path_factory):
    p = tmp_path_factory.mktemp('safe_native')/'safe-0.dist-info'
    p.mkdir()
    (p/'entry_points.txt').write_text("""[fastaudit_safe_native]
_regex = _regex
numpy = numpy
orjson = orjson
rpds = rpds
regex_regex = regex._regex
[fastaudit_monitor_hook]
lxml = fastaudit.hooks:lxml_monitor
[fastaudit_audit_hook]
test_core = test_core:allow_test_audit_event
[fastaudit_import_allow]
entry_import_ok = entry_import_ok
""")
    sys.path.insert(0, str(p.parent))
    yield
    sys.path.remove(str(p.parent))

def touch(p, s='x'):
    with open(p, 'w') as f: f.write(s)

def allow_test_audit_event(event, args, frame, msg, data, calls): return event=='fastaudit.test_hook' and args==('ok',)

def test_audit_blocks(tmp_path):
    start = os.getcwd()
    dotdest = tmp_path/'dotdest'
    okdest = tmp_path/'okdest'
    (dotdest/'child').mkdir(parents=True)
    okdest.mkdir()
    okdest = realpath(okdest)
    inside = join(okdest, 'audit-test.txt')
    inside2 = join(okdest, 'audit-test-2.txt')
    inside3 = join(okdest, 'audit-test-3.txt')
    outside = expanduser('~/audit-test-outside.txt')
    permissive = mk_audit([expanduser('~')], monitor_calls=False)

    with working_directory(dotdest), mk_audit((okdest,'.'))():
        # Sensitive function mutation is blocked.
        def f(): pass
        with expect_fail(PermissionError): f.__code__ = f.__code__

        # Reads outside approved roots are allowed.
        open('/etc/passwd', 'r').close()
        fd = os.open('/etc/passwd', os.O_RDONLY)
        os.close(fd)

        # Writes and deletes outside approved roots are blocked.
        with expect_fail(PermissionError): os.open(outside, os.O_WRONLY)
        with expect_fail(PermissionError): os.remove(outside)

        # Copy destinations must stay inside approved roots.
        shutil.copyfile('/etc/passwd', inside)
        with expect_fail(PermissionError): shutil.copyfile(inside, outside)
        os.remove(inside)

        # Renames touching unapproved roots, and subprocesses, are blocked.
        touch(inside2)
        with expect_fail(PermissionError): os.rename(outside, inside3)
        with expect_fail(PermissionError): os.rename(inside2, outside)
        os.remove(inside2)
        with expect_fail(PermissionError, 'Audit: subprocess.Popen blocked in sandbox\nCall chain:'): subprocess.run(['echo', 'hi'])

        # "." allows writes under the current directory and chdir checks the destination.
        touch('dot-inside.txt')
        touch('child/nested.txt')
        with expect_fail(PermissionError): touch('../sibling.txt')
        with expect_fail(PermissionError): os.chdir(start)

        # fastaudit frames are removed from tracebacks.
        try: subprocess.run(['echo', 'hi'])
        except PermissionError as e: frames = traceback.extract_tb(e.__traceback__)
        assert not [f for f in frames if f.filename.endswith('fastaudit/core.py')]

        # Python classes and callable instances are not treated as native calls.
        class Plain: pass
        class PyCallable:
            def __init__(self): super().__init__()
            def __call__(self): return 'ok'
        assert isinstance(Plain(), Plain)
        assert PyCallable()() == 'ok'
        # fastcore.Self mutates in __getattr__, which call monitoring must not trigger.
        s = Self.split(',')
        state = vars(s).copy()
        assert s('a,b') == ['a', 'b']
        assert vars(s) == state
        @lru_cache(maxsize=8)
        def cached(): return 'ok'
        assert cached() == 'ok'
        assert partial(cached)() == 'ok'

        # Safe native entry points are allowed; unlisted native calls are blocked.
        assert 'numpy' in audit_state()['safe_native']
        assert orjson.dumps({'a': 1}) == b'{"a":1}'
        assert np.array([1, 2, 3]).sum() == 6
        assert regex.compile('a').match('a')
        # Packaged monitor hooks can allow safe native calls while preserving known writer blocks.
        xml = etree.fromstring(b'<root><x>1</x></root>')
        tree = etree.ElementTree(xml)
        style = etree.XML(b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out/></xsl:template></xsl:stylesheet>')
        assert xml.find('x').text == '1'
        with expect_fail(PermissionError, 'lxml.etree._ElementTree.write'): tree.write('lxml-write.xml')
        with expect_fail(PermissionError, 'lxml.etree._ElementTree.write_c14n'): tree.write_c14n('lxml-c14n.xml')
        with expect_fail(PermissionError, 'lxml.etree.xmlfile'): etree.xmlfile('lxml-file.xml')
        with expect_fail(PermissionError, 'lxml.etree._XSLTResultTree.write_output'): etree.XSLT(style)(xml).write_output('lxml-xslt.xml')
        with expect_fail(PermissionError, 'test_core.test_audit_blocks -> exhash.exhash_file -> exhash._apply_file_command -> exhash.exhash -> exhash.exhash.exhash'): exhash_file('exhash.txt', ['0|0000|a\nx'], inplace=True)
        with expect_fail(PermissionError): partial(native_line_hash, 'x')()

        # Audit policy cannot be replaced from inside the sandbox.
        with expect_fail(PermissionError): mk_audit([expanduser('~')], monitor_calls=False)
        with expect_fail(PermissionError), permissive(): pass



def test_expanduser_allowed_path(tmp_path, monkeypatch):
    home = tmp_path/'home'
    allowed = home/'allowed'
    allowed.mkdir(parents=True)
    monkeypatch.setenv('HOME', str(home))
    target = allowed/'audit-path-test.txt'

    with mk_audit(('~/allowed',), monitor_calls=False)(): touch(target)

    assert target.read_text() == 'x'
def test_callbacks(tmp_path):
    def before_deny(event, args, frame, msg, data, calls): return event=='subprocess.Popen' and args[1][:1]==['echo'] or event=='fastaudit.ddl' and args==('ok',)
    def on_call(caller, callee, fn, code, off, data, calls):
        if callee.startswith('exhash.'): return sys.monitoring.DISABLE

    with mk_audit([tmp_path], before_deny=before_deny, on_call=on_call)():
        # Host callbacks can allow native calls beyond the entry-point allowlist.
        f = tmp_path/'exhash.txt'
        exhash_file(str(f), ['0|0000|a\nx'], inplace=True)
        assert f.read_text() == 'x\n'
        # Host callbacks can also allow unknown or package-provided audit events.
        sys.audit('gc.get_objects', 0)
        sys.audit('fastaudit.test_hook', 'ok')
        sys.audit('fastaudit.ddl', 'ok')
        with expect_fail(PermissionError): sys.audit('fastaudit.dml', 'delete')

        # Host callbacks can allow audit events.
        res = subprocess.run(['echo', 'hi'], capture_output=True, text=True)
        assert res.stdout == 'hi\n'
        # Neighboring subprocess commands remain blocked.
        with expect_fail(PermissionError): subprocess.run(['ls'])


def test_allowed_import_side_effects(tmp_path):
    def write_mod(nm): (tmp_path/f'{nm}.py').write_text('def f(): pass\nf.__code__ = f.__code__\n')
    def import_mod(nm):
        sys.modules.pop(nm, None)
        importlib.invalidate_caches()
        return importlib.import_module(nm)
    for nm in ('entry_import_ok','runtime_import_ok','blocked_import'): write_mod(nm)

    sys.path.insert(0, str(tmp_path))
    try:
        with mk_audit([tmp_path])():
            # Import-allow entry points cover trusted import-time side effects.
            assert import_mod('entry_import_ok').f() is None
            with expect_fail(PermissionError): import_mod('blocked_import')

        audit_perms = mk_audit([tmp_path], allow_imports=('runtime_import_ok',), monitor_calls=False)
        with audit_perms():
            # Runtime import allowances can be extended outside the sandbox.
            assert import_mod('runtime_import_ok').f() is None
            with expect_fail(PermissionError): audit_perms.add_imports('blocked_import')
        audit_perms.add_imports('blocked_import')
        with audit_perms(): assert import_mod('blocked_import').f() is None
    finally: sys.path.remove(str(tmp_path))


def test_call_tracker(tmp_path):
    def sync_tool(): return 'ok'
    assert track_call(sync_tool) is sync_tool

    async def run():
        wait = asyncio.Event()
        async def inherited_context():
            await wait.wait()
            return active_calls()

        @track_call
        async def trusted_echo(msg, loud=False):
            task = asyncio.create_task(inherited_context())
            res = subprocess.run(['echo', msg.upper() if loud else msg], capture_output=True, text=True)
            return res,task

        def before_deny(event, args, frame, msg, data, calls):
            return event=='subprocess.Popen' and any(c.qualname.endswith('trusted_echo') and c.args==('hi',) and c.kwargs=={'loud':True}
                for c in calls)

        with mk_audit([tmp_path], before_deny=before_deny)():
            # Asyncio can lazily create its default executor thread inside DNS/file helpers.
            assert await asyncio.get_running_loop().run_in_executor(None, lambda: 'ok') == 'ok'

            # Active calls can drive policy across async frames without stack walking.
            res,task = await trusted_echo('hi', loud=True)
            assert res.stdout == 'HI\n'
            with expect_fail(PermissionError): subprocess.run(['echo', 'hi'])

            # Finished calls copied into child tasks are ignored.
            assert active_calls() == ()
            wait.set()
            assert await task == ()

    asyncio.run(run())


def test_nbformat_read(tmp_path):
    p = tmp_path/'test.ipynb'
    p.write_text('{"cells":[{"cell_type":"code","execution_count":null,"id":"x","metadata":{},"outputs":[],"source":"1+1"}],"metadata":{},"nbformat":4,"nbformat_minor":5}')
    with mk_audit([tmp_path])():
        # Native dependencies can declare safe call prefixes through entry points.
        assert nbformat.read(str(p), as_version=4).cells[0].source == '1+1'


def test_monitor_calls_can_be_disabled(tmp_path):
    with expect_fail(RuntimeError): mk_audit([tmp_path], on_call=lambda *args: None, monitor_calls=False)
    with mk_audit([tmp_path], monitor_calls=False)():
        # Audit-hook checks still run without native call monitoring.
        with expect_fail(PermissionError): subprocess.run(['echo', 'hi'])
        assert orjson.dumps({'a': 1}) == b'{"a":1}'


def test_implement_allow_list(tmp_path):
    "A brief demo of creating an `allow()` system"
    def trusted_echo(): return subprocess.run(['echo', 'hi'], capture_output=True, text=True)

    allowed = set()
    def allow(fn): allowed.add(f'{fn.__module__}.{fn.__qualname__}')
    allow(trusted_echo)

    def before_deny(event, args, frame, msg, data, calls):
        while frame:
            if f"{frame.f_globals.get('__name__')}.{frame.f_code.co_qualname}" in data: return True
            frame = frame.f_back

    audit_perms = mk_audit([tmp_path], before_deny=before_deny, data=frozenset(allowed))
    with audit_perms():
        # A callback can implement frame-based tool allowance.
        assert trusted_echo().stdout == 'hi\n'
        with expect_fail(PermissionError): subprocess.run(['echo', 'hi'])
        # Callback data cannot be replaced from inside the sandbox.
        with expect_fail(PermissionError): audit_perms.set_data(frozenset())

    # Trusted host code can update callback data between sandboxed runs.
    audit_perms.set_data(frozenset())
    with audit_perms():
        with expect_fail(PermissionError): trusted_echo()
