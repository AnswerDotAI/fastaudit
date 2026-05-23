import nbformat, numpy as np, orjson, os, pytest, regex, shutil, subprocess, sys, traceback
from exhash import exhash_file
from fastcore.foundation import working_directory
from fastcore.test import expect_fail
from fastaudit.core import audit_state,mk_audit
from os.path import join,realpath,expanduser


@pytest.fixture(scope='session', autouse=True)
def _safe_native_entrypoints(tmp_path_factory):
    p = tmp_path_factory.mktemp('safe_native')/'safe-0.dist-info'
    p.mkdir()
    (p/'entry_points.txt').write_text('[fastaudit_safe_native]\n_regex = _regex\nnumpy = numpy\norjson = orjson\nrpds = rpds\nregex_regex = regex._regex\n')
    sys.path.insert(0, str(p.parent))
    yield
    sys.path.remove(str(p.parent))

def touch(p, s='x'):
    with open(p, 'w') as f: f.write(s)

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
        with expect_fail(PermissionError): subprocess.run(['echo', 'hi'])

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
        class PyCallable:
            def __init__(self): super().__init__()
            def __call__(self): return 'ok'
        assert PyCallable()() == 'ok'

        # Safe native entry points are allowed; unlisted native calls are blocked.
        assert 'numpy' in audit_state()['safe_native']
        assert orjson.dumps({'a': 1}) == b'{"a":1}'
        assert np.array([1, 2, 3]).sum() == 6
        assert regex.compile('a').match('a')
        with expect_fail(PermissionError): exhash_file('exhash.txt', ['0|0000|a\nx'], inplace=True)

        # Audit policy cannot be replaced from inside the sandbox.
        with expect_fail(PermissionError): mk_audit([expanduser('~')], monitor_calls=False)
        with expect_fail(PermissionError), permissive(): pass


def test_callbacks(tmp_path):
    def before_deny(event, args, frame, msg, data): return event=='subprocess.Popen' and args[1][:1]==['echo'] or event=='fastaudit.ddl' and args==('ok',)
    def on_call(caller, callee, fn, code, off, data):
        if callee.startswith('exhash.'): return sys.monitoring.DISABLE

    with mk_audit([tmp_path], before_deny=before_deny, on_call=on_call)():
        # Host callbacks can allow native calls beyond the entry-point allowlist.
        f = tmp_path/'exhash.txt'
        exhash_file(str(f), ['0|0000|a\nx'], inplace=True)
        assert f.read_text() == 'x\n'
        # Host callbacks can also allow unknown or package-provided audit events.
        sys.audit('http.client.connect', None, 'example.com', 80)
        sys.audit('fastaudit.ddl', 'ok')
        with expect_fail(PermissionError): sys.audit('fastaudit.dml', 'delete')

        # Host callbacks can allow audit events.
        res = subprocess.run(['echo', 'hi'], capture_output=True, text=True)
        assert res.stdout == 'hi\n'
        # Neighboring subprocess commands remain blocked.
        with expect_fail(PermissionError): subprocess.run(['ls'])


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

    def before_deny(event, args, frame, msg, data):
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
