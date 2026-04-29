import orjson, os, shutil, subprocess, traceback
from fastcore.foundation import working_directory
from fastcore.test import expect_fail
from fastaudit.core import mk_audit
from os.path import join,realpath,expanduser


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

        # Non-stdlib native calls are blocked.
        with expect_fail(PermissionError): orjson.dumps({'a': 1})

        # Audit policy cannot be replaced from inside the sandbox.
        with expect_fail(PermissionError): mk_audit([expanduser('~')], monitor_calls=False)
        with expect_fail(PermissionError), permissive(): pass


def test_callbacks(tmp_path):
    def before_deny(event, args, frame, msg, data): return event=='subprocess.Popen' and args[1][:1]==['echo']
    def on_call(caller, callee, fn, code, off, data): return False if callee=='orjson.dumps' else None

    with mk_audit([tmp_path], before_deny=before_deny, on_call=on_call)():
        # Host callbacks can allow specific native calls…
        assert orjson.dumps({'a': 1}) == b'{"a":1}'
        # …and audit events
        res = subprocess.run(['echo', 'hi'], capture_output=True, text=True)
        assert res.stdout == 'hi\n'
        # Neighboring subprocess commands remain blocked.
        with expect_fail(PermissionError): subprocess.run(['ls'])


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
