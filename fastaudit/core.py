import os, sys
from fastcore.utils import *
from collections import namedtuple
from contextlib import contextmanager
from contextvars import ContextVar

_audit_1st = {'os.chmod','os.chown','os.chflags','os.mkdir','os.remove','os.removexattr','os.rmdir','os.setxattr',
    'shutil.chown','shutil.make_archive','shutil.rmtree','sqlite3.connect','tempfile.mkdtemp','tempfile.mkstemp'}
_audit_dst = {'shutil.copyfile','shutil.copymode','shutil.copystat','shutil.copytree','sqlite3.load_extension'}
_audit_both = {'os.link','os.rename','os.symlink','shutil.move','shutil.unpack_archive'}

_audit_proc = {'subprocess.Popen','os.system','os.exec','os.spawn','os.posix_spawn','os.startfile','os.startfile/2',
    'os.kill','os.killpg','pty.spawn','_posixsubprocess.fork_exec','signal.pthread_kill'}
_audit_runtime = {'sys.addaudithook','sys.excepthook','sys.unraisablehook','sys.monitoring.register_callback',
    'cpython.PyConfig_Set','cpython.PyInterpreterState_Clear','cpython.PyInterpreterState_New','cpython._PySys_ClearAuditHooks',
    'cpython.run_command','cpython.run_file','cpython.run_module','cpython.run_stdin','cpython.run_startup',
    'cpython.remote_debugger_script','sys.remote_exec','socket.sethostname','os.add_dll_directory','os.putenv','os.unsetenv',
    '_thread.start_new_thread','_thread.start_joinable_thread'}
_audit_ctypes = {'ctypes.dlopen','ctypes.dlsym','ctypes.dlsym/handle','ctypes.call_function','ctypes.cdata','ctypes.cdata/buffer',
    'ctypes.memoryview_at','ctypes.string_at','ctypes.wstring_at','ctypes.addressof','ctypes.PyObj_FromPtr'}
_audit_win = {'_winapi.CreateFile','_winapi.CreateProcess','_winapi.OpenProcess','_winapi.TerminateProcess','_winapi.CreateJunction',
    '_winapi.CreateNamedPipe','_winapi.CreatePipe','msvcrt.locking','msvcrt.get_osfhandle','msvcrt.open_osfhandle',
    'winreg.CreateKey','winreg.DeleteKey','winreg.DeleteValue','winreg.SetValue','winreg.LoadKey','winreg.SaveKey',
    'winreg.DisableReflectionKey','winreg.EnableReflectionKey'}
_audit_deny = _audit_proc|_audit_runtime|_audit_ctypes|_audit_win
_AuditCfg = namedtuple('AuditCfg', 'oks before_deny on_call data monitor_calls')
_state_attr = '_fastaudit_state'


def _new_state():
    ctx = ContextVar('fastaudit_cfg', default=None)
    write_flags = os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND
    audit_1st,audit_dst,audit_both = map(frozenset, (_audit_1st,_audit_dst,_audit_both))
    audit_deny = frozenset(_audit_deny|{'fastaudit.call','audit_perms.set_config','audit_perms.set_data'})
    audit_all = audit_deny|audit_1st|audit_dst|audit_both|{'open','os.chdir','os.truncate','object.__setattr__'}
    realpath,dirname,fsdecode,sep,getframe = os.path.realpath,os.path.dirname,os.fsdecode,os.sep,sys._getframe
    mon,audit,stdlib = getattr(sys, 'monitoring', None),sys.audit,frozenset(sys.stdlib_module_names)
    state = {'tool_id':None}

    def frame_name(f): return f"{f.f_globals.get('__name__')}.{f.f_code.co_qualname}"

    def owner_mod(fn, obj):
        "Find inherited C method owners, e.g. NotebookNode.get -> dict.get."
        nm = getattr(fn, '__name__', None)
        if not nm: return
        for cls in type(obj).__mro__:
            if nm in cls.__dict__: return getattr(cls, '__module__', None)

    def func_mod(fn):
        mod = getattr(fn, '__module__', None)
        cls = getattr(fn, '__objclass__', None)
        if not mod and cls is not None: mod = getattr(cls, '__module__', None)
        s = getattr(fn, '__self__', None)
        if not mod and s is not None: mod = owner_mod(fn, s) or getattr(type(s), '__module__', None)
        return mod

    def func_name(fn):
        mod = func_mod(fn)
        nm = getattr(fn, '__qualname__', getattr(fn, '__name__', None))
        return f'{mod}.{nm}' if mod and nm else None

    def is_stdlib(fn):
        mod = func_mod(fn)
        return bool(mod) and mod.split('.', 1)[0] in stdlib

    def callee_is_python(fn):
        if hasattr(fn, '__code__') or isinstance(fn, type): return True
        return hasattr(getattr(type(fn), '__call__', None), '__code__')

    def external_frame():
        f = getframe()
        while f:
            if not frame_name(f).startswith('fastaudit.'): return f
            f = f.f_back

    def deny(cfg, event, args, msg):
        if cfg.before_deny and cfg.before_deny(event, args, external_frame(), msg, cfg.data): return
        raise PermissionError(msg)

    def ok_path(cfg, p, parent=False):
        try:
            p = fsdecode(p)
            if parent: p = dirname(p) or '.'
            rp = realpath(p or '.')
        except (OSError,TypeError,ValueError): return False
        cur = realpath('.')
        return any(rp==(cur if o=='.' else o) or rp.startswith((cur if o=='.' else o)+sep) for o in cfg.oks)

    def chk(cfg, event, args):
        if event not in audit_all: return
        errstr = f"Audit: {event} blocked in sandbox with args: {args}"
        if event in audit_deny: return deny(cfg, event, args, errstr)
        if event=='object.__setattr__':
            if args[1] in ('__defaults__', '__doc__','__module__'): return
            return deny(cfg, event, args, errstr)
        ps = []
        if event=='open':
            path,mode,flags = args
            if isinstance(mode,str) and not set('wax+') & set(mode): return
            if mode is None and not flags & write_flags: return
            ps = [path]
        elif event=='os.chdir':
            if not ok_path(cfg, args[0]): return deny(cfg, event, args, f"{event} {args[0]!r} not in {cfg.oks}")
            return
        elif event=='os.truncate':
            if isinstance(args[0],int): return
            ps = [args[0]]
        elif event in audit_1st: ps = [args[0]]
        elif event in audit_dst: ps = [args[1]]
        elif event in audit_both: ps = args[:2]
        for p in ps:
            if not ok_path(cfg, p, parent=True): deny(cfg, event, args, f"{event} {p!r} not in {cfg.oks}")

    def hook(event, args):
        cfg = ctx.get()
        if cfg is None: return
        try: chk(cfg, event, args)
        except PermissionError as e:
            e.__traceback__ = None
            raise

    def call_cb(code, off, fn, arg0):
        if code is call_cb.__code__ or callee_is_python(fn) or is_stdlib(fn): return mon.DISABLE
        cfg = ctx.get()
        if cfg is None or not cfg.monitor_calls: return
        caller,callee = frame_name(getframe(1)),func_name(fn)
        if not callee: return
        if cfg.on_call:
            res = cfg.on_call(caller, callee, fn, code, off, cfg.data)
            if res is mon.DISABLE: return mon.DISABLE
            if res is False: return
        try: audit('fastaudit.call', caller, callee)
        except PermissionError as e:
            e.__traceback__ = None
            raise

    def install_call_monitor(tool_id):
        if not mon: raise RuntimeError('monitor_calls=True requires Python 3.12+ sys.monitoring')
        if (old:=state['tool_id']) is not None:
            if old!=tool_id: raise RuntimeError(f'fastaudit already uses sys.monitoring tool id {old}')
            return
        if (tool:=mon.get_tool(tool_id)) == 'fastaudit':
            mon.set_events(tool_id, 0)
            mon.register_callback(tool_id, mon.events.CALL, None)
            mon.free_tool_id(tool_id)
        elif tool: raise RuntimeError(f'sys.monitoring tool id {tool_id} is already used by {tool!r}')
        mon.use_tool_id(tool_id, 'fastaudit')
        mon.register_callback(tool_id, mon.events.CALL, call_cb)
        mon.set_events(tool_id, mon.events.CALL)
        state['tool_id'] = tool_id

    def mk_audit_(oks, before_deny=None, on_call=None, data=None, tool_id=3, monitor_calls=True):
        audit('audit_perms.set_config', oks)
        if on_call and not monitor_calls: raise RuntimeError('on_call requires monitor_calls=True')
        if monitor_calls: install_call_monitor(tool_id)
        oks = tuple('.' if o=='.' else realpath(fsdecode(o)) for o in oks)
        cfg = _AuditCfg(oks, before_deny, on_call, data, monitor_calls)

        @contextmanager
        def cm():
            nonlocal cfg
            old = ctx.get()
            if old is not cfg: audit('audit_perms.set_config', cfg)
            tok = ctx.set(cfg)
            if cfg.monitor_calls: mon.restart_events()
            try: yield
            finally: ctx.reset(tok)

        def set_data(d):
            nonlocal cfg
            audit('audit_perms.set_data', d)
            cfg = cfg._replace(data=d)
            return cfg.data

        cm.set_data = set_data
        return cm

    sys.addaudithook(hook)
    return mk_audit_


def _get_mk_audit():
    mk_audit_ = getattr(sys, _state_attr, None)
    if mk_audit_ is None:
        mk_audit_ = _new_state()
        setattr(sys, _state_attr, mk_audit_)
    return mk_audit_

def mk_audit(oks, before_deny=None, on_call=None, data=None, tool_id=3, monitor_calls=True):
    return _get_mk_audit()(oks, before_deny, on_call, data, tool_id, monitor_calls)
