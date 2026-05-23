# fastaudit

`fastaudit` is a lightweight execution guard for running LLM-generated Python in a normal Python process.

It is not intended to be a hardened adversarial sandbox. Its purpose is to stop accidental damage from overly broad file operations, unexpected subprocess calls, and tool use that reaches outside approved working directories.

The core mechanism is Python's audit hook system. The first `mk_audit()` call installs one process-wide audit hook. On Python 3.12 and newer, `sys.monitoring` is also used to raise audit events for non-stdlib native calls, except for native modules declared safe through `fastaudit_safe_native` entry point metadata. `mk_audit()` creates an audit context, then enables permission checks only while that execution context is active.

`fastaudit` requires Python 3.10 or newer. Native call monitoring requires Python 3.12 or newer and is enabled by default. Pass `monitor_calls=False` to use audit-hook-only mode on Python 3.10/3.11 or to avoid monitoring overhead.

## Why this exists

LLM-generated code is usually helpful, but sometimes too determined. If a command fails, an assistant may try another route; if a path is wrong, it may broaden the search; if a tool exists, it may use it without fully understanding its side effects.

`fastaudit` is designed for that case.

It helps with:

- blocking subprocess and process-escape operations unless explicitly allowed
- allowing writes only under approved roots
- allowing broad read access where appropriate
- making permission failures clear and immediate
- letting host policy callbacks allow trusted tools while ordinary generated code stays checked
- avoiding global audit state leaks across async tasks

It deliberately does not try to defeat malicious code running in the same interpreter.

## Audit hook categorization

The audit hook is designed as a lightweight guardrail for LLM/tool-generated code, not as a hardened security sandbox against malicious code. The goal is to prevent accidental or over-broad filesystem mutation outside approved working directories: e.g. deleting files in the wrong project, writing into a user’s home directory, or spawning subprocesses unexpectedly. It assumes the surrounding process, user account, and pre-existing filesystem layout are trusted, and that the code being checked is not actively trying to exploit races, pre-planted symlinks, or CPython internals.

The design keeps the common path simple and cheap. Dangerous process-escape events such as subprocess execution are denied outright. Filesystem write/delete events are allowed only when the relevant parent directory is inside a precomputed allowlist, since most mutations are really changes to directory entries. For destination-only operations such as copy, only the destination parent matters; for move/rename/link-style operations, both paths are checked because both filesystem locations may be affected. Read-only operations are generally ignored, and file-descriptor-based truncation is allowed on the assumption that the path policy was enforced when the descriptor was opened. This gives practical protection against accidental damage while avoiding the complexity and cost of pretending to be a fully adversarial sandbox.

Symlinks are treated as part of the trusted filesystem setup. The hook’s path checks focus on the parent directories of mutations, which is the right model for operations that create, remove, or rename directory entries. This means an existing symlink inside an allowed directory may still point outside the allowed roots; that is acceptable under this threat model because the user controls the workspace layout and is assumed not to pre-place hostile links. To avoid making that assumption worse, symlink and hard-link creation should be restricted: the new link’s parent must be allowed, and the link target should either be denied or required to resolve inside an allowed root.

## Threat model

`fastaudit` assumes:

- the user, workspace, and pre-existing filesystem layout are trusted
- code is LLM-generated or LLM-directed, not actively hostile
- accidental overreach is the main risk
- rich user tools may need access that ordinary generated code should not have
- Solveit or the host application controls the execution wrapper

It does not assume:

- Python introspection is unavailable
- frames, closures, or modules are impossible to inspect
- same-process execution can provide a hard security boundary
- OS-level sandboxing is unnecessary for adversarial workloads

For adversarial code, use a subprocess, container, VM, or OS-level policy.

## Audit scope

Auditing is opt-in per logical task. The audit hook is registered globally when the first audit context is created, and the optional call monitor is registered globally when needed, but permission checks only run while `audit_perms()` is active. This matters for async code. A global boolean or counter would leak audit state between unrelated coroutines whenever one audited task awaits. A `ContextVar` gives logical scoping: child tasks inherit at creation time, nested contexts restore cleanly via tokens, and the guard follows execution flow rather than scheduler order. Threads are denied in the audit sandbox since context variables otherwise are not maintained.

The hook is built once inside a closure rather than read from module globals on every event. Allowed roots and callbacks live in the active context config, the event-classification sets are converted to `frozenset`, and the helpers used in the hot path — `realpath`, `dirname`, `fsdecode`, `os.sep` — are captured as local names. Nothing the hook depends on lives in a mutable global that a generated cell could clear, replace, or reassign. This is not a security barrier against introspection or frame walking; it is a deliberate effort to remove the easy, accidental disabling paths that an enthusiastic LLM is most likely to take when retrying after a `PermissionError`.

## Permission model

The policy classifies audit events into a few groups:

- events denied outright
- events where the first path argument is checked
- events where the destination path is checked
- events where both source and destination paths are checked
- special cases such as `open`, `os.truncate`, and sensitive `object.__setattr__`

Writes and filesystem mutations are allowed only when the relevant parent directory is inside an approved root.

Reads are generally allowed.

Subprocess creation and similar process escapes are denied by default.

The allowed root `'.'` is dynamic: it means the current directory at the time of each checked operation. This lets a sandbox follow allowed `chdir` calls into child directories. `os.chdir` itself is checked against the destination directory, not the destination's parent.

Non-stdlib native calls raise a `fastaudit.call` audit event while `audit_perms()` is active when `monitor_calls=True`. Python calls, stdlib calls, and safe native entry point prefixes are ignored by the call monitor. The context manager calls `sys.monitoring.restart_events()` on entry so monitored call sites disabled before the context are seen again inside it. With `monitor_calls=False`, only normal Python audit-hook events are checked.

Native modules can declare safe call prefixes with the `fastaudit_safe_native` entry point group:

```toml
[project.entry-points.fastaudit_safe_native]
mymarkdown = "mymarkdown._rust"
```

`fastaudit` reads the entry point values as module prefixes. It does not load the entry points or import the target modules. Missing or unloadable modules are harmless. A value of `mymarkdown._rust` allows native calls from `mymarkdown._rust` and `mymarkdown._rust.*`, but not `mymarkdown.io`.

### get/set attr hooks

The `object.__setattr__` audit event fires only for a small fixed set of "sensitive" attribute assignments, not for general attribute setting. On types/classes, it fires when setting `__name__`, `__qualname__`, `__module__`, `__bases__`, `__doc__`, or `__type_params__` — these go through `check_set_special_type_attr` in `Objects/typeobject.c`. The `__class__` reassignment on any object is also audited, via `object_set_class` in the same file. On function objects, assignments to `__code__`, `__defaults__`, and `__kwdefaults__` are audited, via the relevant setters in `Objects/funcobject.c`.

All other attribute assignments — including ordinary `C.x = 1` on a class, instance attribute assignment, and even some dunders like `__abstractmethods__` and `__annotations__` (which write directly via `PyDict_SetItem`) — bypass the audit hook entirely. This is why `@dataclass` triggers an event (it sets `cls.__doc__`) and `namedtuple` triggers one (it sets `cls.__module__`), while `class C: pass; C.x = 1; C.foo = lambda self: None` is silent. The authoritative list lives in the CPython source at [`Objects/typeobject.c`](https://github.com/python/cpython/blob/v3.12.0/Objects/typeobject.c) and [`Objects/funcobject.c`](https://github.com/python/cpython/blob/v3.12.0/Objects/funcobject.c); the public docs only describe the event as firing for "certain sensitive attribute assignments" without enumerating them.

## Host policy

Some user-provided tools need permissions that ordinary generated code should not have. For instance, a search tool may need to call `rg`, or a helper may need to spawn a tightly controlled subprocess.

`fastaudit` does not define that policy itself. Host code can pass `before_deny`, which is called after `fastaudit` decides an operation should be blocked and before `PermissionError` is raised:

```python
before_deny(event, args, frame, msg, data)
```

The callback receives the event name, audit arguments, the first non-`fastaudit` stack frame, the error message, and the current host data. Returning a truthy value allows the operation. Returning a falsey value denies it. Exceptions from the callback propagate.

For other non-stdlib native calls, host code can also pass `on_call`, which runs before `fastaudit.call` is raised. `on_call` requires `monitor_calls=True`:

```python
on_call(caller, callee, fn, code, off, data)
```

It receives the caller, callee, function object, code object, bytecode offset, and current host data. It can return `False` to suppress the audit event for that call, or `sys.monitoring.DISABLE` to disable that monitored call site. Exceptions from the callback propagate.

The optional `data` argument is stored in the audit context config and passed to both callbacks. A host can build mutable policy state outside the sandbox, pass a frozen snapshot to `mk_audit`, and later update that snapshot with `audit_perms.set_data(...)`. Creating or entering a new audit context, or calling `set_data`, raises an internal audit event and is denied while `audit_perms()` is active.

`audit_state()` returns a small debug snapshot of the closed-over audit state, including `safe_native`, `monitoring`, `tool_id`, `active`, and `monitor_calls`.

`mk_audit()` uses `sys.monitoring` tool id `3` by default when call monitoring is enabled. Pass `tool_id=...` if the host already uses that id.

## API sketch

```python
audit_perms = mk_audit(['/tmp', os.getcwd()], before_deny=allow_trusted_tool, data=frozenset(allowed))

with audit_perms():
    exec(code, restricted_globals)

audit_perms.set_data(frozenset(new_allowed))

audit_state()

audit_perms = mk_audit(['/tmp'], monitor_calls=False)  # audit hooks only
```

## Implementation notes

The hook should avoid relying on mutable globals during enforcement.

At construction time, bind or freeze:

- approved roots
- safe native module prefixes from `fastaudit_safe_native` entry points
- audit event sets
- write flags
- path helpers such as `realpath`, `dirname`, and `fsdecode`
- frame lookup helper
- call-monitor helpers and callbacks

This prevents the most likely accidental disabling paths, such as clearing a global deny set or replacing a helper function. The implementation still does not claim to be secure against deliberate frame walking or introspection.

## Limitations

`fastaudit` does not provide a hard security boundary.

Known limitations:

- same-process Python code can inspect a lot of runtime state
- pre-existing writable file descriptors may bypass path-open checks
- host callbacks can do anything their implementation permits
- thread support is intentionally restricted unless explicitly designed for
- The `CALL` event in `sys.monitoring` does not fire for operators invoked via dedicated bytecode opcodes — `BINARY_OP` (`a + b`), `BINARY_SUBSCR` (`a[i]`), comparisons, etc. These dispatch directly to the C-level numeric/subscript/compare slots, which aren't "calls" in PEP 669's model. Explicit dunder invocations (`a.__add__(b)`) do fire CALL normally.

These limitations are acceptable for a guardrail system aimed at LLM-directed execution. They are not acceptable for hostile code.

## Design principle

The goal is not to make escape impossible. The goal is to make the safe path easy, the risky path explicit, and accidental overreach fail early with a useful error.

## Release

1) Ensure your GitHub issues are labeled (`bug`, `enhancement`, `breaking`).
2) Run:

```bash
ship-gh
ship-pypi
ship-bump
```
