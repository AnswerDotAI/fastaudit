# fastaudit

`fastaudit` is a lightweight execution guard for running LLM-generated Python in a normal Python process.

It aims to prevent accidental damage from broad file operations, unexpected subprocess calls, and tool use outside approved working directories. It is not a hardened sandbox for adversarial code.

The first `mk_audit()` call installs one process-wide Python audit hook. Each call creates an audit context. Permission checks run only while that context is active.

On Python 3.12 and newer, `sys.monitoring` also raises audit events for non-stdlib native calls. Native modules can declare safe calls through `fastaudit_safe_native` entry points. Packaged monitor hooks can also handle native calls.

`fastaudit` requires Python 3.10 or newer. Native call monitoring requires Python 3.12 or newer and is enabled by default. Pass `monitor_calls=False` to use audit-hook-only mode on Python 3.10/3.11 or to avoid monitoring overhead.

## Why this exists

An LLM can respond to a failed command by trying another approach or broadening a file search. It can also use an available tool without understanding its side effects. These attempts to complete a task can damage files or start processes the user did not intend.

`fastaudit` is intended to catch mistakes such as deleting files in the wrong project or writing into a user’s home directory. It helps with:

- blocking subprocess and process-escape operations unless explicitly allowed
- allowing writes only under approved roots
- allowing broad read access where appropriate
- making permission failures clear and immediate
- letting host policy callbacks allow trusted tools while ordinary generated code stays checked
- avoiding global audit state leaks across async tasks

## Audit hook categorization

The audit hook denies process-escape events such as subprocess execution. It checks filesystem writes and deletions against a precomputed directory allowlist. Most of these operations change directory entries, so the checks apply to parent directories.

For a destination-only operation such as copy, only the destination's parent is checked. Move, rename, and link operations check both paths because they can affect both locations.

The hook generally ignores read-only operations. It allows truncation through a file descriptor on the assumption that opening the descriptor already passed the path check.

The filesystem setup is trusted, including existing symlinks. Parent-directory checks do not prevent a symlink inside an allowed directory from pointing outside the allowed roots. The user controls this layout and is assumed not to have created hostile links.

Restrict symlink and hard-link creation. The new link's parent must be allowed. Either deny link targets or require them to resolve inside an allowed root.

## Threat model

`fastaudit` assumes:

- the surrounding process, user account, workspace, and pre-existing filesystem layout are trusted
- code is LLM-generated or LLM-directed, not actively trying to exploit races, pre-planted symlinks, or CPython internals
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

Auditing is opt-in per logical task. The audit hook and optional call monitor are registered globally. Permission checks run only while `audit_perms()` is active.

A `ContextVar` stores the active audit state. A global boolean or counter would share that state with unrelated coroutines whenever an audited task awaited. Child tasks inherit the context at creation time. Nested contexts restore the previous state through tokens. Audit state therefore follows the task's execution, independently of scheduling order. Threads are restricted because their context variables are not maintained automatically.

Entering `audit_perms()` records the thread id, thread name, current asyncio task, and call chain. If an operation is denied in another thread or task, its error message identifies where the context was entered. This covers inherited or leaked copies of the context. A denial on the same stack omits the extra note because its call chain already identifies the origin.

The hook is constructed once in a closure. Allowed roots and callbacks are stored in the active context's configuration. Event-classification sets use `frozenset`. The hook captures `realpath`, `dirname`, `fsdecode`, and `os.sep` as local names.

The hook does not depend on mutable globals that generated code could clear or replace. This prevents accidental disabling during retries after a `PermissionError`, such as clearing a deny set or replacing a helper. It does not prevent deliberate introspection or frame walking.

## Permission model

The policy classifies audit events into these groups:

- events explicitly allowed
- events where the first path argument is checked
- events where the destination path is checked
- events where both source and destination paths are checked
- special cases such as `open`, `os.truncate`, and sensitive `object.__setattr__`
- everything else, including package-defined audit events, is denied unless `before_deny` allows it

Writes and filesystem mutations are allowed only when the relevant parent directory is inside an approved root.

Reads are generally allowed.

Subprocess creation and similar process escapes are denied by default.

Most environment-variable updates are allowed. Updates to sensitive variables require permission from `before_deny`. These variables control command lookup, Python/import behavior, dynamic loading, virtual environments, home/user identity, shell selection, or temporary directories.

Thread creation is denied by default. One exception permits asyncio to create its default executor thread from `BaseEventLoop.run_in_executor`, for example during DNS resolution. This permits the `asyncio_` worker thread. It does not permit general user-created threads.

The allowed root `'.'` means the current directory at the time of each checked operation. It follows permitted `chdir` calls into child directories. For `os.chdir`, the path check applies to the destination directory itself. It does not check the destination's parent.

Non-stdlib native calls raise a `fastaudit.call` audit event while `audit_perms()` is active when `monitor_calls=True`. Python calls, stdlib calls, safe native entry point prefixes, and packaged monitor-hook suppressions are ignored by the call monitor. With `monitor_calls=False`, only normal Python audit-hook events are checked.

`CALL` instrumentation runs only while at least one monitoring context is active. A reference count tracks context entries and exits. The first entry enables `CALL` events with `sys.monitoring.set_events()`. The last exit disables them.

Between audit contexts, code objects lazily remove instrumentation and run with zero monitoring overhead. This includes code that calls native modules not declared safe. Each context entry calls `sys.monitoring.restart_events()` to re-enable call sites disabled in an earlier context.

Events remain globally enabled while any monitoring context is active. Non-audited code does not disable unmatched call sites. Concurrent non-audited code therefore cannot stop an active context from observing a shared call site.

Native modules can declare safe call prefixes with the `fastaudit_safe_native` entry point group:

```toml
[project.entry-points.fastaudit_safe_native]
mymarkdown = "mymarkdown._rust"
```

`fastaudit` reads the entry point values as module prefixes. It does not load the entry points or import the target modules. Missing or unloadable modules are harmless. A value of `mymarkdown._rust` allows native calls from `mymarkdown._rust` and `mymarkdown._rust.*`, but not `mymarkdown.io`.

Packages can also expose reusable monitor and audit hooks:

```toml
[project.entry-points.fastaudit_monitor_hook]
mypkg = "mypkg.fastaudit:monitor"

[project.entry-points.fastaudit_audit_hook]
mypkg = "mypkg.fastaudit:before_deny"
```

Monitor hooks use the `on_call` signature. Audit hooks use the `before_deny` signature.

The bundled `lxml` monitor hook checks callee names without importing `lxml`. It disables monitoring for ordinary `lxml.` native calls. These known file writers remain blocked as `fastaudit.call` events:

- `lxml.etree._ElementTree.write`
- `lxml.etree._ElementTree.write_c14n`
- `lxml.etree.xmlfile`
- `lxml.etree.xmlfile.__enter__`
- `lxml.etree._XSLTResultTree.write_output`

Some packages have import-time side effects that raise sensitive audit events. For example, a package may set function `__code__` or class `__qualname__` while it is being imported. A package or host can declare those imports trusted:

```toml
[project.entry-points.fastaudit_import_allow]
mypkg = "mypkg"
```

Entries are module prefixes. For example, `mypkg` includes `mypkg.submodule`. Reading the metadata does not import these modules.

During an audit context, fastaudit checks the stack for a frame belonging to an allowed module. If that module's `__spec__` is initializing, events from the import are permitted. Hosts can also set `allow_imports=('mypkg',)` in `mk_audit()` or call `audit_perms.add_imports('mypkg')` outside the sandbox.

### get/set attr hooks

The `object.__setattr__` audit event covers a fixed set of sensitive assignments:

- Setting `__name__`, `__qualname__`, `__module__`, `__bases__`, `__doc__`, or `__type_params__` on a type or class. These use `check_set_special_type_attr` in `Objects/typeobject.c`.
- Reassigning `__class__` on any object. This uses `object_set_class` in the same file.
- Setting `__code__`, `__defaults__`, or `__kwdefaults__` on a function. These use the corresponding setters in `Objects/funcobject.c`.

Other attribute assignments bypass the audit hook. These include `C.x = 1`, instance attributes, and dunders such as `__abstractmethods__` and `__annotations__`. The latter write directly through `PyDict_SetItem`.

`@dataclass` triggers an event because it sets `cls.__doc__`. `namedtuple` triggers one because it sets `cls.__module__`. In contrast, `class C: pass; C.x = 1; C.foo = lambda self: None` triggers no event.

The complete list is in CPython's [`Objects/typeobject.c`](https://github.com/python/cpython/blob/v3.12.0/Objects/typeobject.c) and [`Objects/funcobject.c`](https://github.com/python/cpython/blob/v3.12.0/Objects/funcobject.c). The public documentation describes "certain sensitive attribute assignments" without enumerating them.

## Host policy

Some user-provided tools need permissions that ordinary generated code should not have. For instance, a search tool may need to call `rg`, or a helper may need to spawn a tightly controlled subprocess.

The host defines which tools to trust through `before_deny`. fastaudit calls it before raising `PermissionError` for an operation it would otherwise block:

```python
before_deny(event, args, frame, msg, data, calls)
```

The callback arguments are:

- `event`: the audit event name.
- `args`: the audit arguments.
- `frame`: the first stack frame outside fastaudit.
- `msg`: the error message.
- `data`: the current host data.
- `calls`: active tracked calls.

A truthy return value allows the operation. A falsey value denies it. Exceptions from the callback propagate.

Events outside fastaudit's explicit allow and path-check lists also go through `before_deny`. Libraries can define their own audit events without depending on fastaudit. The host decides which events to allow.

Allowed event entries ending in `.` match prefixes. For example, `http.client.` permits `http.client.connect` and `http.client.send`.

For other non-stdlib native calls, pass `on_call` to run a callback before the `fastaudit.call` event. This requires `monitor_calls=True`:

```python
on_call(caller, callee, fn, code, off, data, calls)
```

Its arguments identify the caller, callee, function object, code object, and bytecode offset. It also receives the current host data and active tracked calls.

Return `False` to suppress the audit event for this call. Return `sys.monitoring.DISABLE` to disable the monitored call site. Exceptions from the callback propagate.

The audit context stores the optional `data` argument and passes it to both callbacks. Build mutable policy state outside the sandbox and pass a frozen snapshot to `mk_audit`. Update the snapshot with `audit_perms.set_data(...)`.

Creating or entering an audit context raises an internal audit event. Calling `set_data` also raises one. These operations are denied while `audit_perms()` is active.

An async tool's stack may no longer contain the trusted function that started its work. `track_call` records wrapped coroutine calls in a `ContextVar`. It stores the function, args, kwargs, module, qualname, and full name. Non-coroutine functions are returned unchanged:

```python
@track_call
async def trusted_tool(q): ...

def before_deny(event, args, frame, msg, data, calls):
    return event=='subprocess.Popen' and any(c.name=='pkg.trusted_tool' for c in calls)
```

Finished calls are marked inactive. A child task's copied context cannot retain permissions from a wrapped call that has returned.

`audit_state()` returns a debug snapshot with `safe_native`, `import_allow`, `monitoring`, `tool_id`, `active`, `monitor_on`, and `monitor_calls`. The `monitor_on` field counts active monitoring contexts.

`mk_audit()` uses `sys.monitoring` tool id `3` by default when call monitoring is enabled. Pass `tool_id=...` if the host already uses that id.

## API sketch

```python
audit_perms = mk_audit(['/tmp', os.getcwd()], before_deny=allow_trusted_tool, data=frozenset(allowed))

with audit_perms():
    exec(code, restricted_globals)

audit_perms.set_data(frozenset(new_allowed))
audit_perms.add_imports('trusted_pkg')

audit_state()

audit_perms = mk_audit(['/tmp'], allow_imports=('trusted_pkg',), monitor_calls=False)  # audit hooks only
```

## Implementation notes

When maintaining the hook, bind or freeze these dependencies at construction time:

- approved roots
- safe native module prefixes from `fastaudit_safe_native` entry points
- import-allowed module prefixes from `fastaudit_import_allow` entry points
- allowed and checked audit event sets
- write flags
- path helpers such as `realpath`, `dirname`, and `fsdecode`
- frame lookup helper
- call-monitor helpers and callbacks

Keep enforcement independent of mutable globals. This prevents accidental disabling by clearing a deny set or replacing a helper. It does not protect against deliberate frame walking or introspection.

## Limitations

`fastaudit` does not provide a hard security boundary.

Known limitations:

- same-process Python code can inspect a lot of runtime state
- pre-existing writable file descriptors may bypass path-open checks
- host callbacks can do anything their implementation permits
- thread support is intentionally restricted unless explicitly designed for
- The `CALL` event in `sys.monitoring` does not fire for operators invoked by dedicated bytecode opcodes. Examples include `BINARY_OP` (`a + b`), `BINARY_SUBSCR` (`a[i]`), and comparisons. They dispatch to C-level numeric, subscript, or comparison slots without a "call" in PEP 669's model. Explicit dunder calls such as `a.__add__(b)` do fire `CALL`.

## Release

Label GitHub issues with `bug`, `enhancement`, or `breaking`. Then run:

```bash
ship-gh
ship-pypi
ship-bump
```
