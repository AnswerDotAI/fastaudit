<!-- do not remove -->

## 0.1.2

### New Features

- Add `fastaudit_safe_native` entry point group to allowlist trusted native modules ([#8](https://github.com/AnswerDotAI/fastaudit/issues/8))


## 0.1.1

### New Features

- Resolve inherited C method modules and allow `__defaults__` setattr ([#7](https://github.com/AnswerDotAI/fastaudit/issues/7))


## 0.1.0

### New Features

- Defer audit hook installation until first `mk_audit`() call ([#6](https://github.com/AnswerDotAI/fastaudit/issues/6))
- More fully exclude Python-level callables from native-call monitoring ([#4](https://github.com/AnswerDotAI/fastaudit/issues/4))
- Install audit hook once at import; move per-policy params into ContextVar-scoped config ([#3](https://github.com/AnswerDotAI/fastaudit/issues/3))
- Support dynamic '.' in allowed roots and audit os.chdir against destination ([#2](https://github.com/AnswerDotAI/fastaudit/issues/2))
- `monitor_calls`=True ([#1](https://github.com/AnswerDotAI/fastaudit/issues/1))

