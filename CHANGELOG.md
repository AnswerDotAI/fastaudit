<!-- do not remove -->

## 0.1.4

### New Features

- expand `~` in allowed paths ([#5](https://github.com/AnswerDotAI/fastaudit/pull/5)), thanks to [@kafkasl](https://github.com/kafkasl)


## 0.2.0

### Breaking Changes

- Switch audit policy from explicit deny-list to explicit allow-list with prefix support and `before_deny` fallback ([#10](https://github.com/AnswerDotAI/fastaudit/issues/10))

### New Features

- Add `track_call` for async-aware permissions; pass active calls to `before_deny`/`on_call`; allow asyncio default executor thread ([#11](https://github.com/AnswerDotAI/fastaudit/issues/11))
- Add `audit_state` ([#9](https://github.com/AnswerDotAI/fastaudit/issues/9))


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

