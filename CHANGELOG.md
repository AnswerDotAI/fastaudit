<!-- do not remove -->

## 0.1.0

### New Features

- Defer audit hook installation until first `mk_audit`() call ([#6](https://github.com/AnswerDotAI/fastaudit/issues/6))
- More fully exclude Python-level callables from native-call monitoring ([#4](https://github.com/AnswerDotAI/fastaudit/issues/4))
- Install audit hook once at import; move per-policy params into ContextVar-scoped config ([#3](https://github.com/AnswerDotAI/fastaudit/issues/3))
- Support dynamic '.' in allowed roots and audit os.chdir against destination ([#2](https://github.com/AnswerDotAI/fastaudit/issues/2))
- `monitor_calls`=True ([#1](https://github.com/AnswerDotAI/fastaudit/issues/1))

