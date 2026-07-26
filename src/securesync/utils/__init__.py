"""SecureSync — utils package.

Small, stateless, generic helpers with no dependency on any specific
phase's domain. See docs/architecture.md for what belongs in this
layer.

Implemented so far:
    Phase 2 (Chunk Engine):
        - ``async_iter``: ``iter_in_thread``, a generic bridge that
          drives a blocking iterator from async code without blocking
          the event loop. Introduced for the chunk engine's use cases
          but has no chunk-engine-specific dependency — any future
          phase wrapping blocking iteration in an async use case can
          reuse it as-is.
"""
