"""SecureSync — domain package.

Entities, value objects, and ports (interfaces). Pure Python only — no
I/O, no third-party dependency. See docs/architecture.md for what
belongs in this layer.

Entities live in ``chunk``, ``conflict``, ``delta``, ``identity``,
``metadata``, ``networking``, ``transfer`` and friends; the ports they
depend on live beside them.
"""
