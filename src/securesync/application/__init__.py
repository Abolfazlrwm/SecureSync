"""SecureSync — application package.

Use-case orchestration against domain ports; depends on ``domain/``
only. See docs/architecture.md for what belongs in this layer.

``use_cases`` holds one module per operation (chunk a file, compute
a delta, sync with a peer, receive pushed files, ...); ``observers``
holds filesystem-event listeners; ``orchestration`` coordinates them.
"""
