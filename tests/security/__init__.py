"""Security regression tests — real attacks against real code paths.

Nothing in this directory asserts that a helper exists or that a
function has a particular shape. Each test drives the production code
with hostile input and checks the *effect*: no file appears outside the
sync root, no metadata is recorded for a rejected push, the receiver
keeps serving other peers after an attack.

Kept as its own package (and its own CI job) because these tests must
never be skipped or silently emptied — a green run here is meant to
mean "the attacks below were actually attempted and actually failed".
"""
