"""SecureSync — reference/utility observers.

Concrete implementations of ``domain.watcher.FileSystemEventObserver``.
Real consumers (chunk engine, metadata indexer) arrive in later phases;
until then this package holds minimal, generically useful observers.
"""
