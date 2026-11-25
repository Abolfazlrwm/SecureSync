"""SecureSync — infrastructure package.

Concrete adapters implementing domain ports. See docs/architecture.md
for what belongs in this layer.

Adapters: ``filesystem`` (watchdog), ``chunking`` (streaming
reader, hashing, repositories), ``config`` (YAML), ``crypto`` (Ed25519
and pyca AEAD), ``metadata`` (SQLite), and ``networking`` (mDNS, TCP
transport, handshake, session stores).
"""
