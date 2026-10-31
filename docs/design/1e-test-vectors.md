# 1e — Published test vectors

Frozen known-answer vectors for the v3 handshake message layer. Every value
below is deterministic: the keys come from fixed seeds and every nonce is
fixed. The KAT in
[`tests/unit/infrastructure/networking/test_handshake_messages.py`](../../tests/unit/infrastructure/networking/test_handshake_messages.py)
asserts these exact bytes.

The primitives themselves are anchored separately to RFC 5869 (HKDF-SHA256)
and RFC 8032 (Ed25519), so a KAT failure points at either the composition or
the primitive rather than at both.

## Fixed inputs

```text
E_I_SEED  = 000102...1f                 (X25519 private, 32 bytes)
E_R_SEED  = 202122...3f                 (X25519 private, 32 bytes)
ID_SEED_I = a0a1...bf                   (Ed25519 seed, 32 bytes)
ID_SEED_R = b0b1...cf                   (Ed25519 seed, 32 bytes)

E_I_PUB   = 8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f
E_R_PUB   = 358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
ID_PUB_I  = 4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4
ID_PUB_R  = 74fca2a3b389fb1a64d9bf52cc0dd4c2964f3804c0cf7c755e8513c6db8198dc

n_i       = 111111...11                 (32 bytes)
n_r       = 222222...22                 (32 bytes)
id_i      = "device-alpha"              (12 bytes)
id_r      = "device-beta"               (11 bytes)
port_i    = 5000, 5001                  (transfer, manifest)
port_r    = 5001, 5002                  (transfer, manifest)

sig_r     = aa...aa                     (64 placeholder bytes)
sig_i     = bb...bb                     (64 placeholder bytes)
mac_r     = cc...cc                     (32 placeholder bytes)
mac_i     = dd...dd                     (32 placeholder bytes)
mac_f     = ee...ee                     (32 placeholder bytes)
```

`sig_*`/`mac_*` are placeholders here: this layer only encodes and decodes
them. Their real values are exercised by the state-machine tests (commits
3–4).

## Message lengths

```text
m1 = 104 + len(id_i) = 116
m2 = 200 + len(id_r) = 211
m3 = 98
m4 = 35
```

## Message bytes

```text
M1 =
03018f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f
1111111111111111111111111111111111111111111111111111111111111111
000c6465766963652d616c706861
4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4
13881389

M2 =
0302358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16
6254222222222222222222222222222222222222222222222222222222222222
2222000b6465766963652d6265746174fca2a3b389fb1a64d9bf52cc0dd4c296
4f3804c0cf7c755e8513c6db8198dc1389138aaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacccccccccccccccccccccccccc
cccccccccccccccccccccccccccccccccccccc

M3 =
0303
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd

M4 =
030400eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
```

## Transcripts

```text
t2      = 4d2c7997e9a177c99ff9c35516dbcae92a0a03bdeacecea0b1092f52f0936486
t2s     = 7c2ee345f5c0589a1e1eb7762dcaa029cfc00c3ab733a72dc51a72c0e881b079
t3      = dcf142ee4ed735e67a1b7e16f2dcf5e307727910db57b9710f6eede55f69aaa1
t3s     = 5ca3818888f39811a0ddf5fad188dbc8a564b896d92ba81a7ce44f8a3e0a1a69
t_final = 6a990fd748d5c02415175ce9623e92c7410d25630e1d0458f7f8573f56921fe3
t4      = 1879942edd44e06245163a7a27ef02a9c1c58f821c8db95aada250d46a546e15
```

## Signature payloads (domain separation)

```text
signed_responder(t2) =
001b73656375726573796e632d31652d726573706f6e6465722d736967
4d2c7997e9a177c99ff9c35516dbcae92a0a03bdeacecea0b1092f52f0936486

signed_initiator(t2s) =
001b73656375726573796e632d31652d696e69746961746f722d736967
7c2ee345f5c0589a1e1eb7762dcaa029cfc00c3ab733a72dc51a72c0e881b079
```

The first two bytes of each payload are the 2-byte big-endian length of the
label (`0x001b` = 27), followed by the ASCII label, followed by the
transcript. A responder signature therefore cannot be replayed as an
initiator signature even if the transcript bytes were identical.
