"""A subset of the multicodec table relevant to IPFS."""

CODES = {
    "identity": 0x00,
    "cidv1": 0x01,
    "sha1": 0x11,
    "sha2-256": 0x12,
    "sha2-512": 0x13,
    "sha3-512": 0x14,
    "sha3-384": 0x15,
    "sha3-256": 0x16,
    "sha3-224": 0x17,
    "cbor": 0x51,
    "raw": 0x55,
    "dag-pb": 0x70,
    "dag-cbor": 0x71,
    "libp2p-key": 0x72,
    "git-raw": 0x78,
    "dag-jose": 0x85,
    "ed25519-pub": 0xED,
    "dag-json": 0x0129,
    "json": 0x0200,
    "blake2b-256": 0xB220,
    "blake2b-512": 0xB240,
    "blake2s-256": 0xB260,
    "libp2p-peer-record": 0x0301,
    "ipns-record": 0x0300,
}
NAMES = {v: k for k, v in CODES.items()}


def code(name_or_code) -> int:
    if isinstance(name_or_code, int):
        return name_or_code
    try:
        return CODES[name_or_code]
    except KeyError:
        raise ValueError(f"unknown multicodec {name_or_code!r}") from None


def name(c: int) -> str:
    return NAMES.get(c, hex(c))
