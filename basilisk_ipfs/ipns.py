"""IPNS records: creation, signing (V1+V2) and validation.

Spec: https://specs.ipfs.tech/ipns/ipns-record/
"""

import datetime

from . import dagcbor
from . import protobuf as pb
from .cid import CID
from .keys import PeerID, PublicKey

EOL = 0
DEFAULT_LIFETIME = datetime.timedelta(hours=48)
DEFAULT_TTL_NS = 5 * 60 * 10 ** 9  # 5 minutes


class InvalidRecord(ValueError):
    pass


def _fmt_time(dt: datetime.datetime) -> str:
    dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond * 1000:09d}Z"


def _parse_time(s: str) -> datetime.datetime:
    s = s.strip()
    main, _, frac = s.rstrip("Z").partition(".")
    dt = datetime.datetime.strptime(main, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    if frac:
        dt += datetime.timedelta(microseconds=int((frac + "000000")[:6]))
    return dt


class Record:
    def __init__(self, value: bytes, sequence: int, validity: datetime.datetime,
                 ttl_ns: int = DEFAULT_TTL_NS, public_key: PublicKey = None,
                 signature_v1=None, signature_v2=None, data=None):
        self.value = value
        self.sequence = sequence
        self.validity = validity
        self.ttl_ns = ttl_ns
        self.public_key = public_key
        self.signature_v1 = signature_v1
        self.signature_v2 = signature_v2
        self.data = data

    @property
    def path(self) -> str:
        return self.value.decode()

    def _cbor_data(self):
        return dagcbor.encode({
            "Value": self.value,
            "Validity": _fmt_time(self.validity).encode(),
            "ValidityType": EOL,
            "Sequence": self.sequence,
            "TTL": self.ttl_ns,
        })

    @classmethod
    def create(cls, private_key, value, sequence=0, lifetime=DEFAULT_LIFETIME,
               ttl_ns=DEFAULT_TTL_NS) -> "Record":
        if isinstance(value, CID):
            value = f"/ipfs/{value}"
        if isinstance(value, str):
            value = value.encode()
        validity = datetime.datetime.now(datetime.timezone.utc) + lifetime
        rec = cls(value, sequence, validity, ttl_ns, private_key.public_key)
        rec.data = rec._cbor_data()
        rec.signature_v2 = private_key.sign(b"ipns-signature:" + rec.data)
        rec.signature_v1 = private_key.sign(value + _fmt_time(validity).encode() + b"EOL")
        return rec

    def encode(self) -> bytes:
        out = pb.enc_bytes(1, self.value)
        if self.signature_v1:
            out += pb.enc_bytes(2, self.signature_v1)
        out += pb.enc_varint(3, EOL) + pb.enc_bytes(4, _fmt_time(self.validity))
        out += pb.enc_varint(5, self.sequence) + pb.enc_varint(6, self.ttl_ns)
        # embed the public key only when it can't be derived from the name
        if self.public_key is not None and len(self.public_key.to_protobuf()) > 42:
            out += pb.enc_bytes(7, self.public_key.to_protobuf())
        out += pb.enc_bytes(8, self.signature_v2) + pb.enc_bytes(9, self.data)
        return out

    @classmethod
    def decode(cls, buf: bytes) -> "Record":
        m = pb.decode(buf)
        data = pb.first(m, 9)
        sig2 = pb.first(m, 8)
        if data is None or sig2 is None:
            raise InvalidRecord("record lacks V2 signature/data")
        d = dagcbor.decode(data)
        try:
            validity = _parse_time(d["Validity"].decode())
            rec = cls(d["Value"], d["Sequence"], validity, d.get("TTL", DEFAULT_TTL_NS),
                      signature_v1=pb.first(m, 2), signature_v2=sig2, data=data)
        except (KeyError, ValueError, AttributeError) as e:
            raise InvalidRecord(f"malformed record data: {e}") from e
        if d.get("ValidityType", EOL) != EOL:
            raise InvalidRecord("unsupported validity type")
        pk = pb.first(m, 7)
        if pk:
            rec.public_key = PublicKey.from_protobuf(pk)
        return rec

    def verify(self, name) -> bool:
        """Validate signature, key/name binding and expiry against an IPNS name."""
        pid = name_to_peer_id(name)
        key = self.public_key or pid.extract_public_key()
        if key is None:
            raise InvalidRecord("no public key available for verification")
        if not pid.matches(key):
            raise InvalidRecord("public key does not match IPNS name")
        if not key.verify(b"ipns-signature:" + self.data, self.signature_v2):
            raise InvalidRecord("invalid V2 signature")
        if self.validity < datetime.datetime.now(datetime.timezone.utc):
            raise InvalidRecord("record expired")
        return True

    def __repr__(self):
        return f"IPNSRecord({self.path!r}, seq={self.sequence}, valid_until={self.validity.isoformat()})"


def name_to_peer_id(name) -> PeerID:
    if isinstance(name, PeerID):
        return name
    name = str(name)
    if name.startswith("/ipns/"):
        name = name[6:].split("/", 1)[0]
    return PeerID.decode(name)


def name_for_key(public_key: PublicKey) -> str:
    """The canonical (base36 CIDv1 libp2p-key) IPNS name for a public key."""
    return public_key.peer_id().to_cid().encode("base36")


def dht_key(name) -> bytes:
    return b"/ipns/" + name_to_peer_id(name).to_bytes()


def select_best(records):
    """Choose the record with the highest sequence, then latest validity."""
    return max(records, key=lambda r: (r.sequence, r.validity)) if records else None
