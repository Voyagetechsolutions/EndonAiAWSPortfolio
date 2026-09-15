"""Write evidence to the Object Lock evidence bucket, hashing everything on the way in.

Every artifact is stored under ``forensics/<case-id>/`` with its SHA-256 recorded both in
the returned record and as object metadata. The bucket has Object Lock (WORM), versioning
and KMS encryption (see the platform stack), so stored evidence cannot be altered or
deleted within the retention period — the property that makes it defensible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import error_code

PREFIX_ROOT = "forensics"
MANIFEST_NAME = "manifest.json"


@dataclass
class StoredObject:
    key: str
    sha256: str
    size_bytes: int


class EvidenceStore:
    def __init__(self, bucket: str, client: Any) -> None:
        self.bucket = bucket
        self._s3 = client

    def _key(self, case_id: str, name: str) -> str:
        return f"{PREFIX_ROOT}/{case_id}/{name}"

    def put(self, case_id: str, name: str, data: bytes, content_type: str) -> StoredObject:
        digest = hashlib.sha256(data).hexdigest()
        key = self._key(case_id, name)
        # SHA256 checksum also satisfies S3 Object Lock's write-integrity requirement.
        self._s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            ChecksumAlgorithm="SHA256",
            Metadata={"endon-sha256": digest, "endon-case": case_id},
        )
        return StoredObject(key=key, sha256=digest, size_bytes=len(data))

    def put_json(self, case_id: str, name: str, obj: Any) -> StoredObject:
        data = json.dumps(obj, indent=2, default=str, sort_keys=True).encode("utf-8")
        return self.put(case_id, name, data, "application/json")

    def case_exists(self, case_id: str) -> bool:
        """Whether a manifest already exists for this case (idempotent re-delivery guard)."""
        try:
            self._s3.head_object(Bucket=self.bucket, Key=self._key(case_id, MANIFEST_NAME))
            return True
        except ClientError as exc:
            if error_code(exc) in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def write_manifest(self, case_id: str, manifest: dict[str, Any]) -> StoredObject:
        return self.put_json(case_id, MANIFEST_NAME, manifest)
