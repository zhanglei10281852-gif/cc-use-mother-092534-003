"""内存存储：保存租约关系、回执、销毁证明与事件。

存储中**没有任何凭据明文字段**；凭据只以 SHA-256 指纹形式存在，
因此快照、任务参数重放或诊断打包都不可能携带明文。
"""
from __future__ import annotations

from typing import Iterable, Optional

from .models import (
    Authorization,
    CredentialVersionRecord,
    DestructionProof,
    Incident,
    LeaseRecord,
    TenantQuota,
    UsageReceipt,
)


class LeaseStore:
    def __init__(self) -> None:
        self.connectors: dict[str, str] = {}
        self.quotas: dict[str, TenantQuota] = {}
        self.authorizations: dict[tuple[str, str, str], Authorization] = {}
        self.credentials: dict[str, list[CredentialVersionRecord]] = {}
        self.leases: dict[str, LeaseRecord] = {}
        self.task_index: dict[tuple[str, str], list[str]] = {}
        self.handles: dict[str, str] = {}  # lease_id -> 最新句柄标识
        self.receipts: list[UsageReceipt] = []
        self.proofs: dict[str, DestructionProof] = {}
        self.incidents: dict[str, Incident] = {}

    # --- connector / quota / authorization -----------------------

    def register_connector(self, connector_id: str, description: str = "") -> None:
        self.connectors.setdefault(connector_id, description)

    def set_quota(self, tenant_id: str, max_active_leases: int) -> None:
        if max_active_leases < 1:
            raise ValueError("租户额度必须大于 0")
        self.quotas[tenant_id] = TenantQuota(tenant_id, max_active_leases)

    def save_authorization(self, authorization: Authorization) -> None:
        key = (
            authorization.context.tenant_id,
            authorization.context.task_id,
            authorization.context.connector_id,
        )
        self.authorizations[key] = authorization

    def get_authorization(
        self, tenant_id: str, task_id: str, connector_id: str
    ) -> Optional[Authorization]:
        return self.authorizations.get((tenant_id, task_id, connector_id))

    # --- credential versions --------------------------------------

    def credential_key(self, tenant_id: str, connector_id: str) -> str:
        return f"cred-{tenant_id}-{connector_id}"

    def save_credential_version(self, record: CredentialVersionRecord) -> None:
        versions = self.credentials.setdefault(record.credential_id, [])
        versions.append(record)

    def versions(self, credential_id: str) -> list[CredentialVersionRecord]:
        return self.credentials.get(credential_id, [])

    def current_version(self, credential_id: str) -> Optional[CredentialVersionRecord]:
        for record in reversed(self.credentials.get(credential_id, [])):
            if record.state.value == "current":
                return record
        return None

    def find_version(
        self, credential_id: str, version: int
    ) -> Optional[CredentialVersionRecord]:
        for record in self.credentials.get(credential_id, []):
            if record.version == version:
                return record
        return None

    # --- leases ---------------------------------------------------

    def save_lease(self, record: LeaseRecord) -> None:
        self.leases[record.lease_id] = record
        key = (record.tenant_id, record.task_id)
        ids = self.task_index.setdefault(key, [])
        if record.lease_id not in ids:
            ids.append(record.lease_id)

    def get_lease(self, lease_id: str) -> Optional[LeaseRecord]:
        return self.leases.get(lease_id)

    def leases_for_task(self, tenant_id: str, task_id: str) -> list[LeaseRecord]:
        return [
            self.leases[lease_id]
            for lease_id in self.task_index.get((tenant_id, task_id), [])
            if lease_id in self.leases
        ]

    def leases_for_tenant(self, tenant_id: str) -> list[LeaseRecord]:
        return [r for r in self.leases.values() if r.tenant_id == tenant_id]

    def leases_for_connector(self, connector_id: str) -> list[LeaseRecord]:
        return [r for r in self.leases.values() if r.connector_id == connector_id]

    def register_handle(self, lease_id: str, handle_id: str) -> None:
        self.handles[lease_id] = handle_id

    def current_handle_id(self, lease_id: str) -> Optional[str]:
        return self.handles.get(lease_id)

    # --- receipts / proofs / incidents ----------------------------

    def append_receipt(self, receipt: UsageReceipt) -> None:
        self.receipts.append(receipt)

    def receipts_for_lease(self, lease_id: str) -> list[UsageReceipt]:
        return [r for r in self.receipts if r.lease_id == lease_id]

    def receipts_for_connector(self, connector_id: str) -> list[UsageReceipt]:
        return [r for r in self.receipts if r.connector_id == connector_id]

    def save_proof(self, proof: DestructionProof) -> None:
        self.proofs[proof.proof_id] = proof

    def proofs_for_leases(self, lease_ids: Iterable[str]) -> list[DestructionProof]:
        wanted = set(lease_ids)
        return [p for p in self.proofs.values() if p.lease_id in wanted]

    def save_incident(self, incident: Incident) -> None:
        self.incidents[incident.incident_id] = incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def open_incidents(self, tenant_id: str) -> list[Incident]:
        return [
            i
            for i in self.incidents.values()
            if i.tenant_id == tenant_id and i.state.value == "open"
        ]
