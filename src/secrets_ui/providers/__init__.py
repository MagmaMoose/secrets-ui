"""Secret stores behind one interface, so the UI and the API do not care which product holds them.

A provider turns a person's sign-in into the stores they may open (an Azure key vault, a
HashiCorp Vault mount) and runs secret operations there with that person's own credential.
`features` tells the UI which controls apply: a store without expiry shows no expiry column.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from ..entra import Entra

# What a provider can do beyond list, reveal, create, add a version and delete.
EXPIRY = "expiry"
ENABLE = "enable"
CONTENT_TYPE = "content_type"
RECOVER = "recover"
VERSIONS = "versions"


class ProviderError(Exception):
    """A store refused or failed an operation. `status` is the HTTP status to answer with."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


class Provider(ABC):
    id: ClassVar[str]
    label: ClassVar[str]
    features: ClassVar[frozenset[str]]
    # A secret name the store accepts, as a regular expression the UI also checks, and in words.
    name_pattern: ClassVar[str]
    name_hint: ClassVar[str]

    def __init__(self, labels: dict[str, str] | None = None):
        # The operator's display names, {store: label}, in the order to show the stores in.
        self.labels = dict(labels or {})

    def arrange(self, stores: Iterable[str]) -> list[str]:
        """The stores the operator listed first, in that order, then the rest by name."""
        rank = {name: i for i, name in enumerate(self.labels)}
        return sorted(stores, key=lambda s: (rank.get(s, len(rank)), s))

    @property
    def sign_in_scope(self) -> str:
        """The delegated scope its credential needs, asked for at sign-in. Empty for none."""
        return ""

    @abstractmethod
    def stores(self, roles: Any) -> tuple[str, ...]:
        """The stores a person may open, from the roles in their ID token."""

    @abstractmethod
    def location(self, store: str) -> str:
        """Where a store lives, shown under its name."""

    async def credential(self, entra: Entra, refresh_token: str) -> tuple[str, float]:
        """The person's credential for this provider and when it expires. By default an Entra ID
        access token for `sign_in_scope`; a provider with its own token exchange overrides this."""
        return await entra.refresh(refresh_token, scope=self.sign_in_scope)

    @abstractmethod
    async def list_secrets(self, store: str, token: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def list_deleted(self, store: str, token: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def get_value(self, store: str, name: str, token: str, version: str = "") -> str:
        """The current value, or that of `version`."""

    async def list_versions(self, store: str, name: str, token: str) -> list[dict[str, Any]]:
        """Every version, newest first: version, created, updated, expires, state (enabled, disabled,
        deleted or destroyed) and current."""
        raise ProviderError(400, "versions_not_supported", "This store keeps no versions.")

    @abstractmethod
    async def exists(self, store: str, name: str, token: str) -> bool: ...

    @abstractmethod
    async def set_secret(
        self, store: str, name: str, token: str, *, value: str, content_type: str | None, expires: int | None
    ) -> None:
        """Create the secret, or add a version to it."""

    @abstractmethod
    async def update(self, store: str, name: str, token: str, **changes: Any) -> dict[str, Any]:
        """Change the current version's attributes: any of enabled, expires (None clears), content_type."""

    @abstractmethod
    async def delete(self, store: str, name: str, token: str) -> None:
        """Delete recoverably, where the store can."""

    @abstractmethod
    async def recover(self, store: str, name: str, token: str) -> None: ...

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "features": sorted(self.features),
            "name_pattern": self.name_pattern,
            "name_hint": self.name_hint,
        }
