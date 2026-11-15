"""Master and organization credential key generation."""

from dataclasses import dataclass, field

from .group import GroupParams, modexp, random_scalar


@dataclass(frozen=True)
class MasterKey:
    x: int = field(repr=False)
    public: int

    @classmethod
    def generate(cls, params: GroupParams) -> "MasterKey":
        x = random_scalar(params.q, nonzero=True)
        return cls(x, modexp(params.g, x, params.p))


@dataclass(frozen=True)
class OrganizationPublicKey:
    h1: int
    h2: int


@dataclass(frozen=True)
class OrganizationCredentialKey:
    s1: int = field(repr=False)
    s2: int = field(repr=False)
    h1: int
    h2: int

    @classmethod
    def generate(cls, params: GroupParams) -> "OrganizationCredentialKey":
        s1 = random_scalar(params.q, nonzero=True)
        s2 = random_scalar(params.q, nonzero=True)
        return cls(s1, s2, modexp(params.g, s1, params.p), modexp(params.g, s2, params.p))

    @property
    def public_key(self) -> OrganizationPublicKey:
        return OrganizationPublicKey(self.h1, self.h2)


@dataclass(frozen=True)
class User:
    master_key: MasterKey

    @classmethod
    def generate(cls, params: GroupParams) -> "User":
        return cls(MasterKey.generate(params))

    @property
    def master_secret(self) -> int:
        return self.master_key.x

    @property
    def master_public(self) -> int:
        return self.master_key.public


@dataclass(frozen=True)
class Organization:
    credential_key: OrganizationCredentialKey
    is_ca: bool = False

    @classmethod
    def generate(cls, params: GroupParams, *, is_ca: bool = False) -> "Organization":
        return cls(OrganizationCredentialKey.generate(params), is_ca)

    @property
    def public_key(self) -> OrganizationPublicKey:
        return self.credential_key.public_key
