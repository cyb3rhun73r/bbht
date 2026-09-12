import datetime
from pydantic import BaseModel, field_validator


class TargetCreate(BaseModel):
    name: str
    domain: str
    program_url: str = ""
    authorized: bool
    notes: str = ""

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must confirm authorization to add a target")
        return v


class TargetOut(BaseModel):
    id: int
    name: str
    domain: str
    program_url: str
    authorized: bool
    notes: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    target_id: int
    url: str
    modules: list[str]


class DiscoverRequest(BaseModel):
    target_id: int
    base_url: str


class FindingOut(BaseModel):
    id: int
    category: str
    title: str
    severity: str
    confidence: str
    location: str
    evidence: str
    poc: str
    remediation: str

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    target_id: int
    url: str
    modules: str
    status: str
    progress: str
    started_at: datetime.datetime
    finished_at: datetime.datetime | None

    class Config:
        from_attributes = True
