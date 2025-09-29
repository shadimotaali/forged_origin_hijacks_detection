import reflex as rx
from sqlmodel import Field
from datetime import datetime, timezone, timedelta

class User(rx.Model, table=True):
    """A table of Users."""

    id: int = Field(default=None, primary_key=True)
    email: str = Field(nullable=False, unique=True)
    password: str = Field(nullable=True)
    first_name: str = Field(nullable=True)
    last_name: str = Field(nullable=True)
    country: str = Field(nullable=True)
    asn: int = Field(nullable=True)

def compute_expiration_time() -> datetime:
    return datetime.now(timezone.utc)+timedelta(hours=1)


