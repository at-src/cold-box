"""Room 1 — R1 staging area and seal."""

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.hallway import (
    current_room,
    normalize_room,
    promote_to_room2,
    promote_to_room_a,
    promote_to_room_b,
    promote_to_room3,
    require_room,
    return_to_room,
    unlocked_rooms,
)
from cold_box_room.r1.intake import intake_case, list_staging_cases
from cold_box_room.r1.seal import is_sealed, require_sealed
from cold_box_room.r1.staging_read import open_staging_read

__all__ = [
    "current_room",
    "intake_case",
    "is_sealed",
    "list_staging_cases",
    "normalize_room",
    "open_staging_read",
    "promote_to_room2",
    "promote_to_room_a",
    "promote_to_room_b",
    "promote_to_room3",
    "r1_checkpoint",
    "require_room",
    "require_sealed",
    "return_to_room",
    "unlocked_rooms",
]
