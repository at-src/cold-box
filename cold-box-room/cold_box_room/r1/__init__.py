"""Room 1 — staging table and glass seal."""

from cold_box_room.r1.checkpoint import r1_checkpoint
from cold_box_room.r1.hallway import current_room, promote_to_room2, require_room
from cold_box_room.r1.intake import intake_case, list_table_cases
from cold_box_room.r1.seal import is_sealed, require_sealed
from cold_box_room.r1.viewport import open_viewport

__all__ = [
    "current_room",
    "intake_case",
    "is_sealed",
    "list_table_cases",
    "open_viewport",
    "promote_to_room2",
    "r1_checkpoint",
    "require_room",
    "require_sealed",
]
