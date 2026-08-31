"""Focused tests for the guarded artisan_id schema migration."""

import pytest

from db_migrations import _ensure_artisan_id_constraint


class _Cursor:
    def __init__(self, *, null_count=0, duplicate=None):
        self.null_count = null_count
        self.duplicate = duplicate
        self.queries = []

    def execute(self, query, *_args):
        self.queries.append(" ".join(query.split()))

    def fetchone(self):
        query = self.queries[-1]
        if query.startswith("SELECT COUNT(*)"):
            return (self.null_count,)
        if query.startswith("SELECT artisan_id"):
            return (self.duplicate,) if self.duplicate is not None else None
        return None


def test_valid_existing_ids_are_not_changed_and_constraint_is_applied():
    cursor = _Cursor()

    _ensure_artisan_id_constraint(cursor)

    assert cursor.queries[-1] == "ALTER TABLE artisans ALTER COLUMN artisan_id SET NOT NULL"


@pytest.mark.parametrize(
    ("null_count", "duplicate", "message"),
    [
        (2, None, "2 NULL"),
        (0, "artisan/duplicate", "duplicate value exists"),
    ],
)
def test_invalid_existing_data_aborts_without_altering_or_regenerating(
    null_count, duplicate, message
):
    cursor = _Cursor(null_count=null_count, duplicate=duplicate)

    with pytest.raises(RuntimeError, match=message):
        _ensure_artisan_id_constraint(cursor)

    assert not any("ALTER TABLE" in query for query in cursor.queries)
