import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_PATH = Path(__file__).parent / "incidents.db"
CORRELATION_WINDOW_MINUTES = 15

SEVERITY_RANK = {
    "Unknown": 0,
    "Low": 1,
    "Medium": 2,
    "Error": 2,
    "High": 3,
    "Critical": 4,
}


def get_connection():
    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=10,
    )
    conn.row_factory = sqlite3.Row
    return conn


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _group_key(source, incident_type, category):
    """
    Build the identity used to correlate repeated events into one incident.

    We deliberately do NOT include the full raw log message here.
    Multiple log records from the same source/type/category inside the
    correlation window are treated as events belonging to one incident.
    """
    raw = "|".join(
        [
            str(source or "").strip().lower(),
            str(incident_type or "").strip().lower(),
            str(category or "").strip().lower(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _higher_severity(current, incoming):
    current = current or "Unknown"
    incoming = incoming or "Unknown"

    if SEVERITY_RANK.get(incoming, 0) > SEVERITY_RANK.get(current, 0):
        return incoming
    return current


def initialize_database():
    """Create/migrate the persistent incident database."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE,
            created_at TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            resolved_at TEXT,
            source TEXT,
            incident_type TEXT,
            severity TEXT,
            category TEXT,
            message TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            group_key TEXT,
            event_count INTEGER NOT NULL DEFAULT 1,
            rca_report TEXT,
            rca_confidence INTEGER,
            rca_evidence TEXT,
            rca_generated_at TEXT
        )
        """
    )


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            correlation_id TEXT UNIQUE,
            created_at TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            sources TEXT,
            reasons TEXT,
            status TEXT NOT NULL DEFAULT 'Open'
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS correlation_members (
            correlation_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            PRIMARY KEY (correlation_id, incident_id)
        )
        """
    )

    cursor.execute("PRAGMA table_info(incidents)")
    existing_columns = {row["name"] for row in cursor.fetchall()}

    required_columns = {
        "incident_id": "TEXT",
        "created_at": "TEXT",
        "first_seen": "TEXT",
        "last_seen": "TEXT",
        "resolved_at": "TEXT",
        "source": "TEXT",
        "incident_type": "TEXT",
        "severity": "TEXT",
        "category": "TEXT",
        "message": "TEXT",
        "status": "TEXT DEFAULT 'Open'",
        "group_key": "TEXT",
        "event_count": "INTEGER DEFAULT 1",
        "rca_report": "TEXT",
        "rca_confidence": "INTEGER",
        "rca_evidence": "TEXT",
        "rca_generated_at": "TEXT",
    }

    for column_name, column_type in required_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE incidents ADD COLUMN {column_name} {column_type}"
            )

    # Backfill new columns for older databases.
    cursor.execute(
        """
        UPDATE incidents
        SET first_seen = COALESCE(first_seen, created_at),
            last_seen = COALESCE(last_seen, created_at),
            event_count = COALESCE(event_count, 1)
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_group_key
        ON incidents(group_key)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incidents_status
        ON incidents(status)
        """
    )

    # Backfill group keys.
    cursor.execute(
        """
        SELECT id, source, incident_type, category
        FROM incidents
        WHERE group_key IS NULL OR group_key = ''
        """
    )
    rows = cursor.fetchall()
    for row in rows:
        cursor.execute(
            "UPDATE incidents SET group_key = ? WHERE id = ?",
            (
                _group_key(
                    row["source"],
                    row["incident_type"],
                    row["category"],
                ),
                row["id"],
            ),
        )

    conn.commit()
    conn.close()

    # Merge old duplicate rows created before aggregation was introduced.
    consolidate_existing_incidents()


def consolidate_existing_incidents():
    """
    Merge historical duplicate rows into incident groups.

    Rows with the same source/type/category created within the configured
    correlation window are collapsed into one incident. This fixes databases
    created by the earlier implementation where every matching log line was
    stored as a separate incident.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY group_key, first_seen, id
        """
    )
    rows = [dict(row) for row in cursor.fetchall()]

    grouped = {}
    for row in rows:
        grouped.setdefault(row.get("group_key"), []).append(row)

    ids_to_delete = []

    for _, group_rows in grouped.items():
        if not group_rows:
            continue

        clusters = []
        current_cluster = []

        for row in group_rows:
            row_time = _parse_iso(row.get("first_seen") or row.get("created_at"))

            if not current_cluster:
                current_cluster = [row]
                continue

            previous = current_cluster[-1]
            previous_time = _parse_iso(
                previous.get("last_seen")
                or previous.get("first_seen")
                or previous.get("created_at")
            )

            if (
                row_time
                and previous_time
                and row_time - previous_time
                <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
            ):
                current_cluster.append(row)
            else:
                clusters.append(current_cluster)
                current_cluster = [row]

        if current_cluster:
            clusters.append(current_cluster)

        for cluster in clusters:
            if len(cluster) <= 1:
                continue

            keeper = cluster[0]
            total_events = sum(int(item.get("event_count") or 1) for item in cluster)

            first_seen_values = [
                _parse_iso(item.get("first_seen") or item.get("created_at"))
                for item in cluster
            ]
            first_seen_values = [x for x in first_seen_values if x]

            last_seen_values = [
                _parse_iso(item.get("last_seen") or item.get("created_at"))
                for item in cluster
            ]
            last_seen_values = [x for x in last_seen_values if x]

            severity = keeper.get("severity") or "Unknown"
            for item in cluster[1:]:
                severity = _higher_severity(severity, item.get("severity"))

            statuses = {str(item.get("status") or "Open") for item in cluster}
            if "Open" in statuses:
                status = "Open"
                resolved_at = None
            elif "Investigating" in statuses:
                status = "Investigating"
                resolved_at = None
            else:
                status = "Resolved"
                resolved_times = [
                    _parse_iso(item.get("resolved_at"))
                    for item in cluster
                    if item.get("resolved_at")
                ]
                resolved_times = [x for x in resolved_times if x]
                resolved_at = max(resolved_times).isoformat() if resolved_times else None

            # Keep the newest message as representative evidence.
            representative = cluster[-1]

            cursor.execute(
                """
                UPDATE incidents
                SET first_seen = ?,
                    last_seen = ?,
                    event_count = ?,
                    severity = ?,
                    message = ?,
                    status = ?,
                    resolved_at = ?
                WHERE id = ?
                """,
                (
                    min(first_seen_values).isoformat() if first_seen_values else keeper.get("created_at"),
                    max(last_seen_values).isoformat() if last_seen_values else keeper.get("created_at"),
                    total_events,
                    severity,
                    representative.get("message"),
                    status,
                    resolved_at,
                    keeper["id"],
                ),
            )

            ids_to_delete.extend(item["id"] for item in cluster[1:])

    if ids_to_delete:
        placeholders = ",".join("?" for _ in ids_to_delete)
        cursor.execute(
            f"DELETE FROM incidents WHERE id IN ({placeholders})",
            ids_to_delete,
        )

    conn.commit()
    conn.close()


def save_incident(
    source,
    incident_type,
    severity,
    category,
    message,
    event_time=None,
):
    """
    Save or aggregate an event.

    Returns:
        tuple(incident_id, created_new)

    Repeated events with the same source/type/category inside the 15-minute
    correlation window update the existing incident instead of creating a
    new incident.
    """
    initialize_database()

    now = datetime.now(timezone.utc)
    observed_at = _parse_iso(event_time) or now
    group_key = _group_key(source, incident_type, category)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        WHERE group_key = ?
          AND status IN ('Open', 'Investigating')
        ORDER BY last_seen DESC, id DESC
        LIMIT 1
        """,
        (group_key,),
    )
    existing = cursor.fetchone()

    if existing:
        existing_last_seen = _parse_iso(
            existing["last_seen"]
            or existing["first_seen"]
            or existing["created_at"]
        )

        if (
            existing_last_seen
            and abs(observed_at - existing_last_seen)
            <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
        ):
            updated_severity = _higher_severity(
                existing["severity"],
                severity,
            )

            cursor.execute(
                """
                UPDATE incidents
                SET last_seen = ?,
                    event_count = COALESCE(event_count, 1) + 1,
                    severity = ?,
                    message = ?
                WHERE id = ?
                """,
                (
                    max(observed_at, existing_last_seen).isoformat(),
                    updated_severity,
                    str(message),
                    existing["id"],
                ),
            )
            conn.commit()
            incident_id = existing["incident_id"]
            conn.close()
            return incident_id, False

    created_at = now.isoformat()
    observed_iso = observed_at.isoformat()

    cursor.execute(
        """
        INSERT INTO incidents (
            created_at,
            first_seen,
            last_seen,
            source,
            incident_type,
            severity,
            category,
            message,
            status,
            group_key,
            event_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (
            created_at,
            observed_iso,
            observed_iso,
            source,
            incident_type,
            severity,
            category,
            str(message),
            "Open",
            group_key,
        ),
    )

    database_id = cursor.lastrowid
    incident_id = f"INC-{database_id:05d}"

    cursor.execute(
        """
        UPDATE incidents
        SET incident_id = ?
        WHERE id = ?
        """,
        (incident_id, database_id),
    )

    conn.commit()
    conn.close()
    return incident_id, True


def save_detected_incidents(
    structured_data,
    default_source="Unknown Source",
):
    """
    Persist parser output.

    Returns only IDs for genuinely new incidents. Repeated events are counted
    against an existing incident but are not reported as new incidents.
    """
    new_incident_ids = []

    for incident in structured_data or []:
        if not isinstance(incident, dict):
            continue

        incident_id, created_new = save_incident(
            source=incident.get("Source", default_source),
            incident_type=incident.get("Type", "Unknown"),
            severity=incident.get("Severity", "Unknown"),
            category=incident.get("Category", "Other"),
            message=incident.get("Message", str(incident)),
            event_time=incident.get("Timestamp"),
        )

        if created_new:
            new_incident_ids.append(incident_id)

    return new_incident_ids


def list_incidents(limit=200):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            incident_id,
            created_at,
            first_seen,
            last_seen,
            source,
            incident_type,
            severity,
            category,
            event_count,
            message,
            status,
            resolved_at,
            rca_confidence,
            rca_generated_at
        FROM incidents
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "Incident ID": row["incident_id"],
            "Created At": row["created_at"],
            "First Seen": row["first_seen"],
            "Last Seen": row["last_seen"],
            "Source": row["source"],
            "Type": row["incident_type"],
            "Severity": row["severity"],
            "Category": row["category"],
            "Events": int(row["event_count"] or 1),
            "Message": row["message"],
            "Status": row["status"],
            "Resolved At": row["resolved_at"],
            "RCA Confidence": row["rca_confidence"],
            "RCA Generated At": row["rca_generated_at"],
        }
        for row in rows
    ]


def update_incident_status(incident_id, new_status):
    valid_statuses = {"Open", "Investigating", "Resolved"}

    if new_status not in valid_statuses:
        raise ValueError(
            "Status must be Open, Investigating, or Resolved."
        )

    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    resolved_at = _now_iso() if new_status == "Resolved" else None

    cursor.execute(
        """
        UPDATE incidents
        SET status = ?, resolved_at = ?
        WHERE incident_id = ?
        """,
        (new_status, resolved_at, incident_id),
    )

    conn.commit()
    conn.close()


def get_incident_counts():
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT status, COUNT(*)
        FROM incidents
        GROUP BY status
        """
    )

    results = dict(cursor.fetchall())
    conn.close()

    return {
        "Open": int(results.get("Open", 0)),
        "Investigating": int(results.get("Investigating", 0)),
        "Resolved": int(results.get("Resolved", 0)),
    }


def calculate_mttr_minutes():
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT created_at, resolved_at
        FROM incidents
        WHERE status = 'Resolved'
          AND resolved_at IS NOT NULL
        """
    )

    rows = cursor.fetchall()
    conn.close()

    durations = []

    for row in rows:
        created = _parse_iso(row["created_at"])
        resolved = _parse_iso(row["resolved_at"])

        if created and resolved and resolved >= created:
            durations.append((resolved - created).total_seconds() / 60)

    if not durations:
        return 0

    return round(sum(durations) / len(durations), 2)


def get_incident(incident_id):
    """Return one incident, including any saved RCA fields."""
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM incidents
        WHERE incident_id = ?
        LIMIT 1
        """,
        (incident_id,),
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    incident = dict(row)

    raw_evidence = incident.get("rca_evidence")
    if raw_evidence:
        try:
            incident["rca_evidence"] = json.loads(raw_evidence)
        except (json.JSONDecodeError, TypeError):
            incident["rca_evidence"] = [str(raw_evidence)]
    else:
        incident["rca_evidence"] = []

    return incident


def save_incident_rca(
    incident_id,
    rca_report,
    confidence,
    evidence,
):
    """Persist RCA output and evidence for one correlated incident."""
    initialize_database()

    confidence = int(max(0, min(100, int(confidence))))
    generated_at = _now_iso()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET rca_report = ?,
            rca_confidence = ?,
            rca_evidence = ?,
            rca_generated_at = ?
        WHERE incident_id = ?
        """,
        (
            str(rca_report),
            confidence,
            json.dumps(
                evidence or [],
                ensure_ascii=False,
                default=str,
            ),
            generated_at,
            incident_id,
        ),
    )

    if cursor.rowcount == 0:
        conn.close()
        raise ValueError(f"Incident {incident_id} was not found.")

    conn.commit()
    conn.close()
    return generated_at


def clear_incident_rca(incident_id):
    """Remove the stored RCA so the user can regenerate it."""
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE incidents
        SET rca_report = NULL,
            rca_confidence = NULL,
            rca_evidence = NULL,
            rca_generated_at = NULL
        WHERE incident_id = ?
        """,
        (incident_id,),
    )

    conn.commit()
    conn.close()


def _correlation_signature(incident_ids):
    """
    Stable signature for a set of child incidents.
    """
    cleaned = sorted(
        {
            str(value).strip()
            for value in incident_ids or []
            if str(value).strip()
        }
    )
    raw = "|".join(cleaned)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_correlation_group(group):
    """
    Create or update a parent correlation group.

    Existing child incidents remain unchanged.
    """
    initialize_database()

    incident_ids = sorted(
        {
            str(value)
            for value in group.get("incident_ids", [])
            if value
        }
    )

    if len(incident_ids) < 2:
        return None, False

    signature = _correlation_signature(incident_ids)

    conn = get_connection()
    cursor = conn.cursor()

    # Find existing group with the exact same members.
    cursor.execute(
        """
        SELECT c.correlation_id
        FROM correlations c
        JOIN correlation_members cm
          ON c.correlation_id = cm.correlation_id
        GROUP BY c.correlation_id
        HAVING GROUP_CONCAT(cm.incident_id, '|') IS NOT NULL
        """
    )

    existing_ids = [
        row["correlation_id"]
        for row in cursor.fetchall()
    ]

    for correlation_id in existing_ids:
        cursor.execute(
            """
            SELECT incident_id
            FROM correlation_members
            WHERE correlation_id = ?
            ORDER BY incident_id
            """,
            (correlation_id,),
        )

        members = [
            row["incident_id"]
            for row in cursor.fetchall()
        ]

        if _correlation_signature(members) == signature:
            cursor.execute(
                """
                UPDATE correlations
                SET confidence = ?,
                    sources = ?,
                    reasons = ?,
                    first_seen = ?,
                    last_seen = ?
                WHERE correlation_id = ?
                """,
                (
                    int(group.get("confidence") or 0),
                    json.dumps(group.get("sources") or []),
                    json.dumps(group.get("reasons") or []),
                    group.get("first_seen"),
                    group.get("last_seen"),
                    correlation_id,
                ),
            )

            conn.commit()
            conn.close()
            return correlation_id, False

    cursor.execute(
        """
        INSERT INTO correlations (
            created_at,
            first_seen,
            last_seen,
            confidence,
            sources,
            reasons,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'Open')
        """,
        (
            _now_iso(),
            group.get("first_seen"),
            group.get("last_seen"),
            int(group.get("confidence") or 0),
            json.dumps(group.get("sources") or []),
            json.dumps(group.get("reasons") or []),
        ),
    )

    db_id = cursor.lastrowid
    correlation_id = f"CORR-{db_id:05d}"

    cursor.execute(
        """
        UPDATE correlations
        SET correlation_id = ?
        WHERE id = ?
        """,
        (
            correlation_id,
            db_id,
        ),
    )

    for incident_id in incident_ids:
        cursor.execute(
            """
            INSERT OR IGNORE INTO correlation_members (
                correlation_id,
                incident_id
            )
            VALUES (?, ?)
            """,
            (
                correlation_id,
                incident_id,
            ),
        )

    conn.commit()
    conn.close()
    return correlation_id, True


def list_correlations(limit=100):
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM correlations
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )

    correlations = []

    for row in cursor.fetchall():
        item = dict(row)

        cursor.execute(
            """
            SELECT incident_id
            FROM correlation_members
            WHERE correlation_id = ?
            ORDER BY incident_id
            """,
            (item["correlation_id"],),
        )

        item["incident_ids"] = [
            member["incident_id"]
            for member in cursor.fetchall()
        ]

        for field in ("sources", "reasons"):
            raw = item.get(field)

            if raw:
                try:
                    item[field] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    item[field] = [str(raw)]
            else:
                item[field] = []

        correlations.append(item)

    conn.close()
    return correlations


def get_correlation(correlation_id):
    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM correlations
        WHERE correlation_id = ?
        LIMIT 1
        """,
        (correlation_id,),
    )

    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    result = dict(row)

    cursor.execute(
        """
        SELECT incident_id
        FROM correlation_members
        WHERE correlation_id = ?
        ORDER BY incident_id
        """,
        (correlation_id,),
    )

    incident_ids = [
        member["incident_id"]
        for member in cursor.fetchall()
    ]

    child_incidents = []

    for incident_id in incident_ids:
        cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        )

        child = cursor.fetchone()

        if child:
            child_incidents.append(dict(child))

    conn.close()

    result["incident_ids"] = incident_ids
    result["incidents"] = child_incidents

    for field in ("sources", "reasons"):
        raw = result.get(field)

        if raw:
            try:
                result[field] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                result[field] = [str(raw)]
        else:
            result[field] = []

    return result


def update_correlation_status(correlation_id, status):
    if status not in {"Open", "Investigating", "Resolved"}:
        raise ValueError(
            "Correlation status must be Open, Investigating, or Resolved."
        )

    initialize_database()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE correlations
        SET status = ?
        WHERE correlation_id = ?
        """,
        (
            status,
            correlation_id,
        ),
    )

    conn.commit()
    conn.close()
