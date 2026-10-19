"""Query-count regression with a cold ORM identity map and many related records."""

from sqlalchemy import event as sql_event
from sqlalchemy import select

from app.models import IncidentComment, User
from tests.test_incident_engine import case, run
from tests.test_incident_engine import http as http
from tests.test_incident_engine import scored as scored
from tests.test_incident_engine import settings as settings
from tests.test_incident_engine import tokens as tokens


def measured_request(db, http, path, headers):
    db.expunge_all()
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(("SELECT", "WITH")):
            statements.append(statement)

    connection = db.connection()
    sql_event.listen(connection, "before_cursor_execute", capture)
    try:
        response = http.get(path, headers=headers)
    finally:
        sql_event.remove(connection, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    return response.json(), len(statements)


def test_investigation_pages_remain_bounded_without_per_record_queries(
    db, http, tokens, scored, settings
):
    scored(80)
    run(db, settings)
    path = f"/api/incidents/{case(db).incident_id}"
    baseline, small_queries = measured_request(db, http, path, tokens["ANALYST"])
    assert baseline["findings"]["total"] == 1
    for index in range(1, 56):
        scored(80, minutes=index)
    run(db, settings, until_empty=True)
    row = case(db)
    author = db.scalar(select(User).where(User.username == "analyst"))
    for index in range(60):
        db.add(IncidentComment(incident_id=row.id, user_id=author.id, comment=f"Note {index}"))
    db.commit()
    expanded, large_queries = measured_request(db, http, path, tokens["ANALYST"])
    assert expanded["findings"]["total"] == 56
    assert len(expanded["findings"]["items"]) == len(expanded["comments"]["items"]) == 20
    assert expanded["comments"]["total"] == 60
    assert expanded["evidence_total"] == 56 and len(expanded["evidence"]) == 50
    assert large_queries <= small_queries + 2 and large_queries < 30
    first = http.get(path + "/events?limit=30", headers=tokens["VIEWER"]).json()
    second = http.get(path + "/events?limit=30&offset=30", headers=tokens["VIEWER"]).json()
    ids = [e["event_id"] for e in first["items"] + second["items"]]
    assert len(ids) == len(set(ids)) == 56
