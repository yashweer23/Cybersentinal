"""Conservative question routing. Unknown questions never receive a guessed answer."""

import re
from datetime import datetime

from app.ai.schemas import AnswerResponse


def answer_question(question, catalog):
    q = re.sub(r"[^a-z0-9 ]", " ", question.lower())
    data = catalog.context.data
    keys = []
    confidence = "LIMITED"
    answer = (
        "The available incident evidence does not establish this. "
        "Ask about risk, detection evidence, successful logins, "
        "cached reputation, the timeline, or investigation steps."
    )
    # Unsupported action/instruction requests must not be confused with evidence queries.
    prohibited = any(
        word in q.split()
        for word in (
            "execute",
            "delete",
            "drop",
            "sql",
            "shell",
            "secrets",
            "ignore",
            "payload",
            "exploit",
        )
    )
    if not prohibited and re.search(
        r"\b(successful|success)\b.*\b(login|logins|authentication)\b|\blogin\b.*\bsuccess", q
    ):
        successes = [
            (i, e) for i, e in enumerate(data["events"]) if e["event_type"] == "LOGIN_SUCCESS"
        ]
        after = any(word in q for word in ("after", "following"))
        matched = None
        for index, event in successes:
            prior = [
                (i, e)
                for i, e in enumerate(data["events"])
                if e["event_type"] == "LOGIN_FAILED"
                and e["account_alias"] is not None
                and e["account_alias"] == event["account_alias"]
                and e["timestamp"] < event["timestamp"]
            ]
            if after and prior:
                previous_index, previous = max(prior, key=lambda value: value[1]["timestamp"])
                seconds = (
                    datetime.fromisoformat(event["timestamp"])
                    - datetime.fromisoformat(previous["timestamp"])
                ).total_seconds()
                answer = (
                    f"Yes. A linked LOGIN_SUCCESS for the same account "
                    f"alias occurred {seconds:g} seconds after a linked "
                    f"LOGIN_FAILED event. This sequence does not establish "
                    f"whether the login was authorized."
                )
                keys = [f"event_{previous_index}", f"event_{index}"]
                matched = True
                break
            if not after:
                answer = (
                    "Yes. A LOGIN_SUCCESS event is present in the linked "
                    "evidence. A successful login alone does not establish "
                    "compromise."
                )
                keys, matched = [f"event_{index}"], True
                break
        if matched:
            confidence = "HIGH"
        elif after:
            answer = (
                "The available representative events do not establish "
                "a successful login after failures for the same account. "
                "Review the full linked event timeline; this is not a "
                "claim that no such login occurred."
            )
            confidence = "INSUFFICIENT"
        else:
            count = data["event_type_counts"].get("LOGIN_SUCCESS", 0)
            if count:
                answer = (
                    f"The linked evidence contains {count} LOGIN_SUCCESS "
                    f"records, but none is included in this bounded event "
                    f"sample. Review the full event evidence."
                )
                keys = ["count_LOGIN_SUCCESS"]
            else:
                answer = (
                    "No LOGIN_SUCCESS record is linked to this incident. "
                    "This does not establish that no successful login occurred "
                    "elsewhere."
                )
                keys, confidence = ["case"], "HIGH"
    elif not prohibited and any(word in q for word in ("risk", "critical", "score", "severity")):
        keys = ["case"] + catalog.risk_facts
        answer = " ".join(catalog.facts[k].statement for k in keys)
        confidence = "HIGH" if catalog.risk_facts else "LIMITED"
    elif not prohibited and any(
        word in q for word in ("reputation", "threat intelligence", "malicious ip")
    ):
        keys = catalog.intelligence_facts
        answer = " ".join(catalog.facts[k].statement for k in keys) or (
            "No cached threat intelligence is available in this incident "
            "context. No external lookup was performed."
        )
    elif not prohibited and any(
        word in q for word in ("investigate", "next step", "recommend", "defensive action")
    ):
        answer = (
            " ".join(catalog.investigations.values())
            + " "
            + " ".join(catalog.recommendations.values())
        )
        keys = catalog.finding_facts[:5] or ["case"]
    elif not prohibited and any(word in q for word in ("timeline", "status change")):
        keys = [k for k in catalog.facts if k.startswith("timeline_")]
        answer = (
            " ".join(catalog.facts[k].statement for k in keys)
            or "No supported workflow action is available in the bounded timeline context."
        )
    elif not prohibited and any(
        word in q
        for word in ("evidence", "flagged", "detect", "what happened", "summar", "findings relate")
    ):
        keys = ["case"] + catalog.finding_facts[:5]
        answer = " ".join(catalog.facts[k].statement for k in keys)
        if "relate" in q:
            answer += (
                " These findings are linked by the existing correlation "
                "engine. Review each finding's recorded relationship "
                "in the Findings tab; this explanation does not create "
                "new correlations."
            )
    references = list(dict.fromkeys(r for k in keys for r in catalog.facts[k].reference_ids))
    return AnswerResponse(
        incident_id=catalog.context.incident_id,
        analysis_mode="FALLBACK",
        answer=answer,
        evidence_ids=references,
        references=[catalog.references[r] for r in references],
        confidence=confidence if keys else "INSUFFICIENT",
        uncertainty=(
            "Controlled evidence query, not a general chatbot. Results "
            "cover only this incident's linked evidence; representative "
            "samples can omit relevant sequences."
        ),
        context_hash=catalog.context.context_hash,
        context_build_ms=catalog.context.build_ms,
        provider_duration_ms=0,
        duration_ms=0,
    )
