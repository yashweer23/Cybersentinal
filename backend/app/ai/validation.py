from app.ai.schemas import EvidencePlan


def validate_plan(value, catalog):
    plan = (
        EvidencePlan.model_validate_json(value)
        if isinstance(value, (str, bytes))
        else EvidencePlan.model_validate(value)
    )
    expected = catalog.context
    if (
        plan.incident_id != expected.incident_id
        or plan.context_hash != expected.context_hash
        or plan.risk_score != expected.data["incident"]["risk_score"]
    ):
        raise ValueError("Analysis identity or score mismatch")
    if "case" not in plan.summary_fact_ids:
        raise ValueError("Authoritative case summary missing")
    for keys, allowed in (
        (plan.summary_fact_ids, catalog.facts),
        (plan.evidence_fact_ids, catalog.facts),
        (plan.investigation_action_ids, catalog.investigations),
        (plan.recommendation_action_ids, catalog.recommendations),
    ):
        if len(keys) != len(set(keys)) or any(key not in allowed for key in keys):
            raise ValueError("Unknown or duplicate evidence/action reference")
    return plan
