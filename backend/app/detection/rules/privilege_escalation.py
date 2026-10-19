from app.detection.base import DetectionMatch, Rule, label, raw, successful


def role(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return "ADMIN" if normalized in {"ADMINISTRATOR", "ADMIN"} else normalized


class PrivilegeEscalation(Rule):
    rule_id, title = "CS-005", "Administrator privilege change requires review"
    types = ("PRIVILEGE_CHANGE",)

    def evaluate(self, events, candidates, config):
        targets = {role(value) for value in config.target_privileges}
        for event in events:
            if (
                event.id not in candidates
                or not self.applicable(event, config)
                or not successful(event)
            ):
                continue
            data = raw(event)
            before, after = role(data.get("previous_role")), role(data.get("new_role"))
            approval = label(data.get("approval_reference"))
            if not before or after not in targets or before in targets:
                continue
            if config.require_approval_reference and approval and approval.strip():
                continue
            yield DetectionMatch(
                self.rule_id,
                self.title,
                "The logged account gained a privileged role without meeting the "
                "configured approval policy. This is suspicious activity requiring "
                "review, not a confirmed compromise.",
                (event.username or str(event.source_ip),),
                event,
                [event],
                {
                    "previous_role": before,
                    "new_role": after,
                    "changed_by": label(data.get("changed_by")),
                    "target_user": event.username,
                    "approval_reference": approval,
                },
                85,
            )
