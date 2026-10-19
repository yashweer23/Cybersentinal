import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Send } from "lucide-react";
import { askIncident } from "../../services/aiApi";
import { Badge, Panel, ErrorState } from "../common/UI";
import EvidenceLinks from "./EvidenceLinks";
const prompts = [
  "Why is the risk score high?",
  "Was there a successful login after failures?",
  "Which evidence is most important?",
  "What should I investigate next?",
  "What does the threat intelligence show?",
];
export default function IncidentQuestions({ incidentId, enabled }) {
  const [question, setQuestion] = useState(""),
    [asked, setAsked] = useState("");
  const mutation = useMutation({
    mutationKey: ["ai-question", incidentId],
    mutationFn: (value) => askIncident(incidentId, value),
    retry: false,
    onSuccess: (_, value) => setAsked(value),
  });
  return (
    <Panel
      title="Ask about this incident"
      subtitle="Controlled evidence queries · no external AI call"
    >
      <div className="ai-question-body">
        <div className="ai-prompts">
          {prompts.map((p) => (
            <button
              type="button"
              key={p}
              className="button secondary small"
              onClick={() => setQuestion(p)}
              disabled={!enabled || mutation.isPending}
            >
              {p}
            </button>
          ))}
        </div>
        <form
          className="ai-question-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (enabled && question.trim().length >= 3 && !mutation.isPending)
              mutation.mutate(question.trim());
          }}
        >
          <label htmlFor="incident-ai-question">Ask about this incident</label>
          <textarea
            id="incident-ai-question"
            placeholder="Ask about the linked evidence…"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            minLength={3}
            maxLength={800}
            disabled={!enabled || mutation.isPending}
            rows={2}
          />
          <button
            className="button"
            disabled={
              !enabled || mutation.isPending || question.trim().length < 3
            }
          >
            <Send size={15} />
            {mutation.isPending ? "Checking evidence…" : "Ask question"}
          </button>
        </form>
        {mutation.isError && <ErrorState error={mutation.error} />}
        {mutation.data && (
          <div className="ai-answer" role="status">
            <div className="inline-badges">
              <Badge>DETERMINISTIC FALLBACK</Badge>
              <Badge>{mutation.data.confidence} EVIDENCE</Badge>
            </div>
            <h3>{asked}</h3>
            <p>{mutation.data.answer}</p>
            <EvidenceLinks
              ids={mutation.data.evidence_ids}
              references={mutation.data.references}
              incidentId={incidentId}
            />
            <p className="muted">{mutation.data.uncertainty}</p>
            <small className="muted">
              Answer uses evidence as of this request; ask again after evidence
              changes.
            </small>
          </div>
        )}
      </div>
    </Panel>
  );
}
