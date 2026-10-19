import { useQuery } from "@tanstack/react-query";
import { getEvent } from "../../services/incidentsApi";
import { QueryState, Badge } from "../common/UI";
import { utc } from "../../utils/format";
import { EvidenceFields, RawData } from "./EvidenceFields";
import Dialog from "./Dialog";
export default function EventDetailDrawer({ eventId, close }) {
  const query = useQuery({
    queryKey: ["event", eventId],
    queryFn: ({ signal }) => getEvent(eventId, signal),
  });
  return (
    <Dialog title="Security event evidence" onClose={close} drawer>
      <QueryState query={query}>
        {(data) => (
          <>
            <div className="inline-badges">
              <Badge>{data.event_type}</Badge>
              <Badge>{data.status}</Badge>
            </div>
            <p className="mono case-event-id">{data.event_id}</p>
            <EvidenceFields
              data={{
                timestamp: utc(data.timestamp),
                source_ip: data.source_ip,
                destination_ip: data.destination_ip,
                username: data.username,
                device: data.device,
                service: data.service,
                source_port: data.source_port,
                destination_port: data.destination_port,
                country: data.country,
                user_agent: data.user_agent,
                status: data.status,
              }}
            />
            <p className="info-note">
              Read-only original evidence. Investigation actions do not rewrite
              this event.
            </p>
            <RawData title="Raw event data" value={data.raw_data} />
          </>
        )}
      </QueryState>
    </Dialog>
  );
}
