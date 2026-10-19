import { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

export default function Dialog({
  title,
  children,
  onClose,
  busy = false,
  drawer = false,
}) {
  const panel = useRef(null),
    titleId = useId();
  const close = useRef(onClose),
    pending = useRef(busy);
  close.current = onClose;
  pending.current = busy;
  useEffect(() => {
    const previous = document.activeElement;
    const bodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const focusables = () =>
      [
        ...panel.current.querySelectorAll(
          'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], summary, [tabindex="0"]',
        ),
      ].filter((el) => {
        const closed = el.closest("details:not([open])");
        return (
          !el.closest("[hidden]") &&
          (!closed || el === closed.querySelector("summary"))
        );
      });
    (focusables()[0] || panel.current).focus();
    function keydown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (!pending.current) close.current();
      }
      if (event.key === "Tab") {
        const nodes = focusables(),
          first = nodes[0],
          last = nodes.at(-1);
        if (!first) {
          event.preventDefault();
          panel.current.focus();
        } else if (
          event.shiftKey &&
          (document.activeElement === first ||
            !panel.current.contains(document.activeElement))
        ) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          (document.activeElement === last ||
            !panel.current.contains(document.activeElement))
        ) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    document.addEventListener("keydown", keydown, true);
    return () => {
      document.removeEventListener("keydown", keydown, true);
      document.body.style.overflow = bodyOverflow;
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return createPortal(
    <div
      className={`case-overlay ${drawer ? "case-drawer-overlay" : ""}`}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <section
        className={`case-dialog ${drawer ? "case-drawer" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={panel}
        aria-busy={busy}
      >
        <div className="case-dialog-heading">
          <h2 id={titleId}>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            disabled={busy}
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
        <div className="case-dialog-body">{children}</div>
      </section>
    </div>,
    document.body,
  );
}
