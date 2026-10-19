import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ErrorBoundary from "../components/ErrorBoundary";

describe("operational recovery", () => {
  it("keeps the application visible when no error occurs", () => {
    render(
      <ErrorBoundary>
        <p>Workspace</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText("Workspace")).toBeInTheDocument();
  });
  it("offers recovery without displaying exception contents", () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    function Broken() {
      throw new Error("private-render-state");
    }
    try {
      render(
        <ErrorBoundary>
          <Broken />
        </ErrorBoundary>,
      );
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Something went wrong",
      );
      expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
      expect(
        screen.getByRole("link", { name: "Return to Overview" }),
      ).toHaveAttribute("href", "/");
      expect(
        screen.queryByText("private-render-state"),
      ).not.toBeInTheDocument();
    } finally {
      log.mockRestore();
    }
  });
});
