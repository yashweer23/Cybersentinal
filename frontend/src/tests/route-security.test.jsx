import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import ProtectedRoute from "../components/ProtectedRoute";
const auth = vi.hoisted(() => ({ status: "ready", user: null }));
vi.mock("../context/AuthContext", () => ({ useAuth: () => auth }));
beforeEach(() => {
  auth.status = "ready";
  auth.user = null;
  auth.error = "Connection unavailable";
  auth.retrySession = vi.fn();
});
function mount() {
  return render(
    <MemoryRouter initialEntries={["/admin"]}>
      <Routes>
        <Route path="/login" element={<h1>Sign in</h1>} />
        <Route element={<ProtectedRoute roles={["ADMIN"]} />}>
          <Route path="/admin" element={<h1>Protected settings</h1>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}
it("redirects an anonymous direct URL before mounting protected content", () => {
  mount();
  expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  expect(screen.queryByText("Protected settings")).not.toBeInTheDocument();
});
it.each(["VIEWER", "ANALYST"])("denies a direct admin URL to %s", (role) => {
  auth.user = { role, username: "<img src=x onerror=alert(1)>" };
  const { container } = mount();
  expect(
    screen.getByText("Administrator access required."),
  ).toBeInTheDocument();
  expect(screen.queryByText("Protected settings")).not.toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(container.textContent).toContain(auth.user.username);
});
it("allows an administrator", () => {
  auth.user = { role: "ADMIN", username: "admin" };
  mount();
  expect(screen.getByText("Protected settings")).toBeInTheDocument();
});
it("does not show protected content while session verification is pending", () => {
  auth.status = "loading";
  mount();
  expect(screen.getByRole("status")).toHaveTextContent("Checking your session");
  expect(screen.queryByText("Protected settings")).not.toBeInTheDocument();
});
it("offers retry on a session network error without treating it as logout", () => {
  auth.status = "error";
  mount();
  expect(screen.getByRole("alert")).toHaveTextContent("Connection unavailable");
  fireEvent.click(screen.getByRole("button", { name: "Retry connection" }));
  expect(auth.retrySession).toHaveBeenCalledOnce();
  expect(
    screen.queryByRole("heading", { name: "Sign in" }),
  ).not.toBeInTheDocument();
});
