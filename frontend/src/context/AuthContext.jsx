import {
  createContext,
  useContext,
  useEffect,
  useSyncExternalStore,
} from "react";
import * as auth from "../services/auth";

const AuthContext = createContext(null);
export function AuthProvider({ children }) {
  const state = useSyncExternalStore(auth.subscribe, auth.getSnapshot);
  useEffect(() => {
    void auth.bootstrapSession();
  }, []);
  useEffect(() => {
    if (!state.user) return;
    const check = () => auth.refreshProfile().catch(auth.reportProfileError);
    const timer = setInterval(check, 60000);
    window.addEventListener("focus", check);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", check);
    };
  }, [state.user?.id]);
  return (
    <AuthContext.Provider value={{ ...state, ...auth }}>
      {children}
    </AuthContext.Provider>
  );
}
export function useAuth() {
  return useContext(AuthContext);
}
