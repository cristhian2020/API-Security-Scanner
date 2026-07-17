// src/components/Navbar.tsx
import { useState, useEffect } from "react";
import { onAuthChange, logoutUser } from "../lib/auth";
import type { User } from "firebase/auth";

export default function Navbar() {
  const [user, setUser] = useState<User | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthChange((u) => setUser(u));
    return () => unsubscribe();
  }, []);

  const handleLogout = async () => {
    await logoutUser();
    window.location.href = "/login";
  };

  return (
    <header className="sticky top-0 z-50 border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
        {/* Logo */}
        <a href="/" className="flex items-center gap-3 group">
          <span className="text-3xl">🔒</span>
          <div>
            <h1 className="text-xl font-bold text-white group-hover:text-purple-400 transition-colors">
              API Security Scanner
            </h1>
            <p className="text-xs text-slate-400">DevSecOps Tool</p>
          </div>
        </a>

        {/* Navigation */}
        {user ? (
          <nav className="flex items-center gap-2">
            <a href="/"
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 transition-all">
              🚀 Escanear
            </a>
            <a href="/dashboard"
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 transition-all">
              📊 Dashboard
            </a>
            <a href="/history"
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 transition-all">
              📋 Historial
            </a>

            {/* User Menu */}
            <div className="relative ml-2">
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600/50 transition-all"
              >
                <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-xs font-bold text-white">
                  {user.email?.charAt(0).toUpperCase()}
                </div>
                <span className="text-sm text-slate-300 hidden md:inline">{user.email}</span>
                <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {menuOpen && (
                <div className="absolute right-0 mt-2 w-48 rounded-xl bg-slate-800 border border-slate-700 shadow-2xl py-2 z-50">
                  <button
                    onClick={handleLogout}
                    className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-slate-700 transition-colors"
                  >
                    🚪 Cerrar Sesión
                  </button>
                </div>
              )}
            </div>
          </nav>
        ) : (
          <nav className="flex items-center gap-3">
            <a href="/login"
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 transition-all">
              Iniciar Sesión
            </a>
            <a href="/register"
              className="btn-primary text-sm !py-2 !px-5">
              Registrarse
            </a>
          </nav>
        )}
      </div>
    </header>
  );
}
