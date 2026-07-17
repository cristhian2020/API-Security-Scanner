// src/components/Register.tsx
import { useState } from "react";
import { registerUser } from "../lib/auth";

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Las contraseñas no coinciden.");
      return;
    }

    if (password.length < 6) {
      setError("La contraseña debe tener al menos 6 caracteres.");
      return;
    }

    setLoading(true);
    const result = await registerUser(email, password);

    if (result.error) {
      setError(result.error);
      setLoading(false);
    } else {
      window.location.href = "/";
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <span className="text-6xl">🛡️</span>
          <h2 className="text-3xl font-bold text-white mt-4">Crear Cuenta</h2>
          <p className="text-slate-400 mt-2">Registra tu cuenta para comenzar a escanear</p>
        </div>

        {/* Card */}
        <div className="glass-card p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-xl text-sm">
                ⚠️ {error}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Correo electrónico</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-dark"
                placeholder="tu@email.com"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Contraseña</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-dark"
                placeholder="Mínimo 6 caracteres"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Confirmar Contraseña</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="input-dark"
                placeholder="Repite tu contraseña"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Creando cuenta...
                </>
              ) : (
                "Crear Cuenta"
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-sm text-slate-400">
              ¿Ya tienes cuenta?{" "}
              <a href="/login" className="text-purple-400 hover:text-purple-300 font-medium transition-colors">
                Inicia sesión
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
