// src/lib/auth.ts
import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  signOut, 
  onAuthStateChanged,
  type User 
} from "firebase/auth";
import { auth } from "./firebase";

export async function registerUser(email: string, password: string) {
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    return { user: userCredential.user, error: null };
  } catch (error: any) {
    let message = "Error al registrar usuario.";
    if (error.code === "auth/email-already-in-use") message = "Este correo ya está registrado.";
    if (error.code === "auth/weak-password") message = "La contraseña debe tener al menos 6 caracteres.";
    if (error.code === "auth/invalid-email") message = "Correo electrónico inválido.";
    return { user: null, error: message };
  }
}

export async function loginUser(email: string, password: string) {
  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    return { user: userCredential.user, error: null };
  } catch (error: any) {
    let message = "Error al iniciar sesión.";
    if (error.code === "auth/user-not-found") message = "No existe una cuenta con este correo.";
    if (error.code === "auth/wrong-password") message = "Contraseña incorrecta.";
    if (error.code === "auth/invalid-credential") message = "Credenciales inválidas.";
    return { user: null, error: message };
  }
}

export async function logoutUser() {
  await signOut(auth);
}

export function onAuthChange(callback: (user: User | null) => void) {
  return onAuthStateChanged(auth, callback);
}

export function getCurrentUser(): User | null {
  return auth.currentUser;
}
