# API Vulnerability Scanner

Herramienta automatizada para la detección de vulnerabilidades en APIs. Combina un potente motor de escaneo backend (basado en VulnAPI y Fuzzing Activo) con un moderno panel de control en React.

## 🚀 Características Principales

*   **Escaneo Pasivo y Activo:** Detecta configuraciones de seguridad deficientes, problemas de autenticación, falta de CORS, SQL Injection, Rate Limiting y más.
*   **Reportes Detallados:** Explicaciones en español, evaluación CVSS, soluciones OWASP y ejemplos de código para remediar las vulnerabilidades.
*   **Soporte OpenAPI:** Escanea tanto URLs directas como especificaciones OpenAPI / Swagger.
*   **Historial y Dashboard:** Integración con Firebase para guardar y visualizar estadísticas y tendencias históricas de los escaneos.
*   **Exportación:** Descarga de reportes en PDF y JSON.

---

## 🛠️ Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

1.  **Python 3.8+**
2.  **Node.js 16+** y npm
3.  **VulnAPI:** Necesitas tener instalado el ejecutable de `vulnapi` en tu sistema y accesible globalmente (en tu PATH). 
    *   *Instalación (Linux/Mac):* `curl -sL https://raw.githubusercontent.com/cerberauth/vulnapi/main/install.sh | bash`
    *   *Instalación (Windows):* Windows: Instalación mediante Chocolatey, abre una terminal de PowerShell o el Símbolo del sistema y ejecuta el siguiente comando.  `choco install vulnapi`


---

## ⚙️ Configuración y Ejecución

El proyecto está dividido en dos partes: el **Backend** (FastAPI) y el **Frontend** (React/Vite). Debes ejecutar ambos simultáneamente.

### 1. Configurar el Backend (FastAPI)

En la raíz del proyecto:

1.  **Instala las dependencias de Python:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Configura Firebase:**
    Asegúrate de colocar tu archivo de credenciales de servicio de Firebase en la raíz del proyecto y nombrarlo exactamente `firebase-credentials.json`.

3.  **Inicia el servidor backend:**
    ```bash
    python -m uvicorn web.api:app --reload
    ```
    El servidor backend se ejecutará por defecto en `http://127.0.0.1:8000`.

### 2. Configurar el Frontend (React)

En una nueva terminal, navega a la carpeta `frontend`:

1.  **Ingresa al directorio del frontend:**
    ```bash
    cd frontend
    ```

2.  **Instala las dependencias de Node.js:**
    ```bash
    npm install
    ```

3.  **Inicia el servidor de desarrollo:**
    ```bash
    npm run dev
    ```
    El frontend normalmente se levantará en `http://localhost:4321` (u otro puerto que indique la terminal).

---

## 💻 Uso

1.  Abre la URL del Frontend (ej. `http://localhost:4321`) en tu navegador.
2.  Inicia sesión o regístrate usando el formulario de autenticación de Firebase.
3.  Ve a la sección **Scanner** en la barra lateral.
4.  Ingresa la URL de la API que deseas analizar.
5.  Haz clic en escanear y espera los resultados.
6.  Desde el historial, puedes volver a consultar escaneos pasados o exportar tus resultados.
