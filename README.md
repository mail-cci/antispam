# antispam

Estructura inicial para una aplicación antispam en Go que interactúa con Postfix a través del protocolo Milter. El proyecto se divide en varios paquetes:

- **`internal/milter`**: servidor que implementa Milter usando `go-milter` y delega en el módulo antispam.
- **`internal/antispam`**: lógica básica de detección por heurísticas y listas blancas/negras en memoria.
- **`internal/api`**: API REST basada en Gin para gestionar las listas.
- **`config`**: estructuras y ejemplo de configuración YAML.
- **`cmd/antispam`**: punto de entrada de la aplicación.

Se incluye además un `Dockerfile` para compilar y ejecutar la aplicación fácilmente.
