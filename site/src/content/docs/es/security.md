---
title: Seguridad
description: Cómo reportar una vulnerabilidad en privado, qué versiones reciben correcciones y qué pasos de endurecimiento aplicar antes de exponer PingWAF a Internet.
minutes: 8
---

## Reportar una vulnerabilidad

PingWAF está en la ruta de petición de las aplicaciones que protege, así que una
vulnerabilidad en él importa tanto como una en los sitios que quedan detrás.
Repórtala siempre en privado: nunca en un issue, discusión o pull request
público.

- **GitHub private vulnerability reporting (preferido):**
  [Reportar una vulnerabilidad](https://github.com/shuaiZend/PingWAF/security/advisories/new)
  — privado, con seguimiento y la vía más rápida a una corrección.
- **Correo:** `security@pingwaf.com`, vigilado por al menos dos mantenedores.
  Se está publicando una clave PGP; hasta que su huella aparezca aquí, envía
  primero un resumen en texto plano y responderemos con la clave.

Incluye la versión afectada, el modo de ejecución (`all-in-one`, `server`,
`agent`), el backend TLS, los pasos de reproducción y los requisitos de ataque;
redacta tokens y contraseñas. Confirmamos en tres días laborables, mantenemos
información semanal mientras se prepara la corrección y coordinamos la
divulgación después de publicarla (o a los 90 días, lo que ocurra antes). La
política completa está en
[SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md).

## Versiones soportadas

| Versión | Estado | Correcciones de seguridad |
| --- | --- | --- |
| `0.32.x` (línea actual) | Soportada | Sí |
| `0.31.x` | Solo correcciones críticas | Bajo petición, best effort |
| `0.30.x` y anteriores | Fin de vida | No |

Solo la línea actual recibe parches garantizados; las correcciones de seguridad
salen en versiones de parche y se listan bajo `### Security` en el
[changelog](https://github.com/shuaiZend/PingWAF/blob/main/CHANGELOG.md).

## Endurecimiento antes de exponer

La consola incluye valores por defecto pensados para desarrollo. Antes de
exponer una instancia a una red que no controlas:

1. **Credenciales** — cambia la contraseña sembrada del administrador, define
   `PINGWAF_JWT_SECRET` y `PINGWAF_SECRET_KEY` con 32 bytes aleatorios cada uno,
   cierra el registro (`PINGWAF_ALLOW_REGISTRATION=false`) y cambia la
   contraseña de PostgreSQL.
2. **Red** — enlaza la consola (`9080`) a loopback o a una interfaz privada y
   accede por VPN o proxy inverso; expón el puerto gRPC (`9090`) solo a los
   hosts de agentes; nunca expongas PostgreSQL (`5432`).
3. **TLS** — sube un certificado real para la consola o termina TLS delante de
   ella; activa HTTPS y HSTS en todos los sitios; mantén TLS en gRPC.
4. **Secretos en reposo** — `PINGWAF_SECRET_KEY` cifra los secretos de los
   canales de notificación, la clave del proveedor de IA y las credenciales de
   los destinos de copia. Sin ella se guardan en texto plano. Haz una copia de
   la clave por separado; todavía no hay rotación en línea.
5. **Registros** — los logs de acceso guardan cabeceras completas (incluidas
   `Authorization`, `Cookie` y `Set-Cookie`) y hasta 8 KiB de cada cuerpo,
   durante 180 días por defecto. Trata PostgreSQL y Elasticsearch como
   almacenes de credenciales y reduce la retención cuando sea posible.
6. **MCP e IA** — una clave MCP `write` es una credencial de administrador
   global; una clave `read` solo ve los sitios de su propietario. El asistente
   de IA envía resultados de herramientas (sitios, logs, eventos WAF, auditoría)
   al proveedor configurado, así que actívalo solo donde esos datos puedan salir
   del despliegue.

La lista completa, con variables exactas, pasos de copia y advertencias de
rotación, está en
[SECURITY.md](https://github.com/shuaiZend/PingWAF/blob/main/SECURITY.md#hardening-checklist)
y [docs/deployment.md](https://github.com/shuaiZend/PingWAF/blob/main/docs/deployment.md).
