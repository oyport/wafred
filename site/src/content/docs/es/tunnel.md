---
title: Túneles
description: Publica un servicio de una red privada a través del plano de datos del WAF, sin puerto entrante ni IP pública en ese host. Emparejamiento, listener del edge, vinculación del pool de orígenes, salida SOCKS5, operación y diagnóstico.
minutes: 12
---

Un túnel publica un servicio que vive en una red privada (un NAS, una aplicación interna, la página de administración de una base de datos) **sin abrir ningún puerto entrante y sin una IP pública en ese host**. El conector se conecta hacia fuera al edge; el edge termina el lado público. Todas las protecciones del WAF (reglas, limitación de tasa, retos, caché, control de acceso, registros, certificados, TLS al origen) se aplican igual, porque para el edge el túnel es un origen normal.

## Las piezas

| Pieza | Dónde se ejecuta | Función |
| --- | --- | --- |
| **Conector** (`wafred-tunnel`) | dentro de la red privada | se conecta **solo hacia fuera** al plano de control y a los edges; reenvía cada conexión al destino interno |
| **Listener del edge** | en el edge (`tunnel_addr`, puerto `9443`) | acepta la sesión TLS del conector y abre un puente loopback por destino |
| **Puente** | en el edge, `127.0.0.1:<puerto efímero>` | hace que el túnel parezca un origen corriente |
| **Vinculación del pool** | plano de control | indica qué `host:port` internos puede alcanzar el tráfico de un sitio por este túnel |

Un túnel **no** es una VPN: solo transporta el tráfico de los pools vinculados. Un túnel es un dominio de confianza.

## Tres estados distintos

| Estado | Significado |
| --- | --- |
| **Emparejado** | existen credenciales; el túnel se puede usar |
| **Habilitado** | el interruptor por túnel del operador |
| **Conector en línea** | un conector mantiene ahora un flujo de control |

Un túnel puede estar emparejado y habilitado con el conector desconectado: es una configuración válida, no una avería.

## Puesta en marcha en cinco pasos

### 1. Crear el túnel

**Agentes → Túneles → Create tunnel.** La consola muestra un comando de emparejamiento de un solo uso. El token se muestra **una vez** y caduca a los 30 minutos por defecto; generar otro rota las credenciales y desconecta el conector en marcha.

### 2. Ejecutar el conector dentro de la red privada

```bash
sudo wafred-tunnel pair \
  --config /etc/wafred/tunnel.toml \
  --server-url https://control-plane:9090 \
  --server-ca-cert /etc/wafred/tunnel-ca.pem \
  --token <pairing-token>
sudo wafred-tunnel run --config /etc/wafred/tunnel.toml
```

`pair` canjea el token por credenciales duraderas y escribe `/etc/wafred/tunnel.toml` (`0600`). `run` mantiene un flujo de control hacia el plano de control y una sesión por ingress de edge. Los fallos de conexión se registran en `warn`.

### 3. Habilitar el listener de un edge y darle una dirección pública

```toml
[agent]
tunnel_addr = "0.0.0.0:9443"
```

Abre `9443` en el cortafuegos y rellena la dirección **Tunnel ingress** en **Agentes → [nodo]**. El edge genera su certificado autofirmado en el primer arranque (persistido), publica su SHA-256 y el conector lo fija. El listener se enlaza al arrancar: cambiar `tunnel_addr` requiere reiniciar el edge. La dirección de ingress y la política se aplican en caliente (≤5 s con el edge conectado).

### 4. Vincular un pool de orígenes

**Sitios → [sitio] → Origin pools → [pool] → Tunnel.** Las direcciones de los nodos del pool son los destinos internos que el conector contacta. Sin sesión, el pool no tiene upstream y las rutas responden `503` en lugar de caer al origen por defecto.

### 5. Verificar

1. **Conector en línea**: la insignia de la lista y el panel de detalle; `wafred-tunnel status` muestra lo mismo en local.
2. **Un edge ofrece ingress**: el panel muestra el edge y los destinos.
3. **El sitio responde**: `curl -H 'Host: app.example.com' --resolve …` debe devolver `200`.

## Recorrido de una petición

Cliente → edge `:443` → pipeline del WAF → pool vinculado al túnel → puente loopback → sesión TLS multiplexada → conector → destino interno. El registro de acceso muestra el origen como `tunnel://<nombre>/<destino>`.

## Sin salida directa: SOCKS5

```toml
socks5_proxy    = "10.0.0.1:1080"
socks5_username = "connector"
socks5_password = "…"
```

Ambos canales —el flujo de control y todas las sesiones de edge— pasan por el proxy. Los nombres de destino los resuelve el proxy (ATYP 3) y no hay repliegue silencioso a una conexión directa.

## Operación

| Acción | Efecto |
| --- | --- |
| **Re-emparejar** | rota las credenciales y desconecta el conector |
| **Revocar** | elimina las credenciales; los edges rechazan el túnel en el siguiente bundle (≤5 s) |
| **Deshabilitar** | interruptor por túnel; las sesiones se cierran en la siguiente recarga |
| **Eliminar** | se rechaza (`409`) mientras haya pools vinculados; `?force=true` los desvincula y pasan a orígenes **directos** |
| **Ajustes** | interruptor global, vida del token, flujos por sesión, destinos por túnel |

## Modelo de seguridad

El edge nunca ve las credenciales del conector: verifica un **token de sesión Ed25519 de corta vida** emitido por el plano de control (clave derivada de `jwt_secret`). Un token capturado caduca (una hora por defecto) y no sirve para otro túnel. El conector fija el certificado del edge. La revocación converge mientras el edge pueda alcanzar el plano de control.

## Diagnóstico

| Síntoma | Qué revisar |
| --- | --- |
| `cannot reach the control plane` | `server_url`, acceso al `9090`, CA, proxy SOCKS5 |
| En línea pero «0 edges» | `tunnel_addr` o dirección de ingress sin configurar |
| Credenciales rechazadas | token caducado o revocado, o el edge aún no tiene la nueva clave pública |
| `502/503` | sin sesión, o el conector no alcanza el destino |
| Eliminación `409` | todavía hay pools que lo referencian |

## Límites de esta versión

HTTP, HTTPS y WebSocket a través de un sitio; TCP crudo no expuesto. Un túnel es un dominio de confianza. Los destinos y los flujos por sesión están limitados por los ajustes.