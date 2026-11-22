---
title: Informe de pruebas de WAFred 1.0.4
description: Resultados corregidos del corpus completo, correcciones de falsos negativos, pruebas HTTPS autofirmadas y referencias históricas de otros WAF.
minutes: 5
---

## Resultados principales

Prueba del 2026-11-22 con una versión candidata de WAFred 1.0.4 compilada localmente y el corpus público chaitin/blazehttp: 33.877 solicitudes HTTP (658 maliciosas y 33.219 benignas). Los bloqueos y desafíos cuentan como detecciones y como tráfico benigno afectado.

| Nivel | Ataques interceptados | Tráfico benigno afectado | Replay p50 / p95 | HTTP 500 |
|---|---:|---:|---:|---:|
| Normal | 397/658 (60,33%) | 4/33.219 (0,012%) | 43 / 48 ms | 0 |
| Normal + inspección del cuerpo | 494/658 (75,08%) | 12/33.219 (0,036%) | 43 / 48 ms | 0 |
| Strict | 501/658 (76,14%; 491 bloqueos, 10 desafíos) | 4/33.219 (0,012%) | 43 / 48 ms | 0 |
| Strict + inspección del cuerpo | **632/658 (96,05%; 622 bloqueos, 10 desafíos)** | **19/33.219 (0,057%)** | 43 / 48 ms | 0 |

## Correcciones de falsos negativos

El replayer original enviaba las muestras sin ajustar. Las solicitudes con cuerpo pero sin `Content-Length` ni `Transfer-Encoding` llegaban al servidor sin cuerpo, lo que infravaloraba la inspección del cuerpo. Ahora se añade una longitud exacta y se recortan los bytes posteriores a un único `Content-Length` válido. Esto también corrigió 15 muestras benignas mal formadas que devolvían HTTP 500 al reenviarse; los cuatro perfiles finales registraron cero HTTP 500.

WAFred incorpora análisis acotado de formularios URL-encoded y multipart sin `Content-Type`, inspección de segmentos de ruta Base64 y dos firmas exclusivas de Strict para `alert.call` / `prompt.call`. Strict + body interceptó 632/658 ataques; 19 solicitudes benignas fueron bloqueadas o desafiadas (17 bloqueos, 2 desafíos), por lo que deben revisarse antes de habilitarlo.

## Referencia histórica entre productos

El gráfico compara la medición actual de WAFred 1.0.4 con la última ejecución de la etapa PingWAF (P13) y conserva las referencias históricas de SafeLine, ModSecurity y Cloudflare. La ejecución anterior usó el mismo corpus nominal, pero una ruta de framing anterior; el arnés actual corrigió 15 respuestas HTTP 500 asociadas al framing. Por eso, se muestran resultados registrados por versión, no un experimento controlado antes/después. Los otros productos no se probaron de nuevo y sus denominadores y rutas de red son distintos. El p95 de WAFred incluye la VM, el proxy y el origen simulado y no se compara directamente con otros valores.

## Cuerpos comprimidos y HTTPS

La suite gzip interceptó 0/8 ataques sin inspección del cuerpo, 7/8 con Normal + inspección y 8/8 con Strict + inspección. Las dos solicitudes benignas pasaron en todos los niveles.

El listener HTTPS aislado usó un certificado autofirmado para `wafred-test.local` y `127.0.0.1`. La validación explícita con `curl --cacert` pasó; el almacén de confianza predeterminado rechazó el certificado como se esperaba. Los handshakes SNI de OpenSSL funcionaron con TLS 1.2 y 1.3. Las solicitudes benignas por HTTP/HTTPS devolvieron 200; los ataques de formulario y ruta Base64 por HTTPS devolvieron 403. TLS terminó en WAFred y el origen simulado usó HTTP.

## Capacidad y alcance

La prueba de tres minutos a 256 conexiones y los resultados del límite de descriptores a 512 se midieron con el binario desplegado original, no con la versión candidata parcheada. El proceso original tenía `nofile=1.024` y generó algunos 502 a 512 conexiones; una copia aislada con 65.536 no generó 502. El proceso all-in-one activo no se modificó.

La matriz de seguridad usa un proxy HTTP/1.1 aislado y un origen simulado. Siguen pendientes un origen real, HTTP/2/HTTP/3, rutas de producción, rate limiting/CC y una prueba de alta concurrencia con el candidato. Informe completo: [WAFred 1.0.4](https://github.com/oyport/wafred/blob/main/docs/wafred-baseline-test-report-2026-11-22.md).
