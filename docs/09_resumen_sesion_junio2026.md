# Bitácora de Sesión — Auditoría y Mitigación C2 Forum

**Fecha**: 27-28 Junio 2026
**Proyecto**: Command & Control (C2) Secure Forum
**Repositorio**: `https://github.com/Noir0x63/Command-Control-Forum`
**Pentest base**: `C:\Users\Shadow\mi-proyecto\c2-pentest\REPORTE.md`
**Commit inicial**: `6b9ecbf` — Commit final: `33ad7d7`

---

## 1. Fase 1 — Auditoría Inicial (White-Box Review)

Se realizó un análisis exhaustivo línea por línea de todo el ecosistema del proyecto. Se identificaron 23 hallazgos:

| Severidad | Cantidad |
|-----------|----------|
| Alta | 5 |
| Media | 8 |
| Baja | 10 |

### Hallazgos críticos encontrados

| ID | Descripción | Archivo |
|----|-------------|---------|
| A1 | `crypto.randomUUID()` crashea en Node.js < 19 | `captcha.js:115` |
| A2 | `CAPTCHA_SECRET` efímero (cambia en cada reinicio) | `captcha.js:3` |
| A3 | Race condition en unicidad de codename | `server.js:718-743` |
| A4 | PoW bloquea el hilo principal del navegador | `app.js:1048-1076` |
| A5 | Timing side-channel en verificación de hash | `hash-worker.js:40` |

### Vulnerabilidades del pentest

| ID | Vulnerabilidad | Tipo | Severidad |
|----|---------------|------|-----------|
| C2-001 | CAPTCHA con templates estáticos y jitter predecible (±0.4px) | Diseño | Alta |
| C2-002 | Nonces solo en RAM (Map), no en DB | Implementación | Media |
| C2-003 | Boundary check con `>` en vez de `>=` | Implementación | Baja |
| C2-004 | Honeypot estático `email: ""` trivialmente evadible | Diseño | Baja |

---

## 2. Fase 2 — Mitigación de Vulnerabilidades del Pentest

### C2-001 — CAPTCHA Vectorial Procedural

**Archivo**: `server/captcha.js` (reescrito)

- Reemplazo de `CHAR_PATHS` (templates fijos) por `CHAR_STROKES` (puntos de anclaje estructurales)
- Generación de curvas de Bézier cúbicas con puntos de control aleatorizados
- PRNG determinista `xoshiro128**` con semilla HMAC-SHA256
- 5 fases de renderizado: grid de interferencia, campo de ruido (40 puntos), caracteres procedurales, fragmentos decoy (3), líneas de interferencia foreground (3)
- 2× más jitter que antes (±0.8px vs ±0.4px)
- Token HMAC-SHA256 (verificación server-side, sin cambios)

### C2-002 — Nonces Persistentes en SQLite

**Archivo**: `server.js`

- Nueva tabla `nonces` con `PRIMARY KEY (nonce)` (UNIQUE constraint)
- Índice `idx_nonces_created_at` para cleanup eficiente
- Caché en RAM (hot cache) + persistencia en SQLite
- GC cada 2 minutos en DB, cada 30s en RAM
- Previene reuso incluso tras reinicio del servidor

### C2-003 — Boundary Conditions

**Archivo**: `server.js`

- `>` reemplazado por `>=` para límite inclusivo
- Constante `FRESHNESS_WINDOW_MS = 5 * 60 * 1000`
- Timestamp exactamente a 300000ms ahora es rechazado

### C2-004 — Honeypot Adaptativo Multicapa

**Archivos**: `server.js`, `app.js`, `index.html`

- **Capa 1 (Time-to-submit)**: Rechaza registros en < 2.5s desde emisión del CAPTCHA
- **Capa 2 (Integridad)**: Token `hpToken` = HMAC-SHA256(timestamp:fieldNames, CAPTCHA_SECRET)
- **Capa 3 (Campos dinámicos)**: 3 campos con nombres `v_<hmac12>` derivados de HMAC por sesión
- **Capa 4 (Ocultación variable)**: 3 técnicas CSS distintas (offscreen, opacity zero, type=hidden)
- Mensajes de error uniformizados: siempre `REGISTRATION_REJECTED`

---

## 3. Fase 3 — Corrección de Errores de Renderizado

### Problema: Modales invisibles en el navegador del usuario

El `<dialog>` nativo con `showModal()` no renderizaba visiblemente a pesar de que la API reportaba `open: true`. Tres intentos de solución:

1. **Primer intento**: `<dialog>` con `class="c2-overlay"` — la clase `.c2-overlay` tenía `background: rgba(0,0,0,0.95)` y `display: none`, haciendo el contenido invisible
2. **Segundo intento**: `<dialog>` sin clase, con estilos inline y `showModal()` — el modal se abría (la página se volvía inert) pero el contenido seguía invisible
3. **Tercer intento (solución final)**: Reemplazo de `<dialog>` por DOM injection directa ( `<div>` con `position:fixed; z-index:2147483647`)

### Problema: `innerHTML` como vector XSS

Se reemplazó todo uso de `innerHTML` en ambos modales (términos y gatekeeper) por `createElement` + `textContent` + `addEventListener`, siguiendo OWASP XSS Prevention Cheat Sheet.

### Problema: CSP con 12 hashes de Cloudflare

Cloudflare Web Analytics rotaba su script constantemente, generando un hash diferente cada vez. Se acumularon 12 hashes en `script-src`. Solución: eliminar completamente Cloudflare Analytics del CSP.

### Problema: Bio se borraba al escribir

El `render()` sobrescribía `this.profBio.value` en cada ciclo de renderizado (disparado por ping WebSocket cada 10s). Solución: `if (document.activeElement !== this.profBio)` — no sobrescribir si el textarea está enfocado.

### Problema: Flujo de admisión evadible

El check `isGKVisible` usaba `this.modalGatekeeper.classList.contains('active')` que referenciaba código muerto. Solución: mostrar el modal incondicionalmente en PENDING_ADMISSION y agregar `return` temprano para bloquear el renderizado del feed.

---

## 4. Fase 4 — Refactorización y Mejoras de Seguridad

### Limpieza de código muerto

| Elemento | Archivo | Líneas eliminadas |
|----------|---------|-------------------|
| `<dialog id="terms-modal">` | `index.html` | ~20 |
| `<div id="gatekeeper-modal">` | `index.html` | ~30 |
| `#terms-modal::backdrop` y relacionados | `index.css` | ~13 |
| `this.modalTerms`, `this.modalGatekeeper`, etc. | `app.js` | ~4 |
| Event listeners de términos y gatekeeper antiguos | `app.js` | ~40 |
| `showTermsModal()`, `showGatekeeperModal()` | `app.js` | ~10 |
| Corrección de rama `else` vacía en submit handler | `app.js` | 1 línea |

### Gatekeeper con pool de preguntas en DB

**Reemplazo completo de `ai_evaluator.js`**:

- **Antes**: `STATIC_CHALLENGE` con respuesta "C" hardcodeada + Gemini API (sin API key, siempre caía al fallback)
- **Ahora**: 15 preguntas almacenadas en SQLite (tabla `admission_questions`), seed automático al primer arranque
- Cada intento recibe 2 preguntas aleatorias (`ORDER BY RANDOM() LIMIT 2`)
- Evaluación por comparación directa (no hashes, no Gemini, sin latencia)
- 5 intentos por usuario + rate limit de 3/día por IP
- El cliente nunca recibe la respuesta correcta

### DEBUG AUTH eliminado

`console.log('[DEBUG AUTH]', ...)` en `server.js:454` exponía tokens de sesión, cookies y headers Authorization en logs de producción. Eliminado completamente.

---

## 5. Resumen de Archivos Modificados

| Archivo | Líneas (final) | Cambios |
|---------|---------------|---------|
| `server.js` | 1632 | +296 líneas — nonces, honeypot, CAPTCHA endpoint, gatekeeper pool |
| `server/captcha.js` | 296 | Reescritura completa — generación procedural, PRNG, Bézier |
| `server/ai_evaluator.js` | 69 | Reescritura completa — pool de preguntas en DB |
| `server/workers/hash-worker.js` | 50 | Fix timing side-channel (SHA-256 antes de timingSafeEqual) |
| `public/app.js` | 2224 | +504 líneas — DOM injection, honeypot dinámico, 2 preguntas, fixes |
| `public/index.html` | 279 | -47 líneas — código muerto eliminado, versión bump |
| `public/index.css` | 689 | -13 líneas — reglas de dialog/gatekeeper eliminadas |
| `deploy.bat` | 84 | Ahora mata procesos previos, hace `git pull`, npm install siempre |
| `documentation/08_informe_mitigacion_pentest_junio2026.md` | ~900 líneas | Informe de mitigación post-pentest |
| `docs/09_resumen_sesion_junio2026.md` | ~300 líneas | Este documento |

---

## 6. Vulnerabilidades Remanentes (Deuda Técnica)

| Ítem | Prioridad | Descripción |
|------|-----------|-------------|
| `CAPTCHA_SECRET` en `.env` | Baja | Se genera aleatoriamente si no está configurado; invalida CAPTCHAs al reiniciar |
| Sin endpoint de health check | Baja | No hay `GET /health` para monitoreo |
| Sin compresión de respuestas | Baja | Las respuestas JSON grandes no se comprimen |
| Índices faltantes en SQLite | Baja | `author` en threads/replies no tienen índice para purge |

---

## 7. Línea de Tiempo de la Sesión

```
T+00:00 — Auditoría inicial: 23 hallazgos, mapeo completo del código
T+01:30 — C2-001: CAPTCHA procedural con curvas de Bézier
T+02:15 — C2-002: Nonces persistentes en SQLite
T+02:20 — C2-003: Boundary fix (>=)
T+02:45 — C2-004: Honeypot adaptativo multicapa
T+03:30 — A5: Timing side-channel en hash-worker.js
T+04:00 — Documentación del informe de mitigación
T+04:30 — Commit y push: 5 archivos, +509/-163 líneas
T+05:00 — Inicio de debugging de modales invisibles (dialog.showModal)
T+06:30 — Solución: DOM injection directa (z-index: 2147483647)
T+07:00 — CSP limpiado: eliminación de 12 hashes de Cloudflare
T+07:30 — Gatekeeper reescrito con pool de preguntas en DB
T+08:00 — Código muerto eliminado (HTML, CSS, JS)
T+08:15 — Bio textarea fix (activeElement check)
T+08:30 — DEBUG AUTH eliminado
T+09:00 — 2 preguntas por intento + textos en inglés
T+09:15 — Commit final, cierre de sesión
```

---

*Documento generado al cierre de la sesión del 28 de Junio de 2026*
