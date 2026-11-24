# Análisis rápido — phishing-psychology-analyzer (24-nov-2026)

Diagnóstico, sin cambios de código. Pedido de Giovanni. Repo público del portafolio Hybrid Intelligence.

## 1. Estado
- `pip install -r requirements.txt` OK. `pytest -q`: **24 passed** (~5 s, offline). CLI y `--json` funcionan; `--file` inexistente da error limpio.
- CLAUDE.md, README y código coinciden (fórmulas, bandas, 24 tests). La sección "Limitations" es honesta.
- Memoria previa (Graphiti/Qdrant): solo la ficha del 3-nov (estructura y stack). Sin decisiones ni bugs pendientes registrados.

## 2. Revisión externa con Nemotron: no se pudo
`opencode_status` responde "online", pero `opencode_run` falla siempre con `Unrecognized flag: --dir in command opencode run` (2 intentos, con y sin `model`). El wrapper del MCP pasa un flag que el CLI instalado no acepta. No es del repo. **Nemotron no devolvió nada, así que no hay aciertos que anotar.** La revisión de abajo es mía. Para reintentar hay que arreglar el wrapper o actualizar `opencode`.

## 3. Verificación propia

### Hallazgos de comportamiento (probados)
| # | Hallazgo | Prueba | Gravedad |
|---|---|---|---|
| 1 | **Falso positivo fuerte con palabras sueltas**: "credit", "critical", "bank", "join", "free", "fine", "unique" disparan vectores en texto de oficina. | "quarterly credit review is critical for our bank partners. Join us, it is free…" → **77 CRITICAL** | Media (README ya avisa de marketing, no de correo neutro) |
| 2 | **Frases solapadas cuentan doble**: "unauthorized" + "unauthorized access", "breach" + "breach detected", "immediately" + "respond immediately". | "Breach detected." → fear 75 con 1 sola idea | Media (infla el score) |
| 3 | **Evasión trivial**: leetspeak ("urg3nt", "acc0unt") y homoglifos (Е cirílica) no matchean; NFKC no pliega confusables. El análisis de caracteres invisibles sí funciona. | "Urg3nt… susp3nded, act n0w" → **0.0 LOW** | Media (limitación ya parcial en README: no menciona homoglifos) |
| 4 | **Solo inglés**: phishing en español → 0.0. | "URGENTE: su cuenta ha sido suspendida…" → 0.0 LOW | Ya documentado; pesa por el público LATAM del portafolio |
| 5 | **Saturación**: con tope 90 y pesos ≥1.0, 3–5 pistas distintas ya dan 90–100 en cualquier vector; el cap 90 casi no frena. Bandas poco discriminantes arriba. | cálculo: fear/urgency/authority/reciprocity llegan a 100 | Baja (diseño, no bug) |
| 6 | Phish bien redactado y cortés → **23.4 LOW**. | "our records show a payment issue on your account…" | Documentado |
| 7 | `risk_boost` en `taxonomy.py` (8 vectores) **no se usa en ningún sitio** (grep). Código muerto que sugiere un efecto que no existe. | grep | Baja |
| 8 | Sin tope de tamaño de `--file`: 1,4 MB de texto tardó ~5,7 s (lineal, sin ReDoS). `errors="replace"` evita crashes. | prueba | Baja |

### ATT&CK: **un ID del README está obsoleto**
Verificado en attack.mitre.org (versión viva **v20**):
- **T1566 Phishing**: vigente (v2.8, modificada 18-sep-2026; 4 subtécnicas .001–.004; táctica Initial Access).
- **T1656 Impersonation: revocada en ATT&CK v19**; reemplazo **T1684.001 Social Engineering: Impersonation** (nueva técnica **T1684 "Social Engineering"**, creada abr-2026, táctica Stealth; incluye T1684.002 Email Spoofing). Confirmado por la página de T1684 y por fuentes secundarias (detections.org, issue de MITRE ATLAS que señala el mismo problema). No pude abrir la página de T1656 (el scraper falló; la revocación sale de esas fuentes).
- **No re-verificados hoy**: T1598, T1585, T1585.001, T1204 (existían en versiones previas; falta confirmar contra v20).
- Usos afectados: `authority` ("T1656 Impersonation; T1585…") y `familiarity` ("…T1656 Impersonation") en `src/taxonomy.py`, tabla del README y JSON de salida (`mitre_ref`).
- Oportunidad: la descripción de T1684 cita explícitamente "scare tactics… sentido de urgencia", justo lo que mide la herramienta. Es mejor ancla que T1566 para urgency/fear/authority/familiarity. Siguen siendo "contexto", no mapeo oficial.

## 4. Valor como pieza de ciberseguridad (opinión breve)
Buena como **pieza de concienciación y de rigor**: el README admite que no es un clasificador, no inventa métricas, tiene tests que fijan las fórmulas y CI en 3.11/3.12. En un portafolio de seguridad eso pesa más que una precisión inventada. Dentro de `1-Cybersecurity` (Network Defense, Hardening, IR, y en `4-Psychology` el análisis de ingeniería social) es el eslabón "factor humano" que conecta con los playbooks de phishing. El perfil de Neckr0ik ya está reposicionado a IA/Impulse Labs, con seguridad en "Foundations": este repo es el puente natural entre ambos mundos (psicología + seguridad + NLP).
Lo que le resta: no tiene **ninguna evaluación** contra datos reales, y el público del perfil es LATAM pero la herramienta es solo inglés. Un lector técnico lo notará en 2 minutos.

## 5. Mejoras priorizadas (para decidir; nada aplicado)
1. **Corregir ATT&CK** (S): sustituir T1656 por T1684.001 (y valorar T1684 para urgency/fear); verificar T1598/T1585/T1204 en v20; fechar la versión ("ATT&CK v20, nov-2026") en README y docstring. Cambiar código, tests (si pinean el texto) y README juntos.
2. **Deduplicar frases solapadas** (S): contar una sola pista cuando una frase contiene a otra; añadir test.
3. **Quitar o usar `risk_boost`** (S).
4. **Evaluación mínima honesta** (M): correr sobre un corpus público de phishing y otro de correo legítimo (p. ej. Nazario/SpamAssassin/Enron; revisar licencias) y publicar distribución de scores, no "accuracy". Es lo que la volvería creíble sin prometer de más.
5. **Normalizar confusables/leet básico** (M) y documentar lo que no cubre.
6. **Español/portugués** (M–L): listas de palabras es/pt + VADER alternativo. Alinea con el público LATAM y con `news-sentiment-analyzer` del mismo portafolio.
7. Palabras ambiguas ("fine", "credit", "bank", "join", "critical") → frases o contexto (S).

## 6. Conectores (1–2 usos, sin activar)
- **Vercel o Replit (demo)**: una demo web mínima (caja de texto → barras por vector + banda + aviso "mide presión persuasiva, no malicia"). Replit es más rápido para prototipo; Vercel si se quiere colgar de un dominio del portafolio. Todo en cliente o servidor propio: nada de enviar texto de usuarios a terceros sin aviso.
- **Gmail (pruebas con correos reales)**: solo con permiso expreso de Giovanni y solo lectura: buscar unos cuantos correos de spam/phishing que ya haya marcado y compararlos con su score, sin guardar contenido ni pegarlo en memoria ni en el repo. Sirve como *smoke test* cualitativo, no como evaluación.

## 7. Límites de este análisis
- Sin revisión de Nemotron (fallo del wrapper). Pruebas de comportamiento hechas con ~8 textos propios: son ejemplos, no medición.
- ATT&CK: T1566, T1684 y la revocación de T1656 verificados hoy; el resto, no.
