// andreznSS iOS v1.1.0
// Analizador local de evidencias iOS para triage de red relacionado con Free Fire.
// Plataforma: Scriptable (iOS/iPadOS). No sube archivos ni credenciales.
// Uso autorizado únicamente. Los hallazgos son indicadores, no una prueba automática de cheats.

const APP = Object.freeze({
  name: "andreznSS iOS",
  version: "1.1.0",
  author: "andrezn",
  maxFiles: 12,
  maxFileBytes: 20 * 1024 * 1024,
  maxRecords: 30000,
  maxFindings: 500,
  reportFolder: "andreznSS/reports",
  customRulesPath: "andreznSS/rules_custom.json",
});

const COLORS = Object.freeze({
  bg: "#050505",
  panel: "#0d0d0f",
  panel2: "#141416",
  red: "#ff2345",
  redDark: "#7d091d",
  white: "#f5f5f7",
  muted: "#9a9aa3",
  green: "#35d07f",
  amber: "#ffb020",
});

const BASE_RULES = {
  freefire: [
    "com.dts.freefireth", "com.dts.freefiremax", "free fire", "freefire",
    "garena free fire", "garena"
  ],
  proxyTools: [
    "shadowrocket", "quantumult", "quantumult x", "surge", "loon", "stash",
    "potatso", "clash", "clashx", "v2ray", "xray-core", "sing-box",
    "wireguard", "openvpn", "outline", "tailscale", "zerotier", "ss-local",
    "shadowsocks", "trojan-go", "packet tunnel", "packet-tunnel", "nepackettunnelprovider"
  ],
  mitmTools: [
    "mitmproxy", "charles proxy", "charlesproxy", "proxyman", "fiddler",
    "burp suite", "burpsuite", "ssl-kill-switch", "sslkillswitch",
    "trustmealready", "justtrustme", "certificate pinning bypass"
  ],
  dynamicInstrumentation: [
    "frida", "frida-server", "frida-gadget", "objection", "cycript",
    "substrate inserter", "ellekit loader", "fishhook", "mshookfunction"
  ],
  jailbreak: [
    "dopamine", "palera1n", "checkra1n", "unc0ver", "taurine", "odyssey",
    "sileo", "zebra", "cydia", "filza", "ellekit", "libhooker",
    "substitute", "mobilesubstrate", "/var/jb", "/bootstrap", "apt/dpkg",
    "com.saurik.cydia", "org.coolstar.sileo", "xyz.willy.zebra"
  ],
  sideload: [
    "trollstore", "altstore", "sidestore", "scarlet", "esign", "feather",
    "gbox", "sideloadly", "appdb", "maplesign", "signulous", "enterprise certificate"
  ],
  vpnDns: [
    "nevpn", "utun0", "utun1", "utun2", "utun3", "utun4", "utun5",
    "dnssettings", "dns settings", "proxysettings", "proxy settings",
    "nextdns", "adguard dns", "cloudflare warp", "1.1.1.1", "quad9",
    "doh", "dot", "dns over https", "dns over tls"
  ],
  suspiciousKeywords: [
    "aimbot", "wallhack", "bypass", "modmenu", "mod menu", "injector",
    "antiban", "anti-ban", "magic bullet", "headshot config", "cheat panel",
    "freefire hack", "free fire hack", "proxy cheat", "ff cheat"
  ],
  suspiciousPaths: [
    "/library/mobilesubstrate/dynamiclibraries", "/usr/lib/tweakinject",
    "/var/lib/dpkg", "/var/cache/apt", "/private/preboot", "/var/jb",
    "/applications/cydia.app", "/applications/sileo.app", "/applications/filza.app"
  ],
  allowDomains: [
    "garena.com", "garenanow.com", "freefiremobile.com", "apple.com",
    "icloud.com", "mzstatic.com", "akamaized.net", "akamai.net",
    "cloudfront.net", "googleapis.com", "googleusercontent.com"
  ],
  suspiciousDomainTokens: [
    "freefirehack", "ffhack", "cheatpanel", "modmenu", "aimbot", "wallhack",
    "antiban", "bypassff", "injectorff", "proxycheat"
  ]
};

let RULES = JSON.parse(JSON.stringify(BASE_RULES));

await main();

async function main() {
  try {
    await loadCustomRules();
    const inputs = collectAutomaticInputs();
    await runUnifiedInterface(inputs);
  } catch (error) {
    // Solo se usa como contingencia cuando la WebView no puede abrirse.
    await simpleAlert("Error crítico", String(error && error.stack ? error.stack : error));
  } finally {
    finish();
  }
}

function collectAutomaticInputs() {
  const inputs = [];

  if (Array.isArray(args.fileURLs)) {
    for (const url of args.fileURLs.slice(0, APP.maxFiles)) {
      inputs.push({ kind: "file", path: normalizeFilePath(String(url)), origin: "share_sheet" });
    }
  }

  if (args.shortcutParameter !== null && args.shortcutParameter !== undefined) {
    let text;
    try {
      text = typeof args.shortcutParameter === "string"
        ? args.shortcutParameter
        : JSON.stringify(args.shortcutParameter);
    } catch (_) {
      text = String(args.shortcutParameter);
    }
    if (text.trim()) inputs.push({ kind: "virtual", name: "entrada_atajos.txt", text, origin: "shortcuts" });
  }

  if (Array.isArray(args.plainTexts)) {
    for (let i = 0; i < args.plainTexts.length && inputs.length < APP.maxFiles; i++) {
      const text = String(args.plainTexts[i] || "");
      if (text.trim()) {
        inputs.push({
          kind: "virtual",
          name: `texto_compartido_${i + 1}.txt`,
          text,
          origin: "share_sheet"
        });
      }
    }
  }

  return dedupeInputs(inputs).slice(0, APP.maxFiles);
}

async function runUnifiedInterface(initialInputs) {
  const state = {
    inputs: dedupeInputs(initialInputs).slice(0, APP.maxFiles),
    result: null,
    paths: null,
    running: false
  };

  const web = new WebView();
  await web.loadHTML(buildUnifiedInterfaceHtml());

  // Presentamos la WebView y mantenemos un puente de eventos con el HTML.
  const presented = web.present(true);
  await uiCall(web, "setEvidence", evidencePreview(state.inputs));

  let open = true;
  while (open) {
    let rawEvent;
    try {
      rawEvent = await Promise.race([
        waitForWebEvent(web),
        presented.then(() => "__WEBVIEW_DISMISSED__", () => "__WEBVIEW_DISMISSED__")
      ]);
    } catch (_) {
      break;
    }

    if (rawEvent === "__WEBVIEW_DISMISSED__") break;

    let event;
    try {
      event = typeof rawEvent === "string" ? JSON.parse(rawEvent) : rawEvent;
    } catch (_) {
      await uiCall(web, "showError", "La interfaz envió una solicitud inválida.");
      continue;
    }

    if (!event || !event.action) continue;

    if (event.action === "ready") {
      await uiCall(web, "setEvidence", evidencePreview(state.inputs));
      continue;
    }

    if (event.action === "addFile") {
      if (state.running) continue;
      if (state.inputs.length >= APP.maxFiles) {
        await uiCall(web, "showError", `El límite es de ${APP.maxFiles} evidencias por análisis.`);
        continue;
      }
      try {
        const selected = await DocumentPicker.openFile();
        if (selected) {
          state.inputs.push({
            kind: "file",
            path: normalizeFilePath(String(selected)),
            origin: "document_picker"
          });
          state.inputs = dedupeInputs(state.inputs).slice(0, APP.maxFiles);
          await uiCall(web, "setEvidence", evidencePreview(state.inputs));
          await uiCall(web, "showToast", "Archivo añadido correctamente.");
        }
      } catch (_) {
        await uiCall(web, "showToast", "Selección cancelada.");
      }
      continue;
    }

    if (event.action === "addText") {
      if (state.running) continue;
      const value = String(event.payload && event.payload.text ? event.payload.text : "").trim();
      if (!value) {
        await uiCall(web, "showError", "Pega contenido antes de añadirlo como evidencia.");
        continue;
      }
      if (Data.fromString(value).getBytes().length > 1024 * 1024) {
        await uiCall(web, "showError", "El texto pegado supera 1 MB. Guárdalo como archivo y selecciónalo.");
        continue;
      }
      if (state.inputs.length >= APP.maxFiles) {
        await uiCall(web, "showError", `El límite es de ${APP.maxFiles} evidencias por análisis.`);
        continue;
      }
      state.inputs.push({
        kind: "virtual",
        name: `texto_manual_${state.inputs.length + 1}.txt`,
        text: value,
        origin: "manual_text"
      });
      state.inputs = dedupeInputs(state.inputs).slice(0, APP.maxFiles);
      await uiCall(web, "setEvidence", evidencePreview(state.inputs));
      await uiCall(web, "clearPastedText");
      await uiCall(web, "showToast", "Texto añadido como evidencia.");
      continue;
    }

    if (event.action === "removeEvidence") {
      if (state.running) continue;
      const index = Number(event.payload && event.payload.index);
      if (Number.isInteger(index) && index >= 0 && index < state.inputs.length) {
        state.inputs.splice(index, 1);
        await uiCall(web, "setEvidence", evidencePreview(state.inputs));
      }
      continue;
    }

    if (event.action === "analyze") {
      if (state.running) continue;
      const payload = event.payload || {};

      if (!payload.consent) {
        await uiCall(web, "showError", "Debes confirmar que tienes autorización para analizar las evidencias.");
        continue;
      }
      if (!state.inputs.length) {
        await uiCall(web, "showError", "Añade al menos una evidencia antes de iniciar el análisis.");
        continue;
      }

      const sessionCheck = sessionFromInterface(payload);
      if (!sessionCheck.ok) {
        await uiCall(web, "showError", sessionCheck.error);
        continue;
      }

      const analyst = {
        player: sanitizeLabel(payload.player, "NO_ESPECIFICADO"),
        matchId: sanitizeLabel(payload.matchId, "NO_ESPECIFICADO"),
        analyst: sanitizeLabel(payload.analyst, "andrezn")
      };

      state.running = true;
      await uiCall(web, "showProcessing", "Preparando las evidencias…");

      try {
        const result = await analyzeEvidence(
          state.inputs,
          sessionCheck.session,
          analyst,
          async (progress) => {
            await uiCall(web, "setProgress", progress.percent, progress.message, progress.detail || "");
          }
        );

        await uiCall(web, "setProgress", 94, "Generando informes", "HTML · JSON · TXT");
        const paths = await saveReports(result);
        state.result = result;
        state.paths = paths;
        Script.setShortcutOutput(paths.html);

        await uiCall(web, "showResult", buildResultFragment(result), {
          caseId: result.case.id,
          score: result.result.score,
          coverage: result.completeness.grade
        });
      } catch (error) {
        await uiCall(web, "showSetup");
        await uiCall(web, "showError", String(error && error.message ? error.message : error));
      } finally {
        state.running = false;
      }
      continue;
    }

    if (event.action === "share") {
      if (!state.paths) {
        await uiCall(web, "showError", "Todavía no existe un informe para compartir.");
        continue;
      }
      const format = String(event.payload && event.payload.format || "html").toLowerCase();
      const path = format === "json" ? state.paths.json : format === "txt" ? state.paths.txt : state.paths.html;
      try {
        await ShareSheet.present([path]);
      } catch (_) {
        await uiCall(web, "showToast", "No se pudo abrir el panel Compartir.");
      }
      continue;
    }

    if (event.action === "newAnalysis") {
      state.result = null;
      state.paths = null;
      await uiCall(web, "showSetup");
      await uiCall(web, "setEvidence", evidencePreview(state.inputs));
      continue;
    }
  }
}

function sessionFromInterface(payload) {
  if (!payload.sessionEnabled) {
    return {
      ok: true,
      session: { enabled: false, start: null, end: null, offset: null, valid: true }
    };
  }

  const offset = normalizeOffset(String(payload.offset || ""));
  const startRaw = String(payload.start || "").replace("T", " ").trim();
  const endRaw = String(payload.end || "").replace("T", " ").trim();
  const start = parseManualDate(startRaw, offset);
  const end = parseManualDate(endRaw, offset);

  if (!start || !end || end <= start) {
    return {
      ok: false,
      error: "La ventana horaria es inválida. Revisa inicio, fin y UTC offset."
    };
  }

  return {
    ok: true,
    session: {
      enabled: true,
      start,
      end,
      offset,
      valid: true,
      startRaw,
      endRaw
    }
  };
}

function evidencePreview(inputs) {
  return inputs.map((input, index) => ({
    index,
    name: input.kind === "file" ? fileNameFromPath(input.path) : input.name,
    kind: input.kind === "file" ? "ARCHIVO" : "TEXTO",
    origin: input.origin || "desconocido"
  }));
}

async function waitForWebEvent(web) {
  return await web.evaluateJavaScript(`
    (() => {
      window.__andreznQueue = window.__andreznQueue || [];
      if (window.__andreznQueue.length) {
        completion(JSON.stringify(window.__andreznQueue.shift()));
      } else {
        window.__andreznNativeWaiter = completion;
      }
    })();
  `, true);
}

async function uiCall(web, method, ...args) {
  const encoded = args.map((x) => JSON.stringify(x)).join(",");
  try {
    return await web.evaluateJavaScript(`
      (() => {
        if (window.andreznApp && typeof window.andreznApp[${JSON.stringify(method)}] === "function") {
          return window.andreznApp[${JSON.stringify(method)}](${encoded});
        }
        return null;
      })();
    `, false);
  } catch (_) {
    return null;
  }
}

function buildUnifiedInterfaceHtml() {
  const offsetMinutes = -new Date().getTimezoneOffset();
  const defaultOffset = `${offsetMinutes >= 0 ? "+" : "-"}${String(Math.floor(Math.abs(offsetMinutes) / 60)).padStart(2, "0")}:${String(Math.abs(offsetMinutes) % 60).padStart(2, "0")}`;

  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${APP.name}</title>
<style>
:root{--bg:${COLORS.bg};--panel:${COLORS.panel};--panel2:${COLORS.panel2};--red:${COLORS.red};--red2:${COLORS.redDark};--text:${COLORS.white};--muted:${COLORS.muted};--green:${COLORS.green};--amber:${COLORS.amber};--line:#26262b}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",Inter,Arial,sans-serif}body{background:radial-gradient(circle at 90% -5%,#33030e 0,transparent 31%),radial-gradient(circle at 0 70%,#170207 0,transparent 24%),var(--bg);line-height:1.45}.app{max-width:900px;margin:auto;padding:calc(env(safe-area-inset-top) + 14px) 14px calc(env(safe-area-inset-bottom) + 28px)}
.hero{padding:22px;border:1px solid #3b0b15;border-radius:24px;background:linear-gradient(145deg,rgba(43,2,13,.88),rgba(8,8,9,.96) 62%);box-shadow:0 20px 65px rgba(0,0,0,.58);position:relative;overflow:hidden}.hero:after{content:"";position:absolute;width:170px;height:170px;border-radius:50%;right:-70px;top:-90px;background:rgba(255,35,69,.13);filter:blur(6px)}.eyebrow{color:var(--muted);font-size:10px;letter-spacing:1.8px;text-transform:uppercase;font-weight:800}.brand{font-size:31px;line-height:1.05;font-weight:950;letter-spacing:-1.2px;margin-top:8px}.brand em{font-style:normal;color:var(--red)}.version{margin-top:8px;color:#ff8ca0;font-family:ui-monospace,Menlo,monospace;font-size:11px}.notice{margin-top:14px;color:#d7d7db;font-size:12px;max-width:680px}
.panel{margin-top:13px;background:rgba(13,13,15,.96);border:1px solid var(--line);border-radius:19px;padding:17px;box-shadow:0 14px 45px rgba(0,0,0,.25)}.panel h2{font-size:16px;margin:0 0 13px}.panel h3{font-size:13px;margin:0}.sub{color:var(--muted);font-size:11px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}.full{grid-column:1/-1}label{display:block;font-size:11px;color:#cfcfd4;font-weight:700;margin:0 0 6px}.field{width:100%;border:1px solid #303036;border-radius:13px;background:#111114;color:var(--text);font:inherit;font-size:14px;padding:12px 13px;outline:none}.field:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(255,35,69,.12)}textarea.field{min-height:108px;resize:vertical;font-family:ui-monospace,Menlo,monospace;font-size:11px}.row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.space{justify-content:space-between}.btn{appearance:none;border:0;border-radius:13px;padding:11px 14px;background:#202024;color:var(--text);font:inherit;font-size:13px;font-weight:800;cursor:pointer}.btn.primary{background:linear-gradient(135deg,var(--red),#bd0d2b);box-shadow:0 9px 28px rgba(255,35,69,.2)}.btn.ghost{border:1px solid #34343a;background:#111114}.btn.small{padding:7px 10px;font-size:11px}.btn:active{transform:scale(.98)}.btn:disabled{opacity:.45}.evidence-list{display:grid;gap:8px;margin-top:12px}.evidence{display:grid;grid-template-columns:38px 1fr auto;align-items:center;gap:10px;padding:10px;border:1px solid #29292e;background:#111114;border-radius:14px}.file-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:#310510;color:#ff7790;font-size:11px;font-weight:900}.file-name{font-size:12px;font-weight:800;word-break:break-word}.file-meta{font-size:10px;color:var(--muted)}.remove{border:0;background:transparent;color:#ff657f;font-size:19px;padding:8px}.empty{padding:22px;border:1px dashed #3a3a40;border-radius:14px;text-align:center;color:var(--muted);font-size:12px}.check{display:flex;align-items:flex-start;gap:10px;padding:12px;border:1px solid #302126;background:#140d0f;border-radius:14px;font-size:12px}.check input{accent-color:var(--red);width:19px;height:19px;margin:1px 0 0}.switchline{display:flex;justify-content:space-between;align-items:center;gap:12px}.switchline input{accent-color:var(--red);width:21px;height:21px}.hidden{display:none!important}.errorbox,.toast{display:none;margin-top:12px;border-radius:13px;padding:11px 13px;font-size:12px}.errorbox{background:#330710;border:1px solid #651229;color:#ff9aae}.toast{position:fixed;z-index:10;left:50%;bottom:calc(env(safe-area-inset-bottom) + 20px);transform:translateX(-50%);background:#1c1c20;border:1px solid #3c3c42;color:#f5f5f7;box-shadow:0 12px 40px #000;max-width:86%;text-align:center}.footer{text-align:center;color:#707078;font-size:10px;padding:21px 10px}
.process{min-height:440px;display:flex;flex-direction:column;justify-content:center;text-align:center}.shield{width:82px;height:92px;margin:0 auto 18px;clip-path:polygon(50% 0,94% 16%,85% 72%,50% 100%,15% 72%,6% 16%);background:linear-gradient(160deg,#ff2b4e,#7d091d);display:grid;place-items:center;font-size:34px;font-weight:950}.process h2{font-size:22px;margin:0}.progress-track{height:10px;background:#232328;border-radius:99px;overflow:hidden;margin:23px auto 10px;max-width:520px;width:100%}.progress-bar{height:100%;width:0;background:linear-gradient(90deg,#9c0a24,var(--red));transition:width .28s ease}.progress-number{font-size:36px;font-weight:950}.process-detail{color:var(--muted);font:11px ui-monospace,Menlo,monospace;min-height:18px}
.result-grid{display:grid;grid-template-columns:repeat(12,1fr);gap:11px}.result-card{grid-column:span 4;background:#0e0e11;border:1px solid #28282d;border-radius:17px;padding:15px}.result-card.wide{grid-column:1/-1}.result-card.two{grid-column:span 6}.score-ring{width:138px;height:138px;border-radius:50%;display:grid;place-items:center;margin:auto;position:relative}.score-ring:before{content:"";position:absolute;inset:13px;border-radius:50%;background:#09090b}.score-ring b,.score-ring small{position:relative}.score-ring b{font-size:34px}.score-ring small{color:var(--muted)}.tag{font-size:9px;color:var(--muted);font-weight:900;letter-spacing:1.4px;text-transform:uppercase}.result-title{font-size:19px;font-weight:950;margin:6px 0}.verdict{border-left:4px solid var(--result-color,var(--red));padding-left:12px;font-size:12px}.metric{font-size:28px;font-weight:950}.finding{padding:12px 0;border-bottom:1px solid #26262b}.finding:last-child{border-bottom:0}.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:9px;font-weight:900}.critical,.high{background:#3a0712;color:#ff7890}.medium{background:#3b2703;color:#ffc457}.low{background:#172124;color:#a4dce7}.indicator{display:block;margin-top:8px;color:#ff8ba0;font:11px ui-monospace,Menlo,monospace;word-break:break-all}.hash{font:9px ui-monospace,Menlo,monospace;color:#ff8ba0;word-break:break-all}.manifest{padding:10px 0;border-bottom:1px solid #26262b}.manifest:last-child{border-bottom:0}.actions{position:sticky;bottom:8px;z-index:5;margin-top:14px;padding:10px;border-radius:17px;background:rgba(10,10,12,.88);border:1px solid #2d2d32;backdrop-filter:blur(18px);display:flex;gap:8px;flex-wrap:wrap}.actions .btn{flex:1;min-width:90px}
@media(max-width:680px){.grid{grid-template-columns:1fr}.result-card,.result-card.two{grid-column:1/-1}.brand{font-size:28px}.app{padding-left:11px;padding-right:11px}.panel{padding:14px}.actions .btn{font-size:11px;padding:10px 8px}}
</style></head><body><main class="app">
<section class="hero"><div class="eyebrow">FORENSIC NETWORK TRIAGE · iOS · FREE FIRE</div><div class="brand"><em>andrezn</em>SS iOS</div><div class="version">v${APP.version} · INTERFAZ UNIFICADA</div><div class="notice">Análisis local de evidencias exportadas. No solicita contraseñas ni entra a cuentas. Los indicadores requieren revisión humana.</div></section>
<div id="errorBox" class="errorbox"></div><div id="toast" class="toast"></div>
<section id="setupView">
  <section class="panel"><h2>1. Autorización</h2><label class="check"><input id="consent" type="checkbox"><span>Confirmo que el propietario del dispositivo autorizó este análisis y que usaré los resultados únicamente como indicadores de revisión.</span></label></section>
  <section class="panel"><div class="row space"><div><h2 style="margin-bottom:2px">2. Evidencias</h2><div class="sub">Máximo ${APP.maxFiles} archivos · ${formatBytes(APP.maxFileBytes)} por archivo</div></div><button id="addFile" class="btn primary">＋ Añadir archivo</button></div><div id="evidenceList" class="evidence-list"></div><details style="margin-top:13px"><summary class="sub" style="cursor:pointer">Pegar texto o JSON manualmente</summary><textarea id="pastedText" class="field" style="margin-top:9px" placeholder="Pega aquí un log, NDJSON o JSON…"></textarea><button id="addText" class="btn ghost" style="margin-top:8px">Añadir texto</button></details></section>
  <section class="panel"><h2>3. Datos del caso</h2><div class="grid"><div><label>Apodo o ID del jugador</label><input id="player" class="field" autocomplete="off" placeholder="Jugador"></div><div><label>ID de partida (opcional)</label><input id="matchId" class="field" autocomplete="off" placeholder="Partida"></div><div class="full"><label>Analista</label><input id="analyst" class="field" autocomplete="off" value="andrezn"></div></div></section>
  <section class="panel"><div class="switchline"><div><h2 style="margin-bottom:2px">4. Ventana de la partida</h2><div class="sub">Mejora la correlación temporal.</div></div><input id="sessionEnabled" type="checkbox"></div><div id="sessionFields" class="grid hidden" style="margin-top:13px"><div><label>Inicio</label><input id="sessionStart" class="field" type="datetime-local"></div><div><label>Fin</label><input id="sessionEnd" class="field" type="datetime-local"></div><div class="full"><label>UTC offset del iPhone analizado</label><input id="offset" class="field" value="${defaultOffset}" placeholder="-04:00"></div></div></section>
  <button id="analyze" class="btn primary" style="width:100%;margin-top:14px;padding:15px;font-size:15px">INICIAR ANÁLISIS</button>
</section>
<section id="processingView" class="panel process hidden"><div class="shield">A</div><div class="eyebrow">andreznSS ENGINE</div><h2 id="processMessage">Preparando análisis</h2><div class="progress-track"><div id="progressBar" class="progress-bar"></div></div><div><span id="progressNumber" class="progress-number">0</span><span class="sub">%</span></div><div id="processDetail" class="process-detail"></div></section>
<section id="resultView" class="hidden"><div id="resultContent" style="margin-top:13px"></div><div class="actions"><button class="btn primary share" data-format="html">Compartir HTML</button><button class="btn ghost share" data-format="json">JSON</button><button class="btn ghost share" data-format="txt">TXT</button><button id="newAnalysis" class="btn ghost">Nuevo análisis</button></div></section>
<div class="footer">${APP.name} v${APP.version} · Negro y rojo · Autor: andrezn · Procesamiento local</div>
</main><script>
(function(){
  window.__andreznQueue = window.__andreznQueue || [];
  function send(action,payload){
    var message={action:action,payload:payload||{}};
    if(window.__andreznNativeWaiter){var callback=window.__andreznNativeWaiter;window.__andreznNativeWaiter=null;callback(JSON.stringify(message));}
    else{window.__andreznQueue.push(message);}
  }
  function byId(id){return document.getElementById(id);}
  function setView(name){
    byId('setupView').classList.toggle('hidden',name!=='setup');
    byId('processingView').classList.toggle('hidden',name!=='processing');
    byId('resultView').classList.toggle('hidden',name!=='result');
    window.scrollTo({top:0,behavior:'smooth'});
  }
  function showError(message){var box=byId('errorBox');box.textContent=message;box.style.display='block';window.scrollTo({top:0,behavior:'smooth'});}
  function clearError(){byId('errorBox').style.display='none';}
  function showToast(message){var toast=byId('toast');toast.textContent=message;toast.style.display='block';clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(function(){toast.style.display='none';},2300);}
  window.andreznApp={
    setEvidence:function(items){
      var list=byId('evidenceList');list.innerHTML='';
      if(!items.length){var empty=document.createElement('div');empty.className='empty';empty.textContent='Aún no hay evidencias cargadas.';list.appendChild(empty);return;}
      items.forEach(function(item){
        var row=document.createElement('div');row.className='evidence';
        var icon=document.createElement('div');icon.className='file-icon';icon.textContent=item.kind==='ARCHIVO'?'FILE':'TXT';
        var info=document.createElement('div');var name=document.createElement('div');name.className='file-name';name.textContent=item.name;var meta=document.createElement('div');meta.className='file-meta';meta.textContent=item.kind+' · '+item.origin;info.appendChild(name);info.appendChild(meta);
        var remove=document.createElement('button');remove.className='remove';remove.textContent='×';remove.setAttribute('aria-label','Quitar');remove.onclick=function(){send('removeEvidence',{index:item.index});};
        row.appendChild(icon);row.appendChild(info);row.appendChild(remove);list.appendChild(row);
      });
    },
    clearPastedText:function(){byId('pastedText').value='';},
    showError:showError,
    showToast:showToast,
    showSetup:function(){setView('setup');},
    showProcessing:function(message){clearError();setView('processing');byId('processMessage').textContent=message||'Analizando';byId('progressBar').style.width='2%';byId('progressNumber').textContent='2';byId('processDetail').textContent='';},
    setProgress:function(percent,message,detail){var p=Math.max(0,Math.min(100,Number(percent)||0));byId('progressBar').style.width=p+'%';byId('progressNumber').textContent=String(Math.round(p));byId('processMessage').textContent=message||'Procesando';byId('processDetail').textContent=detail||'';},
    showResult:function(html,summary){clearError();byId('resultContent').innerHTML=html;setView('result');showToast('Informe '+summary.caseId+' guardado.');},
  };
  byId('addFile').onclick=function(){clearError();send('addFile');};
  byId('addText').onclick=function(){clearError();send('addText',{text:byId('pastedText').value});};
  byId('sessionEnabled').onchange=function(){byId('sessionFields').classList.toggle('hidden',!this.checked);};
  byId('analyze').onclick=function(){
    clearError();
    send('analyze',{
      consent:byId('consent').checked,
      player:byId('player').value,
      matchId:byId('matchId').value,
      analyst:byId('analyst').value,
      sessionEnabled:byId('sessionEnabled').checked,
      start:byId('sessionStart').value,
      end:byId('sessionEnd').value,
      offset:byId('offset').value
    });
  };
  document.querySelectorAll('.share').forEach(function(button){button.onclick=function(){send('share',{format:button.getAttribute('data-format')});};});
  byId('newAnalysis').onclick=function(){send('newAnalysis');};
  send('ready');
})();
</script></body></html>`;
}

function buildResultFragment(r) {
  const topFindings = r.findings.slice(0, 120).map((f) => `
    <div class="finding">
      <span class="badge ${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span>
      <strong style="margin-left:7px;font-size:12px">${escapeHtml(f.category)}</strong>
      <code class="indicator">${escapeHtml(f.indicator)}</code>
      <div class="sub" style="margin-top:6px">${escapeHtml(f.explanation)}</div>
      <div class="sub" style="margin-top:5px">${escapeHtml(f.file)} · ${escapeHtml(f.timestamp || "SIN HORA")} · ${f.insideSession === null ? "ventana no aplicada" : (f.insideSession ? "dentro de sesión" : "fuera/no verificable")}</div>
    </div>`).join("");

  const evidence = r.integrity.evidence.map((e) => `
    <div class="manifest"><strong style="font-size:12px">${escapeHtml(e.name)}</strong><div class="sub">${escapeHtml(e.sourceType)} · ${formatBytes(e.size)}</div><div class="hash">${escapeHtml(e.sha256)}</div>${e.error ? `<div style="color:#ff7890;font-size:11px">${escapeHtml(e.error)}</div>` : ""}</div>`).join("");

  const limitations = r.limitations.map((x) => `<li style="margin-bottom:8px">${escapeHtml(x)}</li>`).join("");
  const scoreColor = escapeHtml(r.result.color);

  return `<div class="result-grid" style="--result-color:${scoreColor}">
    <section class="result-card"><div class="score-ring" style="background:conic-gradient(${scoreColor} ${r.result.score}%,#242428 0)"><div style="text-align:center"><b>${r.result.score}</b><br><small>/100</small></div></div></section>
    <section class="result-card" style="grid-column:span 8"><div class="tag">Resultado</div><div class="result-title">${escapeHtml(r.result.level)}</div><div class="verdict">${escapeHtml(r.result.verdict)}</div><div class="sub" style="margin-top:11px">${escapeHtml(r.result.conclusion)}</div></section>
    <section class="result-card"><div class="tag">Cobertura</div><div class="metric">${escapeHtml(r.completeness.grade)}</div><div class="sub">${r.completeness.score}/100</div></section>
    <section class="result-card"><div class="tag">Evidencias</div><div class="metric">${r.scope.files}</div><div class="sub">${r.scope.readableFiles} legibles · ${r.scope.totalRecords} registros</div></section>
    <section class="result-card"><div class="tag">Contexto Free Fire</div><div class="metric">${r.scope.freeFireRecords}</div><div class="sub">registros relacionados</div></section>
    <section class="result-card two"><div class="tag">Caso</div><div style="margin-top:8px;font-size:12px"><b>ID:</b> <span class="hash">${escapeHtml(r.case.id)}</span><br><b>Jugador:</b> ${escapeHtml(r.case.player)}<br><b>Partida:</b> ${escapeHtml(r.case.matchId)}<br><b>Analista:</b> ${escapeHtml(r.case.analyst)}</div></section>
    <section class="result-card two"><div class="tag">Alcance temporal</div><div style="margin-top:8px;font-size:12px"><b>Ventana:</b> ${r.session.enabled ? `${escapeHtml(r.session.start)} → ${escapeHtml(r.session.end)}` : "Análisis completo"}<br><b>Primer registro:</b> ${escapeHtml(r.scope.earliestTimestamp || "NO_DISPONIBLE")}<br><b>Último registro:</b> ${escapeHtml(r.scope.latestTimestamp || "NO_DISPONIBLE")}</div></section>
    <section class="result-card wide"><div class="row space"><h3>Hallazgos (${r.findings.length})</h3><span class="sub">Se muestran hasta 120</span></div>${topFindings || `<div class="empty" style="margin-top:12px">Sin hallazgos relevantes con las reglas actuales.</div>`}</section>
    <section class="result-card wide"><h3>Cadena de custodia e integridad</h3><div class="sub" style="margin:6px 0 9px">${escapeHtml(r.integrity.note)}</div>${evidence}</section>
    <section class="result-card wide"><h3>Limitaciones obligatorias</h3><ul class="sub" style="padding-left:19px">${limitations}</ul></section>
  </div>`;
}

function finish() {
  try { Script.complete(); } catch (_) {}
}

function dedupeInputs(inputs) {
  const seen = new Set();
  return inputs.filter((x) => {
    const key = x.kind === "file" ? `f:${x.path}` : `v:${x.name}:${x.text.length}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function analyzeEvidence(inputs, session, analyst, onProgress = null) {
  const caseId = makeCaseId();
  const startedAt = new Date();
  const manifests = [];
  const findings = [];
  const sourceTypes = new Set();
  const fileIndicatorIndex = new Map();
  let totalRecords = 0;
  let minTimestamp = null;
  let maxTimestamp = null;
  let freeFireRecords = 0;

  for (let index = 0; index < inputs.length; index++) {
    if (onProgress) {
      const percent = 7 + Math.round((index / Math.max(inputs.length, 1)) * 72);
      await onProgress({
        percent,
        message: `Analizando evidencia ${index + 1} de ${inputs.length}`,
        detail: inputs[index].kind === "file" ? fileNameFromPath(inputs[index].path) : inputs[index].name
      });
    }
    const input = inputs[index];
    const loaded = loadInput(input);
    if (!loaded.ok) {
      manifests.push({
        name: loaded.name,
        origin: input.origin,
        size: loaded.size || 0,
        sha256: loaded.sha256 || "NO_DISPONIBLE",
        sourceType: "unreadable",
        records: 0,
        error: loaded.error
      });
      continue;
    }

    const sourceType = detectSourceType(loaded.name, loaded.text);
    sourceTypes.add(sourceType);
    const records = recordsFromText(loaded.text, APP.maxRecords - totalRecords);
    totalRecords += records.length;
    let fileFindingCount = 0;

    for (const record of records) {
      if (findings.length >= APP.maxFindings) break;
      const timestamp = record.timestamp ? safeDate(record.timestamp, session.offset) : null;
      if (timestamp) {
        if (!minTimestamp || timestamp < minTimestamp) minTimestamp = timestamp;
        if (!maxTimestamp || timestamp > maxTimestamp) maxTimestamp = timestamp;
      }

      const insideWindow = session.enabled
        ? Boolean(timestamp && timestamp >= session.start && timestamp <= session.end)
        : null;
      const ffContext = containsAny(record.rawLower, RULES.freefire);
      if (ffContext) freeFireRecords++;

      const recordFindings = detectRecord(record, {
        sourceType,
        fileName: loaded.name,
        fileIndex: index,
        timestamp,
        insideWindow,
        ffContext,
        sessionEnabled: session.enabled
      });

      for (const f of recordFindings) {
        const dedupeKey = `${f.category}|${f.indicator.toLowerCase()}|${loaded.name}`;
        if (fileIndicatorIndex.has(dedupeKey)) continue;
        fileIndicatorIndex.set(dedupeKey, true);
        findings.push(f);
        fileFindingCount++;
      }
    }

    manifests.push({
      name: loaded.name,
      origin: input.origin,
      size: loaded.size,
      sha256: loaded.sha256,
      sourceType,
      records: records.length,
      findings: fileFindingCount,
      textReadable: true,
      error: null
    });
  }

  if (onProgress) await onProgress({ percent: 82, message: "Correlacionando indicadores", detail: "Tiempo · fuentes · contexto Free Fire" });
  const enriched = correlateFindings(findings, session);
  if (onProgress) await onProgress({ percent: 87, message: "Calculando riesgo", detail: "Control de falsos positivos" });
  const scoring = scoreFindings(enriched);
  if (onProgress) await onProgress({ percent: 91, message: "Evaluando cobertura", detail: "Integridad y fuentes disponibles" });
  const completeness = calculateCompleteness({ manifests, sourceTypes, session, minTimestamp, maxTimestamp, totalRecords });
  const endedAt = new Date();

  return {
    schema: "andreznss-ios-report/v1",
    app: APP,
    case: {
      id: caseId,
      player: analyst.player,
      matchId: analyst.matchId,
      analyst: analyst.analyst,
      createdAt: endedAt.toISOString(),
      processingMs: endedAt.getTime() - startedAt.getTime(),
      device: {
        name: safeCall(() => Device.name(), "NO_DISPONIBLE"),
        model: safeCall(() => Device.model(), "NO_DISPONIBLE"),
        system: `${safeCall(() => Device.systemName(), "iOS")} ${safeCall(() => Device.systemVersion(), "")}`.trim()
      }
    },
    session: serializeSession(session),
    scope: {
      files: manifests.length,
      readableFiles: manifests.filter(x => !x.error).length,
      totalRecords,
      freeFireRecords,
      sourceTypes: Array.from(sourceTypes),
      earliestTimestamp: minTimestamp ? minTimestamp.toISOString() : null,
      latestTimestamp: maxTimestamp ? maxTimestamp.toISOString() : null
    },
    integrity: {
      algorithm: "SHA-256",
      note: "El hash demuestra la identidad del archivo recibido durante este análisis; no demuestra que el archivo no haya sido editado antes de recibirse.",
      evidence: manifests
    },
    completeness,
    result: scoring,
    findings: enriched.sort(sortFindings),
    limitations: [
      "iOS no permite a Scriptable inspeccionar libremente memoria, procesos ni contenedores privados de otras apps.",
      "Un proxy, VPN, DNS personalizado o app de sideload no demuestra por sí solo el uso de cheats.",
      "La evidencia exportada puede ser incompleta, anterior a la partida o editada antes de su recepción.",
      "Los dominios de CDN, publicidad y analítica pueden producir coincidencias no relacionadas con manipulación del juego.",
      "La conclusión debe ser revisada por una persona y contrastada con la partida, video y demás evidencia disponible."
    ]
  };
}

function loadInput(input) {
  try {
    if (input.kind === "virtual") {
      const data = Data.fromString(input.text);
      const bytes = data.getBytes();
      return {
        ok: true,
        name: input.name,
        text: input.text,
        size: bytes.length,
        sha256: sha256(bytes)
      };
    }

    const path = input.path;
    const data = Data.fromFile(path);
    if (!data) throw new Error("No se pudo leer el archivo.");
    const bytes = data.getBytes();
    const name = fileNameFromPath(path);
    if (bytes.length > APP.maxFileBytes) {
      return {
        ok: false,
        name,
        size: bytes.length,
        sha256: sha256(bytes),
        error: `Archivo superior al límite de ${formatBytes(APP.maxFileBytes)} para proteger la memoria de iOS.`
      };
    }
    const text = data.toRawString();
    if (text === null || text === undefined) {
      return { ok: false, name, size: bytes.length, sha256: sha256(bytes), error: "El archivo no contiene texto UTF-8 legible." };
    }
    return { ok: true, name, text, size: bytes.length, sha256: sha256(bytes) };
  } catch (e) {
    return { ok: false, name: input.name || fileNameFromPath(input.path || "evidencia"), error: String(e) };
  }
}

function detectSourceType(name, text) {
  const n = name.toLowerCase();
  const t = text.slice(0, 50000).toLowerCase();
  if (n.endsWith(".ips") || /"bug_type"\s*:/.test(t) || /incident identifier/.test(t)) return "ios_analytics_ips";
  if (n.includes("privacy") || n.includes("privacidad") || t.includes("app privacy report") || t.includes("networkactivity")) return "app_privacy_report";
  if (containsAny(t, RULES.proxyTools) || /proxy|tunnel|wireguard|shadowrocket/.test(n)) return "proxy_or_vpn_log";
  if (n.endsWith(".ndjson")) return "ndjson_log";
  if (n.endsWith(".json")) return "json_log";
  return "generic_text_log";
}

function recordsFromText(text, remainingLimit) {
  if (remainingLimit <= 0) return [];
  const trimmed = text.trim();
  const records = [];

  // Intentar JSON completo.
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      collectJsonRecords(parsed, records, remainingLimit, 0, "$");
      if (records.length) return records;
    } catch (_) {}
  }

  // NDJSON o logs por línea.
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length && records.length < remainingLimit; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    let obj = null;
    if ((line.startsWith("{") && line.endsWith("}")) || (line.startsWith("[") && line.endsWith("]"))) {
      try { obj = JSON.parse(line); } catch (_) {}
    }
    const raw = obj ? safeStringify(obj) : line;
    records.push(makeRecord(raw, obj, `line:${i + 1}`));
  }

  // Archivos sin saltos de línea: fragmentar.
  if (!records.length && text.length) {
    for (let i = 0; i < text.length && records.length < remainingLimit; i += 800) {
      records.push(makeRecord(text.slice(i, i + 800), null, `chunk:${Math.floor(i / 800) + 1}`));
    }
  }
  return records;
}

function collectJsonRecords(value, records, limit, depth, path) {
  if (records.length >= limit || depth > 8 || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length && records.length < limit; i++) {
      collectJsonRecords(value[i], records, limit, depth + 1, `${path}[${i}]`);
    }
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    const scalarCount = keys.filter(k => value[k] === null || typeof value[k] !== "object").length;
    if (scalarCount >= 2 || keys.length <= 8) {
      records.push(makeRecord(safeStringify(value), value, path));
    }
    for (const key of keys) {
      if (records.length >= limit) break;
      if (value[key] && typeof value[key] === "object") {
        collectJsonRecords(value[key], records, limit, depth + 1, `${path}.${key}`);
      }
    }
    return;
  }
  records.push(makeRecord(String(value), null, path));
}

function makeRecord(raw, obj, location) {
  const normalizedRaw = String(raw || "");
  return {
    raw: normalizedRaw,
    rawLower: normalizedRaw.toLowerCase(),
    obj,
    location,
    timestamp: extractTimestamp(obj, normalizedRaw)
  };
}

function extractTimestamp(obj, raw) {
  const keys = ["timestamp", "timeStamp", "time", "date", "datetime", "eventTime", "startTime", "occurredAt", "creationDate"];
  if (obj && typeof obj === "object") {
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const candidate = obj[key];
        if (safeDate(candidate)) return candidate;
      }
    }
  }
  const iso = raw.match(/\b20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b/);
  if (iso && safeDate(iso[0])) return iso[0];

  const apple = raw.match(/\b20\d{2}-\d{2}-\d{2}\s+[0-2]\d:[0-5]\d:[0-5]\d\s+[+-]\d{4}\b/);
  if (apple) {
    const normalized = apple[0]
      .replace(/ ([+-]\d{2})(\d{2})$/, "$1:$2")
      .replace(" ", "T");
    if (safeDate(normalized)) return normalized;
  }
  return null;
}

function detectRecord(record, ctx) {
  const out = [];
  const text = record.rawLower;
  const add = (category, severity, baseScore, indicator, explanation, confidence) => {
    out.push({
      id: `${ctx.fileIndex}-${record.location}-${category}-${indicator}`.slice(0, 180),
      category,
      severity,
      baseScore,
      confidence,
      indicator,
      explanation,
      file: ctx.fileName,
      sourceType: ctx.sourceType,
      location: record.location,
      timestamp: ctx.timestamp ? ctx.timestamp.toISOString() : null,
      insideSession: ctx.insideWindow,
      freeFireContext: ctx.ffContext,
      snippet: redactAndTrim(record.raw, 420)
    });
  };

  for (const indicator of matchedTerms(text, RULES.dynamicInstrumentation)) {
    add("INSTRUMENTACION_DINAMICA", "CRITICAL", 38, indicator,
      "Indicador asociado con instrumentación o inyección dinámica. Requiere confirmación en una segunda fuente.", 88);
  }
  for (const indicator of matchedTerms(text, RULES.mitmTools)) {
    add("INTERCEPCION_TLS_MITM", "HIGH", 28, indicator,
      "Herramienta o técnica compatible con inspección/intercepción de tráfico TLS.", 82);
  }
  for (const indicator of matchedTerms(text, RULES.jailbreak)) {
    add("JAILBREAK", "HIGH", 27, indicator,
      "Indicador compatible con jailbreak o gestor de paquetes/tweaks.", 80);
  }
  for (const indicator of matchedTerms(text, RULES.suspiciousPaths)) {
    add("RUTA_SISTEMA_SOSPECHOSA", "HIGH", 25, indicator,
      "Ruta vinculada con entornos de jailbreak o carga de tweaks.", 86);
  }
  for (const indicator of matchedTerms(text, RULES.proxyTools)) {
    add("PROXY_TUNEL", "MEDIUM", 8, indicator,
      "Herramienta o proveedor de túnel/proxy. Su presencia no prueba manipulación del juego.", 65);
  }
  for (const indicator of matchedTerms(text, RULES.vpnDns)) {
    add("VPN_DNS_PERSONALIZADO", "LOW", 5, indicator,
      "Configuración o interfaz compatible con VPN, túnel o DNS personalizado.", 55);
  }
  for (const indicator of matchedTerms(text, RULES.sideload)) {
    add("SIDELOAD_FIRMA", "MEDIUM", 8, indicator,
      "Indicador de instalación o firma externa. Puede ser legítimo y necesita contexto.", 60);
  }
  for (const indicator of matchedTerms(text, RULES.suspiciousKeywords)) {
    add("PALABRA_CLAVE_CHEAT", "MEDIUM", 10, indicator,
      "Coincidencia textual relacionada con cheats; es una señal débil si aparece aislada.", 52);
  }

  const domains = extractDomains(record.raw);
  for (const domain of domains.slice(0, 25)) {
    if (isAllowedDomain(domain)) continue;
    const token = RULES.suspiciousDomainTokens.find(t => domain.includes(t.toLowerCase()));
    if (token) {
      add("DOMINIO_SOSPECHOSO", "HIGH", 20, domain,
        `Dominio con token sospechoso: ${token}. Debe verificarse su atribución y fecha de contacto.`, 76);
    } else if (ctx.ffContext && looksLikeDynamicHost(domain)) {
      add("HOST_DINAMICO_EN_CONTEXTO_FF", "LOW", 4, domain,
        "Host dinámico o de túnel observado en un registro que también menciona Free Fire. Señal débil.", 45);
    }
  }

  const ips = extractIPs(record.raw);
  for (const ip of ips.slice(0, 10)) {
    if (isPrivateIP(ip)) continue;
    if (ctx.ffContext && (containsAny(text, RULES.proxyTools) || containsAny(text, RULES.mitmTools))) {
      add("IP_PUBLICA_CORRELACIONADA", "LOW", 3, ip,
        "IP pública presente junto con contexto de Free Fire y proxy/MITM. Requiere reputación externa y revisión manual.", 42);
    }
  }

  return out;
}

function correlateFindings(findings, session) {
  const indicatorFiles = new Map();
  for (const f of findings) {
    const key = `${f.category}|${f.indicator.toLowerCase()}`;
    if (!indicatorFiles.has(key)) indicatorFiles.set(key, new Set());
    indicatorFiles.get(key).add(f.file);
  }

  return findings.map((f) => {
    let correlationBonus = 0;
    const reasons = [];
    const files = indicatorFiles.get(`${f.category}|${f.indicator.toLowerCase()}`);
    if (files && files.size >= 2) {
      correlationBonus += 8;
      reasons.push(`mismo indicador en ${files.size} archivos`);
    }
    if (session.enabled && f.insideSession) {
      correlationBonus += 5;
      reasons.push("dentro de la ventana de partida");
    }
    if (f.freeFireContext && !["VPN_DNS_PERSONALIZADO", "PROXY_TUNEL"].includes(f.category)) {
      correlationBonus += 5;
      reasons.push("registro con contexto de Free Fire");
    }
    if (session.enabled && !f.timestamp) {
      correlationBonus -= 4;
      reasons.push("sin timestamp verificable");
    }
    return { ...f, correlationBonus, correlation: reasons };
  });
}

function scoreFindings(findings) {
  const categoryCaps = {
    INSTRUMENTACION_DINAMICA: 45,
    INTERCEPCION_TLS_MITM: 35,
    JAILBREAK: 32,
    RUTA_SISTEMA_SOSPECHOSA: 30,
    DOMINIO_SOSPECHOSO: 26,
    PROXY_TUNEL: 16,
    SIDELOAD_FIRMA: 12,
    VPN_DNS_PERSONALIZADO: 10,
    PALABRA_CLAVE_CHEAT: 14,
    HOST_DINAMICO_EN_CONTEXTO_FF: 8,
    IP_PUBLICA_CORRELACIONADA: 6
  };

  const categoryTotals = {};
  for (const f of findings) {
    const raw = Math.max(0, f.baseScore + f.correlationBonus);
    categoryTotals[f.category] = (categoryTotals[f.category] || 0) + raw;
  }

  let score = 0;
  for (const [category, value] of Object.entries(categoryTotals)) {
    score += Math.min(value, categoryCaps[category] || 15);
  }

  const highSignal = findings.some(f => [
    "INSTRUMENTACION_DINAMICA", "INTERCEPCION_TLS_MITM", "JAILBREAK",
    "RUTA_SISTEMA_SOSPECHOSA", "DOMINIO_SOSPECHOSO"
  ].includes(f.category));
  const strongCorrelation = findings.some(f => f.correlationBonus >= 8);

  // No permitir que VPN/proxy/sideload aislados generen una acusación grave.
  if (!highSignal) score = Math.min(score, 39);
  if (highSignal && !strongCorrelation) score = Math.min(score, 69);
  score = Math.max(0, Math.min(100, Math.round(score)));

  let level, verdict, color;
  if (score <= 14) {
    level = "SIN_HALLAZGOS_RELEVANTES";
    verdict = "No se encontraron indicadores relevantes en la evidencia recibida.";
    color = COLORS.green;
  } else if (score <= 29) {
    level = "REVISION_PREVENTIVA";
    verdict = "Se encontraron indicadores débiles o de uso legítimo posible. Revisión manual recomendada.";
    color = COLORS.amber;
  } else if (score <= 49) {
    level = "ACTIVIDAD_SOSPECHOSA";
    verdict = "Hay señales sospechosas, pero la evidencia aún no permite afirmar uso de cheats.";
    color = COLORS.amber;
  } else if (score <= 69) {
    level = "RIESGO_ALTO";
    verdict = "Existen indicadores de alto riesgo que requieren contraste con video, partida y una segunda fuente independiente.";
    color = COLORS.red;
  } else {
    level = "EVIDENCIA_CRITICA_PARA_REVISION";
    verdict = "Se detectaron indicadores críticos correlacionados. Esto exige revisión humana; no equivale automáticamente a cheat confirmado.";
    color = COLORS.red;
  }

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return {
    score,
    level,
    verdict,
    color,
    findingCounts: counts,
    categories: categoryTotals,
    conclusion: "INDICADORES_DE_TRIAGE_NO_PRUEBA_AUTOMATICA"
  };
}

function calculateCompleteness({ manifests, sourceTypes, session, minTimestamp, maxTimestamp, totalRecords }) {
  let points = 0;
  const reasons = [];
  const readable = manifests.filter(x => !x.error);
  if (readable.length >= 1) { points += 20; reasons.push("al menos un archivo legible"); }
  if (readable.length >= 2) { points += 15; reasons.push("múltiples archivos"); }
  if (sourceTypes.size >= 2) { points += 20; reasons.push("fuentes independientes"); }
  if (sourceTypes.has("app_privacy_report")) { points += 15; reasons.push("reporte de privacidad"); }
  if (sourceTypes.has("ios_analytics_ips")) { points += 10; reasons.push("diagnóstico IPS"); }
  if (session.enabled) { points += 10; reasons.push("ventana de partida definida"); }
  if (minTimestamp && maxTimestamp) { points += 10; reasons.push("timestamps detectados"); }
  if (totalRecords === 0) points = 0;
  points = Math.min(100, points);
  let grade = points >= 80 ? "A" : points >= 60 ? "B" : points >= 35 ? "C" : "D";
  return {
    score: points,
    grade,
    reasons,
    note: grade === "A"
      ? "Cobertura sólida para triage remoto, todavía sujeta a autenticidad y completitud de las exportaciones."
      : "La cobertura es limitada. Una conclusión fuerte requeriría más fuentes y una ventana temporal verificable."
  };
}

async function saveReports(result) {
  const fm = FileManager.iCloud();
  const documents = fm.documentsDirectory();
  const folder = fm.joinPath(documents, APP.reportFolder);
  ensureDirectory(fm, folder);
  const safeCase = result.case.id.replace(/[^A-Za-z0-9_-]/g, "_");
  const jsonPath = fm.joinPath(folder, `${safeCase}.json`);
  const htmlPath = fm.joinPath(folder, `${safeCase}.html`);
  const txtPath = fm.joinPath(folder, `${safeCase}.txt`);
  fm.writeString(jsonPath, JSON.stringify(result, null, 2));
  fm.writeString(htmlPath, buildHtml(result));
  fm.writeString(txtPath, buildTextReport(result));
  return { json: jsonPath, html: htmlPath, txt: txtPath, folder };
}

async function showDashboard(result) {
  const web = new WebView();
  await web.loadHTML(buildHtml(result));
  await web.present(true);
}

async function reportActions(paths, result) {
  const a = new Alert();
  a.title = "Informe guardado";
  a.message = `${result.case.id}\nPuntuación: ${result.result.score}/100\nCobertura: ${result.completeness.grade}`;
  a.addAction("Compartir HTML");
  a.addAction("Compartir JSON");
  a.addAction("Compartir TXT");
  a.addAction("Finalizar");
  const action = await a.presentSheet();
  if (action === 0) await ShareSheet.present([paths.html]);
  else if (action === 1) await ShareSheet.present([paths.json]);
  else if (action === 2) await ShareSheet.present([paths.txt]);
}

function buildTextReport(r) {
  const lines = [];
  lines.push(`${APP.name.toUpperCase()} v${APP.version}`);
  lines.push("=".repeat(64));
  lines.push(`CASO: ${r.case.id}`);
  lines.push(`JUGADOR: ${r.case.player}`);
  lines.push(`PARTIDA: ${r.case.matchId}`);
  lines.push(`ANALISTA: ${r.case.analyst}`);
  lines.push(`FECHA: ${r.case.createdAt}`);
  lines.push("");
  lines.push(`RESULTADO: ${r.result.level}`);
  lines.push(`PUNTUACIÓN: ${r.result.score}/100`);
  lines.push(`COBERTURA: ${r.completeness.grade} (${r.completeness.score}/100)`);
  lines.push(`CONCLUSIÓN: ${r.result.verdict}`);
  lines.push("");
  lines.push("MANIFIESTO DE EVIDENCIA");
  lines.push("-".repeat(64));
  for (const e of r.integrity.evidence) {
    lines.push(`${e.name} | ${formatBytes(e.size)} | ${e.sourceType} | SHA-256 ${e.sha256}`);
    if (e.error) lines.push(`  ERROR: ${e.error}`);
  }
  lines.push("");
  lines.push("HALLAZGOS");
  lines.push("-".repeat(64));
  if (!r.findings.length) lines.push("Sin hallazgos relevantes.");
  for (const f of r.findings) {
    lines.push(`[${f.severity}] ${f.category} | ${f.indicator}`);
    lines.push(`Archivo: ${f.file} | Hora: ${f.timestamp || "NO_DISPONIBLE"} | En partida: ${f.insideSession}`);
    lines.push(`Motivo: ${f.explanation}`);
    if (f.correlation.length) lines.push(`Correlación: ${f.correlation.join(", ")}`);
    lines.push(`Contexto: ${f.snippet}`);
    lines.push("");
  }
  lines.push("LIMITACIONES");
  lines.push("-".repeat(64));
  for (const x of r.limitations) lines.push(`- ${x}`);
  return lines.join("\n");
}

function buildHtml(r) {
  const findingsRows = r.findings.slice(0, 250).map((f) => `
    <tr>
      <td><span class="badge ${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span></td>
      <td><strong>${escapeHtml(f.category)}</strong><br><span class="muted">${escapeHtml(f.explanation)}</span></td>
      <td><code>${escapeHtml(f.indicator)}</code><br><span class="muted">${escapeHtml(f.file)}</span></td>
      <td>${escapeHtml(f.timestamp || "SIN HORA")}<br><span class="muted">${f.insideSession === null ? "Ventana no aplicada" : (f.insideSession ? "Dentro de sesión" : "Fuera/no verificable")}</span></td>
    </tr>`).join("");

  const evidenceRows = r.integrity.evidence.map((e) => `
    <tr>
      <td>${escapeHtml(e.name)}</td>
      <td>${escapeHtml(e.sourceType)}</td>
      <td>${formatBytes(e.size)}</td>
      <td><code class="hash">${escapeHtml(e.sha256)}</code>${e.error ? `<br><span class="error">${escapeHtml(e.error)}</span>` : ""}</td>
    </tr>`).join("");

  const limitations = r.limitations.map(x => `<li>${escapeHtml(x)}</li>`).join("");
  const sourceTypes = r.scope.sourceTypes.length ? r.scope.sourceTypes.map(escapeHtml).join(" · ") : "No identificadas";
  const scoreColor = r.result.color;

  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(r.case.id)} — ${APP.name}</title>
<style>
:root{--bg:${COLORS.bg};--panel:${COLORS.panel};--panel2:${COLORS.panel2};--red:${COLORS.red};--red2:${COLORS.redDark};--text:${COLORS.white};--muted:${COLORS.muted};--green:${COLORS.green};--amber:${COLORS.amber}}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 90% 0,#25030b 0,transparent 32%),var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",Inter,Arial,sans-serif;line-height:1.45}
.wrap{max-width:1180px;margin:auto;padding:24px}.hero{border:1px solid #3c0b15;background:linear-gradient(145deg,#130207,#09090a 60%);border-radius:22px;padding:24px;box-shadow:0 18px 60px #000}
.brand{font-weight:900;font-size:32px;letter-spacing:-1px}.brand em{font-style:normal;color:var(--red)}.tag{color:var(--muted);text-transform:uppercase;letter-spacing:2px;font-size:11px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}.card{grid-column:span 4;background:rgba(13,13,15,.94);border:1px solid #242428;border-radius:18px;padding:18px}.wide{grid-column:span 12}.half{grid-column:span 6}.score{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(${scoreColor} ${r.result.score}%,#242428 0);position:relative;margin:auto}.score:before{content:"";position:absolute;inset:13px;border-radius:50%;background:#09090a}.score b{position:relative;font-size:34px}.score small{position:relative;color:var(--muted)}h2{font-size:17px;margin:0 0 12px}h3{margin:0}.metric{font-size:27px;font-weight:800}.muted{color:var(--muted);font-size:12px}.verdict{border-left:4px solid ${scoreColor};padding-left:14px}.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:10px;font-weight:800}.critical,.high{background:#3a0712;color:#ff6680}.medium{background:#3b2703;color:#ffc457}.low{background:#172124;color:#9fd7e3}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #242428}th{color:#c9c9cf;font-size:10px;text-transform:uppercase;letter-spacing:1px}code{color:#ff879a;word-break:break-all}.hash{font-size:10px}.error{color:#ff6680}.footer{color:var(--muted);font-size:11px;text-align:center;padding:28px}ul{padding-left:20px}.case{color:var(--red);font-family:ui-monospace,Menlo,monospace}
@media(max-width:760px){.wrap{padding:12px}.card,.half{grid-column:span 12}.brand{font-size:26px}table{display:block;overflow-x:auto}.score{width:130px;height:130px}}
</style></head><body><div class="wrap">
<section class="hero"><div class="tag">FORENSIC NETWORK TRIAGE · iOS · FREE FIRE</div><div class="brand"><em>andrezn</em>SS iOS</div><div class="case">${escapeHtml(r.case.id)}</div></section>
<div class="grid">
<section class="card"><div class="score"><div style="text-align:center"><b>${r.result.score}</b><br><small>/100</small></div></div></section>
<section class="card" style="grid-column:span 8"><div class="tag">Resultado</div><h3>${escapeHtml(r.result.level)}</h3><p class="verdict">${escapeHtml(r.result.verdict)}</p><span class="muted">Conclusión controlada: ${escapeHtml(r.result.conclusion)}</span></section>
<section class="card"><div class="tag">Cobertura</div><div class="metric">${escapeHtml(r.completeness.grade)}</div><div class="muted">${r.completeness.score}/100 · ${escapeHtml(r.completeness.note)}</div></section>
<section class="card"><div class="tag">Evidencias</div><div class="metric">${r.scope.files}</div><div class="muted">${r.scope.readableFiles} legibles · ${r.scope.totalRecords} registros</div></section>
<section class="card"><div class="tag">Contexto Free Fire</div><div class="metric">${r.scope.freeFireRecords}</div><div class="muted">registros con coincidencia contextual</div></section>
<section class="card half"><h2>Datos del caso</h2><b>Jugador:</b> ${escapeHtml(r.case.player)}<br><b>Partida:</b> ${escapeHtml(r.case.matchId)}<br><b>Analista:</b> ${escapeHtml(r.case.analyst)}<br><b>Creado:</b> ${escapeHtml(r.case.createdAt)}</section>
<section class="card half"><h2>Alcance temporal</h2><b>Ventana:</b> ${r.session.enabled ? `${escapeHtml(r.session.start)} → ${escapeHtml(r.session.end)}` : "Análisis completo"}<br><b>Primer timestamp:</b> ${escapeHtml(r.scope.earliestTimestamp || "NO_DISPONIBLE")}<br><b>Último timestamp:</b> ${escapeHtml(r.scope.latestTimestamp || "NO_DISPONIBLE")}<br><b>Fuentes:</b> ${sourceTypes}</section>
<section class="card wide"><h2>Hallazgos (${r.findings.length})</h2><table><thead><tr><th>Gravedad</th><th>Categoría</th><th>Indicador</th><th>Tiempo</th></tr></thead><tbody>${findingsRows || `<tr><td colspan="4">Sin hallazgos relevantes en las reglas actuales.</td></tr>`}</tbody></table></section>
<section class="card wide"><h2>Cadena de custodia e integridad</h2><p class="muted">${escapeHtml(r.integrity.note)}</p><table><thead><tr><th>Archivo</th><th>Tipo</th><th>Tamaño</th><th>SHA-256</th></tr></thead><tbody>${evidenceRows}</tbody></table></section>
<section class="card wide"><h2>Limitaciones obligatorias</h2><ul>${limitations}</ul></section>
</div><div class="footer">${APP.name} v${APP.version} · Diseño negro/rojo · Autor: andrezn · Análisis local sin carga automática a servidores</div>
</div></body></html>`;
}

async function loadCustomRules() {
  try {
    const fm = FileManager.iCloud();
    const path = fm.joinPath(fm.documentsDirectory(), APP.customRulesPath);
    if (!fm.fileExists(path)) return;
    if (fm.isFileStoredIniCloud(path)) await fm.downloadFileFromiCloud(path);
    const parsed = JSON.parse(fm.readString(path));
    for (const key of Object.keys(BASE_RULES)) {
      if (Array.isArray(parsed[key])) {
        RULES[key] = Array.from(new Set([...BASE_RULES[key], ...parsed[key].map(String)]));
      }
    }
  } catch (_) {
    RULES = JSON.parse(JSON.stringify(BASE_RULES));
  }
}

function matchedTerms(text, list) {
  const matches = [];
  for (const item of list) {
    const term = String(item).toLowerCase();
    if (term && text.includes(term)) matches.push(String(item));
  }
  return matches.slice(0, 12);
}

function containsAny(text, list) {
  for (const item of list) if (text.includes(String(item).toLowerCase())) return true;
  return false;
}

function extractDomains(text) {
  const set = new Set();
  const urlRegex = /\b(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gg|app|dev|cloud|site|xyz|top|live|online|me|co|cc|tv|info|biz|link|shop|store|ru|cn|br|us|uk|eu|in|ai|lol|pw|pro|vip))(?:[:\/\s]|$)/gi;
  let m;
  while ((m = urlRegex.exec(text)) !== null && set.size < 50) set.add(m[1].toLowerCase());
  return Array.from(set);
}

function extractIPs(text) {
  const set = new Set();
  const regex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  let m;
  while ((m = regex.exec(text)) !== null && set.size < 30) set.add(m[0]);
  return Array.from(set);
}

function isAllowedDomain(domain) {
  return RULES.allowDomains.some(d => domain === d || domain.endsWith(`.${d}`));
}

function looksLikeDynamicHost(domain) {
  return /(?:duckdns|no-ip|ddns|dynu|serveo|ngrok|trycloudflare|localtunnel|tunnel|workers\.dev|pages\.dev|vercel\.app|onrender\.com|railway\.app)/i.test(domain);
}

function isPrivateIP(ip) {
  const p = ip.split(".").map(Number);
  return p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254);
}

function sortFindings(a, b) {
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  return (rank[b.severity] - rank[a.severity]) || ((b.baseScore + b.correlationBonus) - (a.baseScore + a.correlationBonus));
}

function sha256(bytes) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const msg = bytes.slice();
  const bitLen = bytes.length * 8;
  msg.push(0x80);
  while ((msg.length % 64) !== 56) msg.push(0);
  const high = Math.floor(bitLen / 0x100000000);
  const low = bitLen >>> 0;
  msg.push((high >>> 24)&255,(high >>> 16)&255,(high >>> 8)&255,high&255,(low >>> 24)&255,(low >>> 16)&255,(low >>> 8)&255,low&255);
  const w = new Array(64);
  const rotr = (x,n) => (x >>> n) | (x << (32-n));
  for (let offset = 0; offset < msg.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((msg[j]<<24)|(msg[j+1]<<16)|(msg[j+2]<<8)|msg[j+3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+temp1)>>>0; d=c; c=b; b=a; a=(temp1+temp2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  return H.map(x => x.toString(16).padStart(8,"0")).join("");
}

function normalizeFilePath(value) {
  let path = value;
  if (path.startsWith("file://")) path = path.replace(/^file:\/\//, "");
  try { path = decodeURIComponent(path); } catch (_) {}
  return path;
}

function fileNameFromPath(path) {
  const p = String(path || "evidencia").split("/").pop() || "evidencia";
  try { return decodeURIComponent(p); } catch (_) { return p; }
}

function normalizeOffset(value) {
  const m = String(value).match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return "+00:00";
  return `${m[1]}${m[2]}:${m[3]}`;
}

function parseManualDate(value, offset) {
  if (!/^20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?$/.test(value)) return null;
  return safeDate(value.replace(" ", "T") + (value.length === 16 ? ":00" : "") + offset);
}

function safeDate(value, defaultOffset = null) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") {
    const ms = value < 1e12 ? value * 1000 : value;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? null : d;
  }
  let text = String(value).trim();
  if (/^\d{10,13}$/.test(text)) return safeDate(Number(text), defaultOffset);
  if (/^20\d{2}-\d{2}-\d{2} \d{2}:\d{2}/.test(text)) text = text.replace(" ", "T");
  if (defaultOffset && /^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(text)) {
    text += defaultOffset;
  }
  const d = new Date(text);
  return isNaN(d.getTime()) ? null : d;
}

function serializeSession(session) {
  return {
    enabled: session.enabled,
    start: session.start ? session.start.toISOString() : null,
    end: session.end ? session.end.toISOString() : null,
    offset: session.offset || null,
    valid: session.valid
  };
}

function makeCaseId() {
  const d = new Date();
  const stamp = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}-${String(d.getHours()).padStart(2,"0")}${String(d.getMinutes()).padStart(2,"0")}${String(d.getSeconds()).padStart(2,"0")}`;
  const rnd = Math.random().toString(36).slice(2,7).toUpperCase();
  return `ANDREZN-IOS-${stamp}-${rnd}`;
}

function ensureDirectory(fm, path) {
  if (!fm.fileExists(path)) fm.createDirectory(path, true);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024*1024) return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1024/1024).toFixed(2)} MB`;
}

function redactAndTrim(value, max) {
  let s = String(value || "")
    .replace(/(["']?(?:password|passwd|token|authorization|cookie|session|secret)["']?\s*[:=]\s*)[^,\s}\]]+/gi, "$1[REDACTADO]")
    .replace(/\s+/g, " ")
    .trim();
  if (s.length > max) s = s.slice(0, max - 1) + "…";
  return s;
}

function sanitizeLabel(value, fallback) {
  const s = String(value || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
  return s || fallback;
}

function safeStringify(value) {
  try { return JSON.stringify(value); } catch (_) { return String(value); }
}

function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

function safeCall(fn, fallback) {
  try { return fn(); } catch (_) { return fallback; }
}

async function simpleAlert(title, message) {
  const a = new Alert();
  a.title = title;
  a.message = message;
  a.addAction("Aceptar");
  await a.presentAlert();
}
