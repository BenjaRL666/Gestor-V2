let claveActual = null;
let saltActual = null;
let vaultActual = null;
let iteracionesActuales = CURRENT_KDF_ITERATIONS;
let autoLockTimer = null;
let toastTimer = null;
let saveQueue = Promise.resolve();
let sessionGeneration = 0;

const DEFAULT_SETTINGS = {
  autoLockMinutes: 5,
  privacyMode: false
};

window.addEventListener("DOMContentLoaded", () => {
  const existeVault = localStorage.getItem("vault_gestor");
  document.getElementById("pantallaSetup").style.display = existeVault ? "none" : "flex";
  document.getElementById("pantallaDesbloqueo").style.display = existeVault ? "flex" : "none";

  document.getElementById("passDesbloqueo")?.addEventListener("keydown", e => {
    if (e.key === "Enter") desbloquear();
  });
  document.getElementById("pass2")?.addEventListener("keydown", e => {
    if (e.key === "Enter") crearVault();
  });

  ["click", "keydown", "mousemove", "touchstart"].forEach(evt => {
    document.addEventListener(evt, () => {
      if (vaultActual) reiniciarAutoLock();
    }, { passive: true });
  });

  document.addEventListener("keydown", manejarAtajos);
  document.querySelectorAll(".overlay").forEach(overlay => {
    overlay.addEventListener("mousedown", e => {
      if (e.target === overlay) cerrarOverlayPorId(overlay.id);
    });
  });
});

function validarContenidoVault(vault) {
  if (!vault || typeof vault !== "object" || !Array.isArray(vault.entradas)) throw new Error("Contenido inválido");
  for (const name of ["entradas", "papelera", "notas", "codigos"]) {
    if (vault[name] === undefined) continue;
    if (!Array.isArray(vault[name])) throw new Error("Lista inválida");
    for (const item of vault[name]) {
      if (!item || typeof item !== "object") throw new Error("Entrada inválida");
      if (item.id !== undefined && (typeof item.id !== "string" || !/^[a-zA-Z0-9_-]{1,100}$/.test(item.id))) throw new Error("Identificador inválido");
      for (const field of ["sitio", "usuario", "contraseña", "notas", "url", "categoria", "titulo", "contenido", "nombre", "secreto", "creadoEn", "actualizadoEn", "eliminadoEn"]) {
        if (item[field] !== undefined && typeof item[field] !== "string") throw new Error("Campo inválido");
      }
      if (name === "codigos" && (typeof item.secreto !== "string" || !/^[A-Z2-7\s=-]+$/i.test(item.secreto))) throw new Error("Secreto inválido");
    }
  }
}

function normalizarVault(vault = {}) {
  return {
    entradas: Array.isArray(vault.entradas) ? vault.entradas.map(e => ({
      id: e.id || crypto.randomUUID(),
      sitio: e.sitio || "Sin nombre",
      usuario: e.usuario || "",
      contraseña: e.contraseña || "",
      notas: e.notas || "",
      url: e.url || "",
      categoria: e.categoria || "Otros",
      favorito: Boolean(e.favorito),
      creadoEn: e.creadoEn || e.actualizadoEn || new Date().toISOString(),
      actualizadoEn: e.actualizadoEn || e.creadoEn || new Date().toISOString()
    })) : [],
    codigos: Array.isArray(vault.codigos) ? vault.codigos : [],
    notas: Array.isArray(vault.notas) ? vault.notas : [],
    papelera: Array.isArray(vault.papelera) ? vault.papelera : [],
    settings: { ...DEFAULT_SETTINGS, ...(vault.settings || {}) }
  };
}

async function crearVault() {
  const pass1 = document.getElementById("pass1").value;
  const pass2 = document.getElementById("pass2").value;
  const mensaje = document.getElementById("mensaje");

  if (pass1.length < 10) return setMensaje(mensaje, "Usa al menos 10 caracteres para la contraseña maestra.", "error");
  if (pass1 !== pass2) return setMensaje(mensaje, "Las contraseñas no coinciden.", "error");

  setMensaje(mensaje, "Creando y cifrando tu bóveda…", "");
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const clave = await derivarClave(pass1, salt, CURRENT_KDF_ITERATIONS);
    const vault = normalizarVault();
    const { iv, cifrado } = await cifrarVault(vault, clave);
    localStorage.setItem("vault_gestor", JSON.stringify({
      version: 2,
      iterations: CURRENT_KDF_ITERATIONS,
      salt: bytesABase64(salt),
      iv: bytesABase64(iv),
      cifrado: bytesABase64(cifrado)
    }));
    document.getElementById("pass1").value = "";
    document.getElementById("pass2").value = "";
    document.getElementById("pantallaSetup").style.display = "none";
    document.getElementById("pantallaDesbloqueo").style.display = "flex";
    setMensaje(document.getElementById("mensajeDesbloqueo"), "Bóveda creada. Desbloquéala para comenzar.", "ok");
  } catch (err) {
    setMensaje(mensaje, "No se pudo crear la bóveda en este navegador.", "error");
  }
}

async function desbloquear() {
  const passIngresada = document.getElementById("passDesbloqueo").value;
  const mensaje = document.getElementById("mensajeDesbloqueo");
  if (!passIngresada) return setMensaje(mensaje, "Ingresa tu contraseña maestra.", "error");

  setMensaje(mensaje, "Verificando y descifrando…", "");
  let guardado;
  try {
    guardado = JSON.parse(localStorage.getItem("vault_gestor"));
    if (!guardado?.salt || !guardado?.iv || !guardado?.cifrado) throw new Error("Formato inválido");
  } catch {
    return setMensaje(mensaje, "La bóveda guardada parece estar dañada.", "error");
  }

  try {
  validarRespaldo(guardado);
  const salt = base64ABytes(guardado.salt);
  const iv = base64ABytes(guardado.iv);
  const cifrado = base64ABytes(guardado.cifrado);
  const iterations = guardado.iterations || 100000;

    let clave = await derivarClave(passIngresada, salt, iterations);
    const decoded = await descifrarVault(cifrado, iv, clave);
    validarContenidoVault(decoded);
    let vault = normalizarVault(decoded);

    // Migra bóvedas antiguas a una derivación de clave más exigente sin romper compatibilidad.
    if (iterations < CURRENT_KDF_ITERATIONS) {
      clave = await derivarClave(passIngresada, salt, CURRENT_KDF_ITERATIONS);
      iteracionesActuales = CURRENT_KDF_ITERATIONS;
      claveActual = clave;
      saltActual = salt;
      vaultActual = vault;
      await guardarCambiosEnDisco();
    } else {
      iteracionesActuales = iterations;
      claveActual = clave;
      saltActual = salt;
      vaultActual = vault;
    }

    document.getElementById("passDesbloqueo").value = "";
    document.getElementById("pantallaDesbloqueo").style.display = "none";
    document.getElementById("appLayout").classList.add("show");
    aplicarConfiguracion();
    refrescarTodo();
    reiniciarAutoLock();
  } catch (err) {
    setMensaje(mensaje, "Contraseña incorrecta o bóveda no compatible.", "error");
  }
}

async function guardarCambiosEnDisco() {
  if (!vaultActual || !claveActual || !saltActual) throw new Error("Bóveda bloqueada");
  const snapshot = JSON.parse(JSON.stringify(vaultActual));
  const key = claveActual, salt = saltActual, iterations = iteracionesActuales;
  const generation = sessionGeneration;
  const operation = saveQueue.catch(() => {}).then(async () => {
    const { iv, cifrado } = await cifrarVault(snapshot, key);
    if (generation !== sessionGeneration) throw new Error("La sesión cambió durante el guardado");
    localStorage.setItem("vault_gestor", JSON.stringify({
      version: 2, iterations, salt: bytesABase64(salt),
      iv: bytesABase64(iv), cifrado: bytesABase64(cifrado)
    }));
  });
  saveQueue = operation;
  return operation;
}

function refrescarTodo() {
  renderizarLista();
  renderizarFavoritos();
  renderizarCodigos();
  renderizarRevision();
  renderizarNotas();
  renderizarPapelera();
  renderizarDashboard();
  actualizarContadoresNav();
}

function setMensaje(el, texto, tipo = "") {
  if (!el) return;
  el.textContent = texto;
  el.className = `hint${tipo ? ` ${tipo}` : ""}`;
}

function escapeHTML(valor = "") {
  return String(valor).replace(/[&<>'"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[c]));
}

function iniciales(texto = "") {
  const limpio = String(texto).trim();
  if (!limpio) return "--";
  const partes = limpio.split(/\s+/).filter(Boolean);
  return (partes.length > 1 ? partes[0][0] + partes[1][0] : limpio.slice(0, 2)).toUpperCase();
}

function fechaRelativa(iso) {
  if (!iso) return "Sin fecha";
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "Ahora";
  const min = Math.floor(ms / 60000);
  if (min < 1) return "Ahora";
  if (min < 60) return `Hace ${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `Hace ${h} h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `Hace ${d} d`;
  return new Date(iso).toLocaleDateString("es-CL", { day: "2-digit", month: "short", year: "numeric" });
}

function renderEntradaHTML(e, { revision = false, papelera = false } = {}) {
  const cat = revision ? calcularCategoriaSemaforo(e.contraseña) : null;
  const repetida = revision ? esContraseñaRepetida(e.contraseña) : false;
  const onclick = papelera ? "" : `onclick="abrirModalEditar('${e.id}')"`;
  const actions = papelera
    ? `<div class="row-actions"><button class="mini-btn" onclick="restaurarEntrada(event,'${e.id}')" title="Restaurar">↶</button><button class="mini-btn" onclick="eliminarDefinitivo(event,'${e.id}')" title="Eliminar definitivamente">✕</button></div>`
    : revision
      ? `<div class="revision-right">${repetida ? '<span class="repeat-badge">Reutilizada</span>' : ""}<span class="risk ${cat.clase}"><span class="risk-dot" style="background:${cat.color}"></span>${cat.texto}</span></div>`
      : `<div class="row-actions"><span class="badge">${escapeHTML(e.categoria || "Otros")}</span><button class="mini-btn star ${e.favorito ? "active" : ""}" onclick="toggleFavorito(event,'${e.id}')" title="Favorito">★</button><button class="mini-btn" onclick="copiarUsuario(event,'${e.id}')" title="Copiar usuario">＠</button><button class="mini-btn" onclick="copiarContraseña(event,'${e.id}')" title="Copiar contraseña">⧉</button></div>`;

  return `<div class="entrada" ${onclick}>
    <div class="avatar">${escapeHTML(iniciales(e.sitio))}</div>
    <div class="info">
      <div class="sitio">${escapeHTML(e.sitio)}</div>
      <div class="usuario">${escapeHTML(e.usuario || "Sin usuario")}</div>
      ${papelera ? `<div class="meta">Eliminada ${escapeHTML(fechaRelativa(e.eliminadoEn))}</div>` : ""}
    </div>
    ${actions}
  </div>`;
}

function renderizarLista() {
  if (!vaultActual) return;
  const cont = document.getElementById("listaEntradas");
  const vacio = document.getElementById("listaVacia");
  const busqueda = (document.getElementById("buscador")?.value || "").trim().toLowerCase();
  const categoria = document.getElementById("filtroCategoria")?.value || "";

  const entradas = vaultActual.entradas
    .filter(e => !categoria || e.categoria === categoria)
    .filter(e => [e.sitio, e.usuario, e.categoria, e.url].some(v => String(v || "").toLowerCase().includes(busqueda)))
    .sort((a, b) => new Date(b.actualizadoEn || 0) - new Date(a.actualizadoEn || 0));

  cont.innerHTML = entradas.map(e => renderEntradaHTML(e)).join("");
  vacio.style.display = entradas.length ? "none" : "block";
}

function renderizarFavoritos() {
  if (!vaultActual) return;
  const lista = vaultActual.entradas.filter(e => e.favorito).sort((a,b) => a.sitio.localeCompare(b.sitio));
  document.getElementById("listaFavoritos").innerHTML = lista.map(e => renderEntradaHTML(e)).join("");
  document.getElementById("favoritosVacio").style.display = lista.length ? "none" : "block";
}

async function toggleFavorito(event, id) {
  event.stopPropagation();
  const entrada = vaultActual.entradas.find(e => e.id === id);
  if (!entrada) return;
  entrada.favorito = !entrada.favorito;
  entrada.actualizadoEn = new Date().toISOString();
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  renderizarLista();
  renderizarFavoritos();
  renderizarDashboard();
  toast(entrada.favorito ? "Agregada a favoritos" : "Quitada de favoritos", "★");
}

async function copiarContraseña(event, id) {
  event.stopPropagation();
  const entrada = vaultActual.entradas.find(e => e.id === id);
  if (entrada) await copiarTexto(entrada.contraseña, "Contraseña copiada");
}

async function copiarUsuario(event, id) {
  event.stopPropagation();
  const entrada = vaultActual.entradas.find(e => e.id === id);
  if (entrada) await copiarTexto(entrada.usuario, "Usuario copiado");
}

async function copiarTexto(texto, mensaje = "Copiado") {
  try {
    await navigator.clipboard.writeText(texto || "");
    toast(mensaje, "✓");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = texto || "";
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast(mensaje, "✓");
  }
}

function abrirModalNueva() {
  document.getElementById("modalTitulo").textContent = "Nueva credencial";
  document.getElementById("entradaId").value = "";
  document.getElementById("fSitio").value = "";
  document.getElementById("fCategoria").value = "Otros";
  document.getElementById("fUrl").value = "";
  document.getElementById("fUsuario").value = "";
  document.getElementById("fContraseña").value = "";
  document.getElementById("fContraseña").type = "password";
  document.getElementById("fNotas").value = "";
  document.getElementById("fFavorito").checked = false;
  document.getElementById("btnEliminarEntrada").style.display = "none";
  document.getElementById("opcionesGen").style.display = "none";
  actualizarFortaleza();
  abrirOverlay("overlayModal");
  setTimeout(() => document.getElementById("fSitio")?.focus(), 50);
}

function abrirModalEditar(id) {
  const entrada = vaultActual.entradas.find(e => e.id === id);
  if (!entrada) return;
  document.getElementById("modalTitulo").textContent = "Editar credencial";
  document.getElementById("entradaId").value = entrada.id;
  document.getElementById("fSitio").value = entrada.sitio;
  document.getElementById("fCategoria").value = entrada.categoria || "Otros";
  document.getElementById("fUrl").value = entrada.url || "";
  document.getElementById("fUsuario").value = entrada.usuario;
  document.getElementById("fContraseña").value = entrada.contraseña;
  document.getElementById("fContraseña").type = "password";
  document.getElementById("fNotas").value = entrada.notas || "";
  document.getElementById("fFavorito").checked = Boolean(entrada.favorito);
  document.getElementById("btnEliminarEntrada").style.display = "block";
  document.getElementById("opcionesGen").style.display = "none";
  actualizarFortaleza();
  abrirOverlay("overlayModal");
}

function cerrarModal() { cerrarOverlay("overlayModal"); }

async function guardarEntrada() {
  const id = document.getElementById("entradaId").value;
  const sitio = document.getElementById("fSitio").value.trim();
  const categoria = document.getElementById("fCategoria").value;
  const url = document.getElementById("fUrl").value.trim();
  const usuario = document.getElementById("fUsuario").value.trim();
  const contraseña = document.getElementById("fContraseña").value;
  const notas = document.getElementById("fNotas").value.trim();
  const favorito = document.getElementById("fFavorito").checked;

  if (!sitio || !usuario || !contraseña) {
    toast("Completa servicio, usuario y contraseña", "!");
    return;
  }

  const ahora = new Date().toISOString();
  if (id) {
    const entrada = vaultActual.entradas.find(e => e.id === id);
    if (!entrada) return;
    Object.assign(entrada, { sitio, categoria, url, usuario, contraseña, notas, favorito, actualizadoEn: ahora });
  } else {
    vaultActual.entradas.push({ id: crypto.randomUUID(), sitio, categoria, url, usuario, contraseña, notas, favorito, creadoEn: ahora, actualizadoEn: ahora });
  }

  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  cerrarModal();
  refrescarTodo();
  toast(id ? "Credencial actualizada" : "Credencial guardada", "✓");
}

async function eliminarEntradaActual() {
  const id = document.getElementById("entradaId").value;
  const entrada = vaultActual.entradas.find(e => e.id === id);
  if (!entrada) return;
  if (!confirm(`¿Mover “${entrada.sitio}” a la papelera?`)) return;
  vaultActual.entradas = vaultActual.entradas.filter(e => e.id !== id);
  vaultActual.papelera.unshift({ ...entrada, eliminadoEn: new Date().toISOString() });
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  cerrarModal();
  refrescarTodo();
  toast("Movida a la papelera", "⌫");
}

function renderizarPapelera() {
  if (!vaultActual) return;
  const lista = vaultActual.papelera || [];
  document.getElementById("listaPapelera").innerHTML = lista.map(e => renderEntradaHTML(e, { papelera: true })).join("");
  document.getElementById("papeleraVacia").style.display = lista.length ? "none" : "block";
}

async function restaurarEntrada(event, id) {
  event.stopPropagation();
  const i = vaultActual.papelera.findIndex(e => e.id === id);
  if (i < 0) return;
  const [entrada] = vaultActual.papelera.splice(i, 1);
  delete entrada.eliminadoEn;
  entrada.actualizadoEn = new Date().toISOString();
  vaultActual.entradas.push(entrada);
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  refrescarTodo();
  toast("Credencial restaurada", "↶");
}

async function eliminarDefinitivo(event, id) {
  event.stopPropagation();
  const entrada = vaultActual.papelera.find(e => e.id === id);
  if (!entrada || !confirm(`¿Eliminar definitivamente “${entrada.sitio}”? Esta acción no se puede deshacer.`)) return;
  vaultActual.papelera = vaultActual.papelera.filter(e => e.id !== id);
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  refrescarTodo();
  toast("Credencial eliminada definitivamente", "✕");
}

async function vaciarPapelera() {
  if (!vaultActual.papelera.length) return toast("La papelera ya está vacía", "✓");
  if (!confirm("¿Vaciar la papelera? Se eliminarán definitivamente todas las credenciales que contiene.")) return;
  vaultActual.papelera = [];
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  refrescarTodo();
  toast("Papelera vaciada", "⌫");
}

function toggleOpcionesGen() {
  const panel = document.getElementById("opcionesGen");
  panel.style.display = panel.style.display === "none" ? "block" : "none";
}

function randomInt(max) {
  if (max <= 0) return 0;
  const limit = Math.floor(0x100000000 / max) * max;
  const arr = new Uint32Array(1);
  do crypto.getRandomValues(arr); while (arr[0] >= limit);
  return arr[0] % max;
}

function shuffleSeguro(chars) {
  const a = [...chars];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.join("");
}

function generarContraseñaSegura(largo = 18, usarMayus = true, usarNum = true, usarSim = true) {
  const grupos = ["abcdefghijkmnopqrstuvwxyz"];
  if (usarMayus) grupos.push("ABCDEFGHJKLMNPQRSTUVWXYZ");
  if (usarNum) grupos.push("23456789");
  if (usarSim) grupos.push("!@#$%^&*()_-+=?");
  const alfabeto = grupos.join("");
  const obligatorios = grupos.map(g => g[randomInt(g.length)]);
  const restantes = [];
  while (obligatorios.length + restantes.length < Math.max(largo, grupos.length)) restantes.push(alfabeto[randomInt(alfabeto.length)]);
  return shuffleSeguro(obligatorios.join("") + restantes.join(""));
}

function generarYRellenar() {
  const largo = Number(document.getElementById("largoGen").value);
  const pass = generarContraseñaSegura(largo, document.getElementById("chkMayus").checked, document.getElementById("chkNum").checked, document.getElementById("chkSim").checked);
  const input = document.getElementById("fContraseña");
  input.value = pass;
  input.type = "text";
  actualizarFortaleza();
  toast("Contraseña generada", "✦");
}

function abrirGeneradorRapido() {
  abrirOverlay("overlayGenerador");
  regenerarQuick();
}
function cerrarGeneradorRapido() { cerrarOverlay("overlayGenerador"); }
function regenerarQuick() {
  const largo = Number(document.getElementById("quickLength")?.value || 20);
  document.getElementById("quickGenerated").textContent = generarContraseñaSegura(largo, true, true, true);
}

function calcularFortaleza(pass) {
  if (!pass) return { puntaje: 0, texto: "Sin evaluar", color: "var(--muted-2)", entropia: 0 };
  let tamañoAlfabeto = 0;
  if (/[a-z]/.test(pass)) tamañoAlfabeto += 26;
  if (/[A-Z]/.test(pass)) tamañoAlfabeto += 26;
  if (/[0-9]/.test(pass)) tamañoAlfabeto += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) tamañoAlfabeto += 32;
  let entropia = pass.length * Math.log2(tamañoAlfabeto || 1);

  // Penalizaciones simples para patrones muy obvios.
  if (/(.)\1{2,}/.test(pass)) entropia *= .78;
  if (/1234|abcd|qwerty|password|contraseña/i.test(pass)) entropia *= .45;
  const puntaje = Math.round(Math.max(0, Math.min(100, (entropia / 90) * 100)));
  let texto = "Débil", color = "var(--red)";
  if (entropia >= 75) { texto = "Muy fuerte"; color = "var(--green)"; }
  else if (entropia >= 55) { texto = "Fuerte"; color = "#8dda65"; }
  else if (entropia >= 38) { texto = "Media"; color = "var(--yellow)"; }
  return { puntaje, texto, color, entropia: Math.round(entropia) };
}

function actualizarFortaleza() {
  const r = calcularFortaleza(document.getElementById("fContraseña")?.value || "");
  const barra = document.getElementById("barraFortaleza");
  const label = document.getElementById("labelFortaleza");
  if (!barra || !label) return;
  barra.style.width = `${r.puntaje}%`;
  barra.style.background = r.color;
  label.textContent = r.texto;
  label.style.color = r.color;
  document.getElementById("entropiaLabel").textContent = r.entropia ? `≈ ${r.entropia} bits` : "";
}

function calcularCategoriaSemaforo(pass) {
  const r = calcularFortaleza(pass);
  if (r.texto === "Débil") return { texto: "Débil", color: "var(--red)", clase: "bad", nivel: "debil" };
  if (r.texto === "Media") return { texto: "Media", color: "var(--yellow)", clase: "medium", nivel: "media" };
  return { texto: r.texto, color: "var(--green)", clase: "good", nivel: "segura" };
}

function conteoContraseñas() {
  const map = new Map();
  (vaultActual?.entradas || []).forEach(e => map.set(e.contraseña, (map.get(e.contraseña) || 0) + 1));
  return map;
}
function esContraseñaRepetida(pass) { return (conteoContraseñas().get(pass) || 0) > 1; }

function obtenerMetricasSeguridad() {
  const entradas = vaultActual?.entradas || [];
  const conteo = conteoContraseñas();
  let debiles = 0, seguras = 0, repetidas = 0;
  entradas.forEach(e => {
    const cat = calcularCategoriaSemaforo(e.contraseña);
    if (cat.nivel === "segura") seguras++; else debiles++;
    if ((conteo.get(e.contraseña) || 0) > 1) repetidas++;
  });
  const total = entradas.length;
  const penalty = total ? ((debiles / total) * 45 + (repetidas / total) * 30) : 0;
  const score = total ? Math.max(0, Math.round(100 - penalty)) : 100;
  return { total, debiles, seguras, repetidas, score };
}

function renderizarRevision() {
  if (!vaultActual) return;
  const entradas = [...vaultActual.entradas].sort((a, b) => {
    const aR = calcularCategoriaSemaforo(a.contraseña).nivel === "segura" ? 1 : 0;
    const bR = calcularCategoriaSemaforo(b.contraseña).nivel === "segura" ? 1 : 0;
    return aR - bR;
  });
  const m = obtenerMetricasSeguridad();
  document.getElementById("statDebiles").textContent = m.debiles;
  document.getElementById("statRepetidas").textContent = m.repetidas;
  document.getElementById("statSeguras").textContent = m.seguras;
  document.getElementById("listaRevision").innerHTML = entradas.map(e => renderEntradaHTML(e, { revision: true })).join("");
  document.getElementById("revisionVacia").style.display = entradas.length ? "none" : "block";
}

async function base32Decode(base32) {
  const alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const limpio = String(base32).replace(/=+$/, "").toUpperCase().replace(/[\s-]/g, "");
  if (!limpio || [...limpio].some(char => !alfabeto.includes(char))) throw new Error("Base32 inválido");
  let bits = "";
  for (const char of limpio) bits += alfabeto.indexOf(char).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  if (!bytes.length) throw new Error("Secreto vacío");
  return new Uint8Array(bytes);
}

async function generarTOTP(secretoBase32) {
  const claveBytes = await base32Decode(secretoBase32);
  const contador = Math.floor(Date.now() / 1000 / 30);
  const buffer = new ArrayBuffer(8);
  const vista = new DataView(buffer);
  const high = Math.floor(contador / 0x100000000);
  const low = contador >>> 0;
  vista.setUint32(0, high);
  vista.setUint32(4, low);
  const claveHMAC = await crypto.subtle.importKey("raw", claveBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const firma = new Uint8Array(await crypto.subtle.sign("HMAC", claveHMAC, buffer));
  const offset = firma[firma.length - 1] & 0xf;
  const codigoBin = ((firma[offset] & 0x7f) << 24) | ((firma[offset + 1] & 0xff) << 16) | ((firma[offset + 2] & 0xff) << 8) | (firma[offset + 3] & 0xff);
  return (codigoBin % 1000000).toString().padStart(6, "0");
}

function abrirModalCodigo() {
  document.getElementById("cNombre").value = "";
  document.getElementById("cSecreto").value = "";
  abrirOverlay("overlayCodigo");
}
function cerrarModalCodigo() { cerrarOverlay("overlayCodigo"); }

async function guardarCodigo() {
  const nombre = document.getElementById("cNombre").value.trim();
  const secreto = document.getElementById("cSecreto").value.trim().replace(/[\s-]/g, "");
  if (!nombre || !secreto) return toast("Completa servicio y clave secreta", "!");
  try { await generarTOTP(secreto); } catch { return toast("La clave Base32 no parece válida", "!"); }
  vaultActual.codigos.push({ id: crypto.randomUUID(), nombre, secreto, creadoEn: new Date().toISOString() });
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  cerrarModalCodigo();
  renderizarCodigos();
  renderizarDashboard();
  toast("Código 2FA agregado", "✓");
}

async function eliminarCodigo(id) {
  if (!confirm("¿Eliminar este código 2FA?")) return;
  vaultActual.codigos = vaultActual.codigos.filter(c => c.id !== id);
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  renderizarCodigos();
  renderizarDashboard();
  toast("Código eliminado", "✕");
}

async function copiarCodigo(event, secreto) {
  event.stopPropagation();
  try { await copiarTexto(await generarTOTP(secreto), "Código 2FA copiado"); } catch { toast("No se pudo generar el código", "!"); }
}

async function renderizarCodigos() {
  const cont = document.getElementById("listaCodigos");
  const vacio = document.getElementById("codigosVacio");
  if (!vaultActual?.codigos?.length) {
    cont.innerHTML = "";
    vacio.style.display = "block";
    return;
  }
  vacio.style.display = "none";
  const segundos = 30 - (Math.floor(Date.now() / 1000) % 30);
  const t = segundos / 30;
  const color = t > .5 ? "var(--green)" : t > .2 ? "var(--yellow)" : "var(--red)";
  const circ = 2 * Math.PI * 12;
  const offset = circ * (1 - t);
  const filas = await Promise.all(vaultActual.codigos.map(async c => {
    let codigo = "------";
    try { codigo = await generarTOTP(c.secreto); } catch {}
    return `<div class="codigo-item">
      <div class="avatar">${escapeHTML(iniciales(c.nombre))}</div>
      <div class="info"><div class="nombre-servicio">${escapeHTML(c.nombre)}</div><div class="digitos mono" style="color:${color}">${codigo.slice(0,3)} ${codigo.slice(3)}</div></div>
      <div class="lado-derecho">
        <div class="anillo-wrap"><svg viewBox="0 0 30 30"><circle class="anillo-fondo" cx="15" cy="15" r="12"/><circle class="anillo-progreso" cx="15" cy="15" r="12" stroke="${color}" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/></svg><div class="segundos-txt" style="color:${color}">${segundos}</div></div>
        <button class="mini-btn" onclick="copiarCodigo(event,'${c.secreto}')" title="Copiar código">⧉</button>
        <button class="mini-btn" onclick="eliminarCodigo('${c.id}')" title="Eliminar">✕</button>
      </div>
    </div>`;
  }));
  if (!vaultActual) return;
  cont.innerHTML = filas.join("");
}

setInterval(() => {
  if (vaultActual && document.getElementById("sub-codigos")?.classList.contains("active")) renderizarCodigos();
}, 1000);

function abrirModalNota(id = "") {
  const nota = id ? vaultActual.notas.find(n => n.id === id) : null;
  document.getElementById("notaId").value = nota?.id || "";
  document.getElementById("notaTitulo").value = nota?.titulo || "";
  document.getElementById("notaContenido").value = nota?.contenido || "";
  document.getElementById("notaModalTitulo").textContent = nota ? "Editar nota segura" : "Nueva nota segura";
  document.getElementById("btnEliminarNota").style.display = nota ? "block" : "none";
  abrirOverlay("overlayNota");
  setTimeout(() => document.getElementById("notaTitulo")?.focus(), 50);
}
function cerrarModalNota() { cerrarOverlay("overlayNota"); }

async function guardarNota() {
  const id = document.getElementById("notaId").value;
  const titulo = document.getElementById("notaTitulo").value.trim();
  const contenido = document.getElementById("notaContenido").value.trim();
  if (!titulo || !contenido) return toast("Completa título y contenido", "!");
  const ahora = new Date().toISOString();
  if (id) {
    const nota = vaultActual.notas.find(n => n.id === id);
    if (!nota) return;
    Object.assign(nota, { titulo, contenido, actualizadoEn: ahora });
  } else {
    vaultActual.notas.unshift({ id: crypto.randomUUID(), titulo, contenido, creadoEn: ahora, actualizadoEn: ahora });
  }
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  cerrarModalNota();
  renderizarNotas();
  toast(id ? "Nota actualizada" : "Nota guardada", "✓");
}

async function eliminarNotaActual() {
  const id = document.getElementById("notaId").value;
  if (!id || !confirm("¿Eliminar definitivamente esta nota segura?")) return;
  vaultActual.notas = vaultActual.notas.filter(n => n.id !== id);
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  cerrarModalNota();
  renderizarNotas();
  toast("Nota eliminada", "✕");
}

function renderizarNotas() {
  if (!vaultActual) return;
  const notas = [...vaultActual.notas].sort((a,b) => new Date(b.actualizadoEn || b.creadoEn || 0) - new Date(a.actualizadoEn || a.creadoEn || 0));
  document.getElementById("listaNotas").innerHTML = notas.map(n => `<article class="note-card" onclick="abrirModalNota('${n.id}')"><div class="eyebrow">Nota segura</div><h3>${escapeHTML(n.titulo)}</h3><p>${escapeHTML(n.contenido)}</p><span class="note-date">${escapeHTML(fechaRelativa(n.actualizadoEn || n.creadoEn))}</span></article>`).join("");
  document.getElementById("notasVacio").style.display = notas.length ? "none" : "block";
}

function renderizarDashboard() {
  if (!vaultActual) return;
  const m = obtenerMetricasSeguridad();
  const favs = vaultActual.entradas.filter(e => e.favorito).length;
  document.getElementById("dashTotal").textContent = m.total;
  document.getElementById("dashScore").textContent = `${m.score}%`;
  document.getElementById("dash2FA").textContent = vaultActual.codigos.length;
  document.getElementById("dashFavs").textContent = favs;
  document.getElementById("dashScoreText").textContent = m.debiles || m.repetidas ? "Hay elementos por revisar" : "Sin riesgos evidentes";
  document.getElementById("scoreRingValue").textContent = m.score;
  const ring = document.getElementById("scoreRing");
  ring.style.setProperty("--score", m.score);
  const ringColor = m.score >= 80 ? "var(--green)" : m.score >= 60 ? "var(--yellow)" : "var(--red)";
  ring.style.background = `conic-gradient(${ringColor} calc(${m.score} * 1%), rgba(255,255,255,.06) 0)`;
  document.getElementById("scoreTitle").textContent = m.score >= 90 ? "Excelente" : m.score >= 75 ? "Buen estado" : m.score >= 55 ? "Necesita atención" : "Riesgo elevado";
  document.getElementById("scoreDescription").textContent = m.total === 0 ? "Agrega credenciales para comenzar la revisión automática." : m.debiles || m.repetidas ? "Conviene actualizar las contraseñas marcadas como débiles o reutilizadas." : "Tus credenciales actuales no muestran problemas evidentes.";
  document.getElementById("pillWeak").textContent = `${m.debiles} débiles`;
  document.getElementById("pillRepeated").textContent = `${m.repetidas} reutilizadas`;

  const recientes = [...vaultActual.entradas].sort((a,b) => new Date(b.actualizadoEn || 0) - new Date(a.actualizadoEn || 0)).slice(0,5);
  document.getElementById("listaRecientes").innerHTML = recientes.length ? recientes.map(e => `<div class="compact-item" onclick="abrirModalEditar('${e.id}')"><div class="compact-avatar">${escapeHTML(iniciales(e.sitio))}</div><div class="compact-copy"><div class="compact-title">${escapeHTML(e.sitio)}</div><div class="compact-sub">${escapeHTML(e.usuario)}</div></div><span class="compact-time">${escapeHTML(fechaRelativa(e.actualizadoEn))}</span></div>`).join("") : `<div class="empty-state" style="margin:0 0 12px"><div>▣</div><h3>Tu bóveda está vacía</h3><p>Agrega tu primera credencial para verla aquí.</p></div>`;
}

function actualizarContadoresNav() {
  document.getElementById("navTotal").textContent = vaultActual?.entradas?.length || 0;
  document.getElementById("navTrash").textContent = vaultActual?.papelera?.length || 0;
}

function irASub(el, seccion) {
  document.querySelectorAll(".sub-panel").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".side-item").forEach(s => s.classList.remove("active"));
  document.getElementById(`sub-${seccion}`)?.classList.add("active");
  el?.classList.add("active");
  document.getElementById("sidebar")?.classList.remove("mobile-open");
  if (seccion === "codigos") renderizarCodigos();
  if (seccion === "revision") renderizarRevision();
  if (seccion === "inicio") renderizarDashboard();
}

function navegarA(seccion) {
  const el = document.querySelector(`.side-item[data-section="${seccion}"]`);
  irASub(el, seccion);
}

function toggleSidebar() { document.getElementById("sidebar")?.classList.toggle("mobile-open"); }

function aplicarConfiguracion() {
  if (!vaultActual) return;
  const settings = { ...DEFAULT_SETTINGS, ...(vaultActual.settings || {}) };
  vaultActual.settings = settings;
  const select = document.getElementById("autoLockSelect");
  const privacy = document.getElementById("privacyMode");
  if (select) select.value = String(settings.autoLockMinutes);
  if (privacy) privacy.checked = Boolean(settings.privacyMode);
  document.body.classList.toggle("privacy-mode", Boolean(settings.privacyMode));
}

async function guardarConfiguracion() {
  if (!vaultActual) return;
  vaultActual.settings.autoLockMinutes = Number(document.getElementById("autoLockSelect").value);
  vaultActual.settings.privacyMode = document.getElementById("privacyMode").checked;
  document.body.classList.toggle("privacy-mode", vaultActual.settings.privacyMode);
  try {
    await guardarCambiosEnDisco();
  } catch {
    toast("No se pudo guardar. Los cambios siguen en esta sesión; intenta guardar nuevamente antes de bloquear o cerrar.", "!");
    return;
  }
  reiniciarAutoLock();
  toast("Configuración guardada", "✓");
}

function reiniciarAutoLock() {
  clearTimeout(autoLockTimer);
  if (!vaultActual) return;
  const min = Number(vaultActual.settings?.autoLockMinutes ?? 5);
  if (min > 0) autoLockTimer = setTimeout(() => bloquearApp(true), min * 60 * 1000);
}

function bloquearApp(automatico = false) {
  clearTimeout(autoLockTimer);
  sessionGeneration++;
  backupPendiente = null;
  document.querySelectorAll(".overlay.show").forEach(el => el.classList.remove("show"));
  document.querySelectorAll("input:not([type=checkbox]):not([type=range]), textarea").forEach(el => {
    el.value = "";
    if (el.type === "password" || ["fContraseña", "masterActual", "masterNueva", "masterNueva2"].includes(el.id)) el.type = "password";
  });
  ["listaEntradas", "listaFavoritos", "listaCodigos", "listaRevision", "listaNotas", "listaPapelera", "listaRecientes", "quickGenerated"].forEach(id => {
    document.getElementById(id).replaceChildren();
  });
  claveActual = null;
  saltActual = null;
  vaultActual = null;
  document.getElementById("appLayout").classList.remove("show");
  document.getElementById("sidebar")?.classList.remove("mobile-open");
  document.getElementById("pantallaDesbloqueo").style.display = "flex";
  document.getElementById("passDesbloqueo").value = "";
  setMensaje(document.getElementById("mensajeDesbloqueo"), automatico ? "La bóveda se bloqueó por inactividad." : "Bóveda bloqueada.", automatico ? "" : "ok");
  setTimeout(() => document.getElementById("passDesbloqueo")?.focus(), 50);
}

function exportarBackup() {
  const raw = localStorage.getItem("vault_gestor");
  if (!raw) return toast("No hay bóveda para exportar", "!");
  const payload = {
    type: "vaultguard-encrypted-backup",
    exportedAt: new Date().toISOString(),
    vault: JSON.parse(raw)
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vaultguard-backup-${new Date().toISOString().slice(0,10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Respaldo cifrado exportado", "⇩");
}

let backupPendiente = null;

function validarRespaldo(vault) {
  if (!vault || ![1, 2].includes(vault.version ?? 1)) throw new Error("Versión no compatible");
  const iterations = vault.iterations ?? 100000;
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) throw new Error("Parámetros inválidos");
  if (typeof vault.salt !== "string" || typeof vault.iv !== "string" || typeof vault.cifrado !== "string") throw new Error("Formato inválido");
  if (base64ABytes(vault.salt).length !== 16 || base64ABytes(vault.iv).length !== 12 || base64ABytes(vault.cifrado).length < 16) throw new Error("Datos inválidos");
}

async function importarBackup(event) {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file) return;
  try {
    if (file.size > 10 * 1024 * 1024) throw new Error("Archivo demasiado grande");
    const data = JSON.parse(await file.text());
    const vault = data.type === "vaultguard-encrypted-backup" ? data.vault : data;
    validarRespaldo(vault);
    backupPendiente = vault;
    document.getElementById("backupPassword").value = "";
    setMensaje(document.getElementById("backupMensaje"), "", "");
    abrirOverlay("overlayBackup");
  } catch {
    toast("El archivo no es un respaldo válido o compatible", "!");
  }
}

async function confirmarImportacion() {
  const pending = backupPendiente;
  if (!pending) return;
  const mensaje = document.getElementById("backupMensaje");
  try {
    const key = await derivarClave(document.getElementById("backupPassword").value, base64ABytes(pending.salt), pending.iterations ?? 100000);
    const decoded = await descifrarVault(base64ABytes(pending.cifrado), base64ABytes(pending.iv), key);
    validarContenidoVault(decoded);
    if (backupPendiente !== pending) return;
    if (!confirm(`Respaldo verificado: ${decoded.entradas.length} credenciales. Reemplazará la bóveda actual. ¿Continuar?`)) return;
    await saveQueue.catch(() => {});
    localStorage.setItem("vault_gestor", JSON.stringify(pending));
    bloquearApp();
    toast("Respaldo verificado e importado", "✓");
  } catch {
    setMensaje(mensaje, "No se pudo importar: revisa la contraseña, el archivo y el almacenamiento disponible. Tu bóveda actual se conserva.", "error");
  }
}

function abrirModalMaster() {
  ["masterActual", "masterNueva", "masterNueva2"].forEach(id => document.getElementById(id).value = "");
  setMensaje(document.getElementById("masterMensaje"), "", "");
  abrirOverlay("overlayMaster");
}
function cerrarModalMaster() { cerrarOverlay("overlayMaster"); }

async function cambiarMaster() {
  const actual = document.getElementById("masterActual").value;
  const nueva = document.getElementById("masterNueva").value;
  const nueva2 = document.getElementById("masterNueva2").value;
  const mensaje = document.getElementById("masterMensaje");
  if (nueva.length < 10) return setMensaje(mensaje, "La nueva contraseña debe tener al menos 10 caracteres.", "error");
  if (nueva !== nueva2) return setMensaje(mensaje, "Las nuevas contraseñas no coinciden.", "error");
  try {
    const guardado = JSON.parse(localStorage.getItem("vault_gestor"));
    const saltViejo = base64ABytes(guardado.salt);
    const claveVieja = await derivarClave(actual, saltViejo, guardado.iterations || 100000);
    await descifrarVault(base64ABytes(guardado.cifrado), base64ABytes(guardado.iv), claveVieja);

    const previous = { salt: saltActual, key: claveActual, iterations: iteracionesActuales };
    const generation = sessionGeneration;
    const nuevoSalt = crypto.getRandomValues(new Uint8Array(16));
    const nuevaClave = await derivarClave(nueva, nuevoSalt, CURRENT_KDF_ITERATIONS);
    if (!vaultActual || generation !== sessionGeneration) return;
    saltActual = nuevoSalt;
    claveActual = nuevaClave;
    iteracionesActuales = CURRENT_KDF_ITERATIONS;
    try {
      await guardarCambiosEnDisco();
    } catch {
      if (generation === sessionGeneration) {
        saltActual = previous.salt;
        claveActual = previous.key;
        iteracionesActuales = previous.iterations;
        setMensaje(mensaje, "No se pudo guardar. Tu contraseña maestra anterior sigue vigente.", "error");
      }
      return;
    }
    cerrarModalMaster();
    toast("Contraseña maestra actualizada", "◆");
  } catch {
    setMensaje(mensaje, "La contraseña maestra actual no es correcta.", "error");
  }
}

function togglePasswordField(id, button) {
  const input = document.getElementById(id);
  if (!input) return;
  input.type = input.type === "password" ? "text" : "password";
  if (button) button.style.color = input.type === "text" ? "var(--steel)" : "";
}

function abrirOverlay(id) { document.getElementById(id)?.classList.add("show"); }
function cerrarOverlay(id) {
  document.getElementById(id)?.classList.remove("show");
  if (id === "overlayBackup") {
    backupPendiente = null;
    document.getElementById("backupPassword").value = "";
  }
}
function cerrarOverlayPorId(id) {
  const map = { overlayModal: cerrarModal, overlayCodigo: cerrarModalCodigo, overlayNota: cerrarModalNota, overlayMaster: cerrarModalMaster, overlayGenerador: cerrarGeneradorRapido, overlayBackup: () => cerrarOverlay("overlayBackup") };
  map[id]?.();
}

function manejarAtajos(e) {
  if (!vaultActual) return;
  if (e.key === "Escape") {
    document.querySelectorAll(".overlay.show").forEach(o => cerrarOverlayPorId(o.id));
    document.getElementById("sidebar")?.classList.remove("mobile-open");
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    navegarA("todas");
    document.getElementById("buscador")?.focus();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
    e.preventDefault();
    abrirModalNueva();
  }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") {
    e.preventDefault();
    bloquearApp();
  }
}

function toast(texto, icono = "✓") {
  const el = document.getElementById("toast");
  if (!el) return;
  document.getElementById("toastText").textContent = texto;
  document.getElementById("toastIcon").textContent = icono;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}
