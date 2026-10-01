const CURRENT_KDF_ITERATIONS = 310000;

async function derivarClave(contraseña, salt, iterations = CURRENT_KDF_ITERATIONS) {
  const encoder = new TextEncoder();
  const claveBase = await crypto.subtle.importKey(
    "raw", encoder.encode(contraseña), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    claveBase,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function cifrarVault(vaultObj, clave) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const datos = new TextEncoder().encode(JSON.stringify(vaultObj));
  const cifrado = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, clave, datos);
  return { iv, cifrado: new Uint8Array(cifrado) };
}

async function descifrarVault(cifradoBytes, ivBytes, clave) {
  const datos = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, clave, cifradoBytes);
  return JSON.parse(new TextDecoder().decode(datos));
}

function bytesABase64(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function base64ABytes(base64) {
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
