export const BUNDLE_MAGIC = "local-cookie-bridge";
export const PAYLOAD_MAGIC = "local-cookie-bridge-payload";
export const FORMAT_VERSION = 1;
export const KDF_ITERATIONS = 600_000;
export const MAX_BUNDLE_BYTES = 50 * 1024 * 1024;
export const MAX_COOKIE_COUNT = 100_000;
export const MAX_PERSISTENT_LIFETIME_SECONDS = 400 * 24 * 60 * 60;

const SAME_SITE_VALUES = new Set([
  "no_restriction",
  "lax",
  "strict",
  "unspecified",
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const aad = encoder.encode(`${BUNDLE_MAGIC}:${FORMAT_VERSION}`);

function requireCrypto(cryptoApi) {
  if (!cryptoApi?.subtle || !cryptoApi?.getRandomValues) {
    throw new Error("Web Crypto is unavailable in this browser.");
  }
  return cryptoApi;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} is missing from the bundle.`);
  }
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    throw new Error(`${label} is not valid base64.`);
  }
}

async function deriveKey(passphrase, salt, cryptoApi, usage) {
  const material = await cryptoApi.subtle.importKey(
    "raw",
    encoder.encode(passphrase.normalize("NFC")),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return cryptoApi.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: KDF_ITERATIONS,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

function assertPassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 12) {
    throw new Error("Use a passphrase of at least 12 characters.");
  }
}

export function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("The decrypted payload is not an object.");
  }
  if (payload.magic !== PAYLOAD_MAGIC || payload.version !== FORMAT_VERSION) {
    throw new Error("The decrypted payload uses an unsupported format.");
  }
  if (!Array.isArray(payload.cookies)) {
    throw new Error("The decrypted payload has no cookie list.");
  }
  if (payload.cookies.length > MAX_COOKIE_COUNT) {
    throw new Error(`The bundle exceeds the ${MAX_COOKIE_COUNT.toLocaleString()} cookie safety limit.`);
  }
  if (typeof payload.exportedAt !== "string" || !Number.isFinite(Date.parse(payload.exportedAt))) {
    throw new Error("The bundle has an invalid export timestamp.");
  }
  return payload;
}

export async function encryptBundle(payload, passphrase, cryptoApi = globalThis.crypto) {
  validatePayload(payload);
  assertPassphrase(passphrase);
  const activeCrypto = requireCrypto(cryptoApi);
  const salt = activeCrypto.getRandomValues(new Uint8Array(16));
  const iv = activeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, activeCrypto, "encrypt");
  const plaintext = encoder.encode(JSON.stringify(payload));
  const ciphertext = await activeCrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    plaintext,
  );
  return JSON.stringify(
    {
      magic: BUNDLE_MAGIC,
      version: FORMAT_VERSION,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: KDF_ITERATIONS,
        salt: bytesToBase64(salt),
      },
      cipher: {
        name: "AES-GCM",
        iv: bytesToBase64(iv),
      },
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    },
    null,
    2,
  );
}

export async function decryptBundle(serialized, passphrase, cryptoApi = globalThis.crypto) {
  assertPassphrase(passphrase);
  if (typeof serialized !== "string" || serialized.length > MAX_BUNDLE_BYTES) {
    throw new Error("The selected bundle is empty or too large.");
  }

  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw new Error("The selected file is not a valid Cookie Bridge bundle.");
  }

  if (
    envelope?.magic !== BUNDLE_MAGIC ||
    envelope?.version !== FORMAT_VERSION ||
    envelope?.kdf?.name !== "PBKDF2" ||
    envelope?.kdf?.hash !== "SHA-256" ||
    envelope?.kdf?.iterations !== KDF_ITERATIONS ||
    envelope?.cipher?.name !== "AES-GCM"
  ) {
    throw new Error("The selected bundle uses an unsupported or unsafe format.");
  }

  const activeCrypto = requireCrypto(cryptoApi);
  const salt = base64ToBytes(envelope.kdf.salt, "KDF salt");
  const iv = base64ToBytes(envelope.cipher.iv, "cipher IV");
  const ciphertext = base64ToBytes(envelope.ciphertext, "ciphertext");
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
    throw new Error("The selected bundle has invalid cryptographic parameters.");
  }

  const key = await deriveKey(passphrase, salt, activeCrypto, "decrypt");
  let plaintext;
  try {
    plaintext = await activeCrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      ciphertext,
    );
  } catch {
    throw new Error("The bundle could not be decrypted. Check the passphrase and file integrity.");
  }

  try {
    return validatePayload(JSON.parse(decoder.decode(plaintext)));
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof TypeError) {
      throw new Error("The decrypted bundle payload is invalid.");
    }
    throw error;
  }
}

function stripLeadingDot(domain) {
  return domain.startsWith(".") ? domain.slice(1) : domain;
}

function isValidDomain(domain) {
  if (typeof domain !== "string" || domain.length === 0 || domain.length > 253) {
    return false;
  }
  const clean = stripLeadingDot(domain).toLowerCase();
  if (!clean || /[\s/?#]/u.test(clean)) {
    return false;
  }
  try {
    return new URL(`https://${clean}/`).hostname.toLowerCase() === clean;
  } catch {
    return false;
  }
}

export function normalizeDomainToken(token) {
  if (typeof token !== "string") {
    return null;
  }
  let value = token.trim().toLowerCase();
  if (!value) {
    return null;
  }
  try {
    if (/^[a-z][a-z\d+.-]*:\/\//iu.test(value)) {
      value = new URL(value).hostname;
    } else {
      value = value.replace(/^\*\./u, "").replace(/^\./u, "");
      value = value.split(/[/?#]/u, 1)[0];
      if (value.includes(":")) {
        value = new URL(`https://${value}/`).hostname;
      }
    }
  } catch {
    return null;
  }
  value = stripLeadingDot(value);
  return isValidDomain(value) ? value : null;
}

export function parseDomainList(input) {
  const tokens = String(input ?? "")
    .split(/[\s,;]+/u)
    .map((token) => token.trim())
    .filter(Boolean);
  const domains = new Set();
  const invalid = [];
  for (const token of tokens) {
    const domain = normalizeDomainToken(token);
    if (domain) {
      domains.add(domain);
    } else {
      invalid.push(token);
    }
  }
  return { domains: [...domains].sort(), invalid };
}

export function cookieMatchesDomains(cookie, selectedDomains) {
  const cookieDomain = stripLeadingDot(String(cookie.domain ?? "")).toLowerCase();
  return selectedDomains.some(
    (selected) =>
      cookieDomain === selected ||
      cookieDomain.endsWith(`.${selected}`) ||
      (!cookie.hostOnly && selected.endsWith(`.${cookieDomain}`)),
  );
}

function copyPartitionKey(partitionKey) {
  if (!partitionKey?.topLevelSite) {
    return undefined;
  }
  const copied = { topLevelSite: partitionKey.topLevelSite };
  if (typeof partitionKey.hasCrossSiteAncestor === "boolean") {
    copied.hasCrossSiteAncestor = partitionKey.hasCrossSiteAncestor;
  }
  return copied;
}

export function sanitizeCookie(cookie) {
  const sanitized = {
    name: String(cookie.name ?? ""),
    value: String(cookie.value ?? ""),
    domain: String(cookie.domain ?? ""),
    hostOnly: Boolean(cookie.hostOnly),
    path: String(cookie.path ?? "/"),
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: SAME_SITE_VALUES.has(cookie.sameSite) ? cookie.sameSite : "unspecified",
    session: Boolean(cookie.session),
  };
  if (!sanitized.session && Number.isFinite(cookie.expirationDate)) {
    sanitized.expirationDate = cookie.expirationDate;
  }
  const partitionKey = copyPartitionKey(cookie.partitionKey);
  if (partitionKey) {
    sanitized.partitionKey = partitionKey;
  }
  if (cookie.sourceScheme === "http" || cookie.sourceScheme === "https") {
    sanitized.sourceScheme = cookie.sourceScheme;
  }
  if (Number.isInteger(cookie.sourcePort) && cookie.sourcePort >= 1 && cookie.sourcePort <= 65535) {
    sanitized.sourcePort = cookie.sourcePort;
  }
  if (["exact", "derived", "ambiguous", "unknown"].includes(cookie.originConfidence)) {
    sanitized.originConfidence = cookie.originConfidence;
  }
  if (cookie.ambiguousDuplicate === true) {
    sanitized.ambiguousDuplicate = true;
  }
  return sanitized;
}

function prefixErrors(cookie) {
  const name = cookie.name.toLowerCase();
  const errors = [];
  const secure = cookie.secure === true;
  const httpOnly = cookie.httpOnly === true;
  const hostRoot = cookie.hostOnly === true && cookie.path === "/";

  if (name.startsWith("__host-http-") && (!secure || !httpOnly || !hostRoot)) {
    errors.push("__Host-Http- cookies require Secure, HttpOnly, a host-only domain, and Path=/.");
  } else if (name.startsWith("__host-") && (!secure || !hostRoot)) {
    errors.push("__Host- cookies require Secure, a host-only domain, and Path=/.");
  } else if (name.startsWith("__http-") && (!secure || !httpOnly)) {
    errors.push("__Http- cookies require Secure and HttpOnly.");
  } else if (name.startsWith("__secure-") && !secure) {
    errors.push("__Secure- cookies require Secure.");
  }
  return errors;
}

export function cookieValidationErrors(cookie, nowSeconds = Date.now() / 1000) {
  const errors = [];
  if (!cookie || typeof cookie !== "object" || Array.isArray(cookie)) {
    return ["Cookie record is not an object."];
  }
  if (typeof cookie.name !== "string" || typeof cookie.value !== "string") {
    errors.push("Cookie name and value must be strings.");
  }
  if (!isValidDomain(cookie.domain)) {
    errors.push("Cookie domain is invalid.");
  }
  if (typeof cookie.path !== "string" || !cookie.path.startsWith("/")) {
    errors.push("Cookie path must begin with '/'.");
  }
  for (const field of ["hostOnly", "secure", "httpOnly", "session"]) {
    if (typeof cookie[field] !== "boolean") {
      errors.push(`Cookie ${field} must be boolean.`);
    }
  }
  if (!SAME_SITE_VALUES.has(cookie.sameSite)) {
    errors.push("Cookie SameSite value is unsupported.");
  }
  if (cookie.sameSite === "no_restriction" && cookie.secure !== true) {
    errors.push("SameSite=None cookies require Secure.");
  }
  if (cookie.session === false) {
    if (!Number.isFinite(cookie.expirationDate)) {
      errors.push("Persistent cookie has no valid expiration.");
    } else if (cookie.expirationDate <= nowSeconds) {
      errors.push("Cookie is expired.");
    }
  }
  if (cookie.partitionKey !== undefined) {
    if (
      !cookie.partitionKey ||
      typeof cookie.partitionKey !== "object" ||
      typeof cookie.partitionKey.topLevelSite !== "string"
    ) {
      errors.push("Partitioned cookie has an invalid partition key.");
    } else {
      try {
        const site = new URL(cookie.partitionKey.topLevelSite);
        if (!site.hostname || !["http:", "https:"].includes(site.protocol)) {
          errors.push("Partition top-level site is invalid.");
        }
      } catch {
        errors.push("Partition top-level site is invalid.");
      }
    }
    if (
      cookie.partitionKey?.hasCrossSiteAncestor !== undefined &&
      typeof cookie.partitionKey.hasCrossSiteAncestor !== "boolean"
    ) {
      errors.push("Partition ancestor flag must be boolean.");
    }
    if (cookie.secure !== true) {
      errors.push("Partitioned cookies require Secure.");
    }
  }
  if (cookie.ambiguousDuplicate === true) {
    errors.push("Cookie is origin-bound but indistinguishable through the extension API.");
  }
  if (typeof cookie.name === "string") {
    errors.push(...prefixErrors(cookie));
  }
  return [...new Set(errors)];
}

function partitionIdentity(partitionKey) {
  if (!partitionKey?.topLevelSite) {
    return "unpartitioned";
  }
  const ancestor =
    typeof partitionKey.hasCrossSiteAncestor === "boolean"
      ? String(partitionKey.hasCrossSiteAncestor)
      : "unset";
  return `${partitionKey.topLevelSite}|${ancestor}`;
}

export function cookieIdentity(cookie) {
  return JSON.stringify([
    stripLeadingDot(String(cookie.domain ?? "")).toLowerCase(),
    Boolean(cookie.hostOnly),
    String(cookie.path ?? ""),
    String(cookie.name ?? ""),
    partitionIdentity(cookie.partitionKey),
  ]);
}

export function markAmbiguousDuplicates(cookies) {
  const counts = new Map();
  for (const cookie of cookies) {
    const key = cookieIdentity(cookie);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return cookies.map((cookie) => ({
    ...cookie,
    ...(counts.get(cookieIdentity(cookie)) > 1 ? { ambiguousDuplicate: true } : {}),
  }));
}

export function cookieToSetDetails(cookie) {
  const errors = cookieValidationErrors(cookie);
  if (errors.length > 0) {
    throw new Error(errors[0]);
  }

  const host = stripLeadingDot(cookie.domain);
  const scheme = cookie.sourceScheme === "http" || cookie.sourceScheme === "https"
    ? cookie.sourceScheme
    : cookie.secure
      ? "https"
      : "https";
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = Number.isInteger(cookie.sourcePort) ? cookie.sourcePort : defaultPort;
  const includePort = port !== defaultPort;
  const url = new URL(`${scheme}://${host}${includePort ? `:${port}` : ""}/`);
  url.pathname = cookie.path;

  const details = {
    url: url.href,
    name: cookie.name,
    value: cookie.value,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
  };
  if (!cookie.hostOnly) {
    details.domain = cookie.domain;
  }
  if (!cookie.session) {
    details.expirationDate = cookie.expirationDate;
  }
  const partitionKey = copyPartitionKey(cookie.partitionKey);
  if (partitionKey) {
    details.partitionKey = partitionKey;
  }
  return details;
}

export function summarizeCookies(cookies) {
  const domains = new Set();
  let session = 0;
  let persistent = 0;
  let secure = 0;
  let httpOnly = 0;
  let partitioned = 0;
  let originHeuristic = 0;
  for (const cookie of cookies) {
    domains.add(stripLeadingDot(String(cookie.domain ?? "")).toLowerCase());
    cookie.session ? (session += 1) : (persistent += 1);
    if (cookie.secure) secure += 1;
    if (cookie.httpOnly) httpOnly += 1;
    if (cookie.partitionKey?.topLevelSite) partitioned += 1;
    if (["ambiguous", "unknown"].includes(cookie.originConfidence)) originHeuristic += 1;
  }
  return {
    total: cookies.length,
    domains: domains.size,
    session,
    persistent,
    secure,
    httpOnly,
    partitioned,
    originHeuristic,
  };
}

export function analyzeImport(
  cookies,
  existingCookies,
  { conflictMode = "preserve", supportsPartitioned = true, nowSeconds = Date.now() / 1000 } = {},
) {
  const existingCounts = new Map();
  for (const cookie of existingCookies) {
    const key = cookieIdentity(cookie);
    existingCounts.set(key, (existingCounts.get(key) ?? 0) + 1);
  }
  const ready = [];
  const invalid = [];
  const expired = [];
  const conflicts = [];
  const unsupportedPartitioned = [];
  const ambiguousTarget = [];

  for (const cookie of cookies) {
    if (!cookie || typeof cookie !== "object" || Array.isArray(cookie)) {
      invalid.push({ cookie, errors: cookieValidationErrors(cookie, nowSeconds) });
      continue;
    }
    if (cookie.session === false && Number.isFinite(cookie.expirationDate) && cookie.expirationDate <= nowSeconds) {
      expired.push(cookie);
      continue;
    }
    if (cookie.partitionKey?.topLevelSite && !supportsPartitioned) {
      unsupportedPartitioned.push(cookie);
      continue;
    }
    const errors = cookieValidationErrors(cookie, nowSeconds);
    if (errors.length > 0) {
      invalid.push({ cookie, errors });
      continue;
    }
    const identity = cookieIdentity(cookie);
    if ((existingCounts.get(identity) ?? 0) > 1) {
      ambiguousTarget.push(cookie);
      continue;
    }
    if (conflictMode === "preserve" && existingCounts.has(identity)) {
      conflicts.push(cookie);
      continue;
    }
    ready.push(cookie);
  }

  return { ready, invalid, expired, conflicts, unsupportedPartitioned, ambiguousTarget };
}

export function countMissingCookieIdentities(beforeCookies, afterCookies) {
  const counts = (cookies) => {
    const result = new Map();
    for (const cookie of cookies) {
      const key = cookieIdentity(cookie);
      result.set(key, (result.get(key) ?? 0) + 1);
    }
    return result;
  };
  const before = counts(beforeCookies);
  const after = counts(afterCookies);
  let missing = 0;
  for (const [key, count] of before) {
    missing += Math.max(0, count - (after.get(key) ?? 0));
  }
  return missing;
}

export function formatImportFailure(writtenCount, message) {
  const detail = String(message || "Unknown browser error.").slice(0, 240);
  if (writtenCount > 0) {
    return `Import stopped after ${writtenCount.toLocaleString()} cookies were written. Those changes were not rolled back. ${detail}`;
  }
  return `Import failed before any cookies were written. ${detail}`;
}

export function compareCookieRecords(expected, actual, nowSeconds = Date.now() / 1000) {
  if (!actual) {
    return { matches: false, adjustedExpiration: false, reason: "Cookie was not present after import." };
  }
  const exactFields = ["name", "value", "hostOnly", "path", "secure", "httpOnly", "sameSite", "session"];
  for (const field of exactFields) {
    if (actual[field] !== expected[field]) {
      return { matches: false, adjustedExpiration: false, reason: `Browser changed ${field}.` };
    }
  }
  if (stripLeadingDot(actual.domain).toLowerCase() !== stripLeadingDot(expected.domain).toLowerCase()) {
    return { matches: false, adjustedExpiration: false, reason: "Browser changed the domain." };
  }
  if (partitionIdentity(actual.partitionKey) !== partitionIdentity(expected.partitionKey)) {
    return { matches: false, adjustedExpiration: false, reason: "Browser changed the partition key." };
  }
  if (!expected.session) {
    if (!Number.isFinite(actual.expirationDate) || actual.expirationDate <= nowSeconds) {
      return { matches: false, adjustedExpiration: false, reason: "Persistent expiration was not retained." };
    }
    const capAtVerification = nowSeconds + MAX_PERSISTENT_LIFETIME_SECONDS;
    if (expected.expirationDate <= capAtVerification) {
      if (Math.abs(actual.expirationDate - expected.expirationDate) > 2) {
        return { matches: false, adjustedExpiration: false, reason: "Browser changed the persistent expiration unexpectedly." };
      }
      return { matches: true, adjustedExpiration: false };
    }
    const minimumClamp = nowSeconds + 399 * 24 * 60 * 60;
    const maximumClamp = capAtVerification + 5 * 60;
    if (actual.expirationDate < minimumClamp || actual.expirationDate > maximumClamp) {
      return { matches: false, adjustedExpiration: false, reason: "Browser expiration is outside the expected 400-day clamp window." };
    }
    return { matches: true, adjustedExpiration: true };
  }
  return { matches: true, adjustedExpiration: false };
}

export function createPayload(cookies, scope, metadata = {}) {
  return {
    magic: PAYLOAD_MAGIC,
    version: FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    scope,
    metadata,
    cookies: cookies.map(sanitizeCookie),
  };
}
