import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  analyzeImport,
  clearCookieValues,
  compareCookieRecords,
  countMissingCookieIdentities,
  cookieIdentity,
  cookieMatchesDomains,
  cookieToSetDetails,
  createPayload,
  decryptBundle,
  encryptBundle,
  formatImportFailure,
  markAmbiguousDuplicates,
  parseDomainList,
  sanitizeCookie,
  setCookieWithConflictPolicy,
  validatePayload,
} from "../lib/bridge-core.js";

const baseCookie = Object.freeze({
  name: "session",
  value: "secret-value",
  domain: "app.example.com",
  hostOnly: true,
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
  session: true,
});

test("domain input normalizes URLs, wildcards, and duplicates", () => {
  assert.deepEqual(
    parseDomainList("https://GitHub.com/login\n*.example.com, github.com"),
    { domains: ["example.com", "github.com"], invalid: [] },
  );
  assert.deepEqual(parseDomainList("good.test https://[broken"), {
    domains: ["good.test"],
    invalid: ["https://[broken"],
  });
});

test("domain matching includes subdomains and applicable parent cookies", () => {
  assert.equal(cookieMatchesDomains({ domain: ".example.com", hostOnly: false }, ["login.example.com"]), true);
  assert.equal(cookieMatchesDomains({ domain: "example.com", hostOnly: true }, ["login.example.com"]), false);
  assert.equal(cookieMatchesDomains({ domain: "api.example.com", hostOnly: true }, ["example.com"]), true);
  assert.equal(cookieMatchesDomains({ domain: "unrelated.test", hostOnly: false }, ["example.com"]), false);
});

test("sanitization whitelists portable fields and omits store id", () => {
  const source = {
    ...baseCookie,
    storeId: "0",
    extraInternalField: "ignored",
    partitionKey: { topLevelSite: "https://top.example", hasCrossSiteAncestor: false },
  };
  const sanitized = sanitizeCookie(source);
  assert.equal("storeId" in sanitized, false);
  assert.equal("extraInternalField" in sanitized, false);
  assert.deepEqual(sanitized.partitionKey, {
    topLevelSite: "https://top.example",
    hasCrossSiteAncestor: false,
  });
  source.value = "changed-after-snapshot";
  assert.equal(sanitized.value, "secret-value");
});

test("host-only session cookie maps without domain or expiration", () => {
  const details = cookieToSetDetails(baseCookie);
  assert.equal(details.url, "https://app.example.com/");
  assert.equal("domain" in details, false);
  assert.equal("expirationDate" in details, false);
  assert.equal(details.httpOnly, true);
});

test("domain persistent cookie preserves partition key and explicit origin", () => {
  const cookie = {
    ...baseCookie,
    domain: ".example.com",
    hostOnly: false,
    session: false,
    expirationDate: Date.now() / 1000 + 3600,
    sourceScheme: "https",
    sourcePort: 8443,
    sameSite: "no_restriction",
    partitionKey: { topLevelSite: "https://container.test", hasCrossSiteAncestor: true },
  };
  const details = cookieToSetDetails(cookie);
  assert.match(details.url, /^https:\/\/example\.com:8443\//u);
  assert.equal(details.domain, ".example.com");
  assert.equal(details.expirationDate, cookie.expirationDate);
  assert.deepEqual(details.partitionKey, cookie.partitionKey);
});

test("expired cookie is skipped before it could delete a target cookie", () => {
  const expired = { ...baseCookie, session: false, expirationDate: 1 };
  const analysis = analyzeImport([expired], [], { nowSeconds: 10 });
  assert.equal(analysis.ready.length, 0);
  assert.equal(analysis.expired.length, 1);
});

test("malformed cookie records are reported instead of aborting inspection", () => {
  const analysis = analyzeImport([null, "bad-record"], []);
  assert.equal(analysis.invalid.length, 2);
  assert.equal(analysis.ready.length, 0);
});

test("payload validation rejects structurally unsafe cookie records", () => {
  const payload = createPayload([baseCookie], { type: "domains", domains: ["example.com"] });
  for (const record of [null, "bad-record", 7, false, []]) {
    assert.throws(
      () => validatePayload({ ...payload, cookies: [record] }),
      /cookie record 1 is not an object/u,
    );
  }
  assert.doesNotThrow(() => validatePayload({ ...payload, cookies: [{}] }));
});

test("cookie-value cleanup tolerates malformed records and clears valid records", () => {
  const cookie = { ...baseCookie };
  assert.doesNotThrow(() => clearCookieValues([cookie, null, "bad-record", []]));
  assert.equal(cookie.value, "");
});

test("partitioned cookies are explicitly skipped when target API lacks support", () => {
  const partitioned = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://top.example", hasCrossSiteAncestor: false },
  };
  const analysis = analyzeImport([partitioned], [], { supportsPartitioned: false });
  assert.equal(analysis.ready.length, 0);
  assert.equal(analysis.unsupportedPartitioned.length, 1);
});

test("preserve mode skips exact conflicts while overwrite mode readies them", () => {
  const existing = [{ ...baseCookie }];
  assert.equal(analyzeImport([baseCookie], existing, { conflictMode: "preserve" }).conflicts.length, 1);
  assert.equal(analyzeImport([baseCookie], existing, { conflictMode: "overwrite" }).ready.length, 1);
});

test("a destination cookie created after inspection prevents a preserve write", async () => {
  const calls = [];
  const outcome = await setCookieWithConflictPolicy(baseCookie, "preserve", {
    getCurrentCookies: async () => {
      calls.push("get");
      return [{ ...baseCookie, value: "late-destination-value" }];
    },
    setCookie: async () => {
      calls.push("set");
      throw new Error("setCookie must not be called for a late conflict");
    },
  });
  assert.deepEqual(outcome, { preserved: true });
  assert.deepEqual(calls, ["get"]);
});

test("partition identity canonicalizes site casing without inventing an ancestor flag", () => {
  const imported = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://EXAMPLE.COM" },
  };
  const existing = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://example.com" },
  };
  assert.equal(cookieIdentity(imported), cookieIdentity(existing));
});

test("sanitization preserves an omitted cross-site ancestor flag for Chrome to compute", () => {
  const imported = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://different.test" },
  };
  const sanitized = sanitizeCookie(imported);
  assert.equal("hasCrossSiteAncestor" in sanitized.partitionKey, false);
  assert.equal("hasCrossSiteAncestor" in cookieToSetDetails(sanitized).partitionKey, false);
});

test("a partition-scoped recheck treats Chrome's canonical partition key as authoritative", async () => {
  const imported = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://EXAMPLE.COM" },
  };
  const existing = {
    ...baseCookie,
    value: "late-destination-value",
    partitionKey: { topLevelSite: "https://example.com", hasCrossSiteAncestor: false },
  };
  let setCalls = 0;
  const outcome = await setCookieWithConflictPolicy(imported, "preserve", {
    getCurrentCookies: async () => [existing],
    setCookie: async () => {
      setCalls += 1;
      return imported;
    },
  });
  assert.deepEqual(outcome, { preserved: true });
  assert.equal(setCalls, 0);
});

test("preserve mode rechecks immediately before writing a non-conflict", async () => {
  const calls = [];
  const result = { ...baseCookie, value: "written-value" };
  const outcome = await setCookieWithConflictPolicy(baseCookie, "preserve", {
    getCurrentCookies: async () => {
      calls.push("get");
      return [{ ...baseCookie, path: "/different" }];
    },
    setCookie: async () => {
      calls.push("set");
      return result;
    },
  });
  assert.deepEqual(outcome, { preserved: false, result });
  assert.deepEqual(calls, ["get", "set"]);
});

test("preserve mode fails closed when the live recheck fails", async () => {
  let setCalls = 0;
  await assert.rejects(
    setCookieWithConflictPolicy(baseCookie, "preserve", {
      getCurrentCookies: async () => {
        throw new Error("cookie lookup failed");
      },
      setCookie: async () => {
        setCalls += 1;
        return baseCookie;
      },
    }),
    /cookie lookup failed/u,
  );
  assert.equal(setCalls, 0);
});

test("overwrite mode writes without a preserve recheck", async () => {
  let getCalls = 0;
  let setCalls = 0;
  const outcome = await setCookieWithConflictPolicy(baseCookie, "overwrite", {
    getCurrentCookies: async () => {
      getCalls += 1;
      return [baseCookie];
    },
    setCookie: async () => {
      setCalls += 1;
      return baseCookie;
    },
  });
  assert.equal(outcome.preserved, false);
  assert.equal(getCalls, 0);
  assert.equal(setCalls, 1);
});

test("origin-bound duplicate identities in the target are skipped in every conflict mode", () => {
  const target = [
    { ...baseCookie, value: "https-binding" },
    { ...baseCookie, value: "http-binding" },
  ];
  const analysis = analyzeImport([baseCookie], target, { conflictMode: "overwrite" });
  assert.equal(analysis.ready.length, 0);
  assert.equal(analysis.ambiguousTarget.length, 1);
});

test("identity distinguishes host-only, paths, and partition ancestor bits", () => {
  const domain = { ...baseCookie, hostOnly: false };
  const path = { ...baseCookie, path: "/account" };
  const partitionA = {
    ...baseCookie,
    partitionKey: { topLevelSite: "https://top.example", hasCrossSiteAncestor: false },
  };
  const partitionB = {
    ...partitionA,
    partitionKey: { topLevelSite: "https://top.example", hasCrossSiteAncestor: true },
  };
  const identities = new Set([baseCookie, domain, path, partitionA, partitionB].map(cookieIdentity));
  assert.equal(identities.size, 5);
});

test("indistinguishable origin-bound duplicates are marked non-portable", () => {
  const duplicates = markAmbiguousDuplicates([
    { ...baseCookie, value: "http-value" },
    { ...baseCookie, value: "https-value" },
  ]);
  assert.equal(duplicates.every((cookie) => cookie.ambiguousDuplicate), true);
  assert.equal(analyzeImport(duplicates, []).invalid.length, 2);
});

test("prefix validation rejects malformed host cookies", () => {
  const malformed = { ...baseCookie, name: "__Host-token", hostOnly: false };
  const analysis = analyzeImport([malformed], []);
  assert.equal(analysis.invalid.length, 1);
  assert.match(analysis.invalid[0].errors.join(" "), /__Host-/u);
});

test("encrypted bundle round-trips and rejects a wrong passphrase", async () => {
  const payload = createPayload([baseCookie], { type: "domains", domains: ["example.com"] });
  const serialized = await encryptBundle(payload, "correct horse battery staple", webcrypto);
  const decrypted = await decryptBundle(serialized, "correct horse battery staple", webcrypto);
  assert.deepEqual(decrypted, payload);
  await assert.rejects(
    decryptBundle(serialized, "this passphrase is incorrect", webcrypto),
    /could not be decrypted/u,
  );
});

test("tampering is authenticated and non-decryptable", async () => {
  const payload = createPayload([baseCookie], { type: "all", domains: [] });
  const serialized = await encryptBundle(payload, "correct horse battery staple", webcrypto);
  const envelope = JSON.parse(serialized);
  envelope.ciphertext = `${envelope.ciphertext.slice(0, -4)}AAAA`;
  await assert.rejects(
    decryptBundle(JSON.stringify(envelope), "correct horse battery staple", webcrypto),
    /could not be decrypted/u,
  );
});

test("verification accepts Chromium expiration clamping but reports adjustment", () => {
  const expected = {
    ...baseCookie,
    session: false,
    expirationDate: Date.now() / 1000 + 500 * 24 * 3600,
  };
  const actual = {
    ...expected,
    expirationDate: Date.now() / 1000 + 400 * 24 * 3600,
  };
  assert.deepEqual(compareCookieRecords(expected, actual), {
    matches: true,
    adjustedExpiration: true,
  });
});

test("verification rejects arbitrary future expiration changes", () => {
  const now = Date.now() / 1000;
  const expected = {
    ...baseCookie,
    session: false,
    expirationDate: now + 30 * 24 * 3600,
  };
  const actual = { ...expected, expirationDate: now + 60 * 60 };
  const comparison = compareCookieRecords(expected, actual, now);
  assert.equal(comparison.matches, false);
  assert.match(comparison.reason, /expiration unexpectedly/u);
});

test("pre-existing destination identity removals are counted as a multiset", () => {
  const duplicate = { ...baseCookie };
  const retained = { ...baseCookie, path: "/retained" };
  assert.equal(
    countMissingCookieIdentities([baseCookie, duplicate, retained], [baseCookie, retained]),
    1,
  );
});

test("top-level import errors disclose partial writes and lack of rollback", () => {
  assert.match(formatImportFailure(7, "Verification snapshot failed."), /7 cookies were written/u);
  assert.match(formatImportFailure(7, "Verification snapshot failed."), /not rolled back/u);
  assert.match(formatImportFailure(0, "Permission denied."), /before any cookies were written/u);
});
