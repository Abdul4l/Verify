/*
 * core.js - verification logic shared by the web page and the test suite.
 *
 * How a record is protected:
 *   - The register is public, so it never contains the letter ID or any readable detail.
 *   - A record is found by SHA-256("mk-lookup|" + ID). Without the ID you cannot find it.
 *   - The details (issue date, type, recipient initials, note) are encrypted with AES-256-GCM,
 *     using a key derived from the ID: SHA-256("mk-key|" + ID). Only someone holding the
 *     letter (and so the ID in its QR code) can read them.
 *   - Only the status ("valid" / "revoked") and revocation date are readable by everyone.
 */
(function (root) {
  "use strict";

  var ID_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I, L, O, U
  var ID_LENGTH = 16;                                   // 80 bits of randomness
  var PREFIX = "MK";

  function getSubtle() {
    if (root.crypto && root.crypto.subtle) return root.crypto.subtle;
    throw new Error("This browser cannot run the check (secure context required).");
  }

  // Accepts "MK-7F3K-9Q2X-Q4ZM-1A2B", lowercase, spaces, O/0 and I/L/1 mix-ups.
  // Returns the 16-character canonical ID, or null if it cannot be a valid ID.
  function normaliseId(raw) {
    if (typeof raw !== "string") return null;
    var s = raw.trim().toUpperCase();
    try { s = decodeURIComponent(s); } catch (e) { /* keep as is */ }
    s = s.replace(/[\s\-_]/g, "");
    if (s.indexOf(PREFIX) === 0) s = s.slice(PREFIX.length);
    s = s.replace(/O/g, "0").replace(/[IL]/g, "1");
    if (s.length !== ID_LENGTH) return null;
    for (var i = 0; i < s.length; i++) if (ID_CHARS.indexOf(s[i]) === -1) return null;
    return s;
  }

  function displayId(canon) {
    return PREFIX + "-" + canon.match(/.{4}/g).join("-");
  }

  function utf8(str) { return new TextEncoder().encode(str); }
  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  }
  function fromB64(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function lookupHash(canon) {
    return toHex(await getSubtle().digest("SHA-256", utf8("mk-lookup|" + canon)));
  }

  async function decryptDetails(canon, record, lookup) {
    var subtle = getSubtle();
    var keyBytes = await subtle.digest("SHA-256", utf8("mk-key|" + canon));
    var key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    var plain = await subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(record.n), additionalData: utf8(lookup) },
      key, fromB64(record.d));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  /*
   * Returns { result: ..., ... } where result is one of:
   *   "invalid-format" - the text is not a possible letter ID
   *   "not-found"      - no record for this ID
   *   "unreadable"     - record exists but could not be decrypted (damaged or tampered)
   *   "valid" / "revoked" - with .id, .details, .revokedOn
   */
  async function verify(rawId, register) {
    var canon = normaliseId(rawId);
    if (!canon) return { result: "invalid-format" };
    var lookup = await lookupHash(canon);
    var records = (register && register.records) || {};
    if (!Object.prototype.hasOwnProperty.call(records, lookup)) {
      return { result: "not-found", id: displayId(canon) };
    }
    var rec = records[lookup];
    var details;
    try { details = await decryptDetails(canon, rec, lookup); }
    catch (e) { return { result: "unreadable", id: displayId(canon) }; }
    return {
      result: rec.s === "revoked" ? "revoked" : "valid",
      id: displayId(canon),
      details: details,
      revokedOn: rec.rv || null
    };
  }

  var api = { normaliseId: normaliseId, displayId: displayId, lookupHash: lookupHash, verify: verify };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.MKVerify = api;
})(typeof globalThis !== "undefined" ? globalThis : (typeof self !== "undefined" ? self : this));
