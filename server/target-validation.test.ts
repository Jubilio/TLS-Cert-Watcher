import assert from "node:assert/strict";
import test from "node:test";
import {
  isBlockedAddress,
  normalizeHostname,
  TargetValidationError,
  validatePort,
} from "./target-validation";

test("normalizes safe domain names and IP literals", () => {
  assert.equal(normalizeHostname(" Example.COM. "), "example.com");
  assert.equal(normalizeHostname("[2606:4700:4700::1111]"), "2606:4700:4700::1111");
});

test("rejects shell metacharacters and URLs", () => {
  assert.throws(() => normalizeHostname("example.com;touch /tmp/pwn"), TargetValidationError);
  assert.throws(() => normalizeHostname("https://example.com"), TargetValidationError);
});

test("validates the full TCP port range", () => {
  assert.equal(validatePort(1), 1);
  assert.equal(validatePort(65_535), 65_535);
  assert.throws(() => validatePort(0), TargetValidationError);
  assert.throws(() => validatePort(65_536), TargetValidationError);
  assert.throws(() => validatePort(443.5), TargetValidationError);
});

test("blocks local, private, metadata, and reserved addresses", () => {
  for (const address of [
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "198.51.100.1",
    "203.0.113.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
  ]) {
    assert.equal(isBlockedAddress(address), true, address);
  }
});

test("allows globally routable IPv4 and IPv6 addresses", () => {
  assert.equal(isBlockedAddress("8.8.8.8"), false);
  assert.equal(isBlockedAddress("2606:4700:4700::1111"), false);
});
