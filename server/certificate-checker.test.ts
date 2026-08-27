import assert from "node:assert/strict";
import test from "node:test";
import { classifyCertificate, daysUntilExpiration } from "./certificate-checker";

const now = new Date("2026-08-27T10:00:00.000Z");

test("rounds partial remaining and elapsed days conservatively", () => {
  assert.equal(daysUntilExpiration(new Date("2026-08-28T09:00:00.000Z"), now), 1);
  assert.equal(daysUntilExpiration(new Date("2026-08-27T09:00:00.000Z"), now), -1);
});

test("classifies certificate expiration thresholds", () => {
  assert.equal(classifyCertificate(new Date("2026-08-27T09:00:00.000Z"), now), "expired");
  assert.equal(classifyCertificate(new Date("2026-09-26T10:00:00.000Z"), now), "warning");
  assert.equal(classifyCertificate(new Date("2026-09-27T10:00:00.000Z"), now), "valid");
});
