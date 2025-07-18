import { pgTable, text, serial, integer, boolean, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const certificateChecks = pgTable("certificate_checks", {
  id: serial("id").primaryKey(),
  hostname: text("hostname").notNull(),
  port: integer("port").notNull().default(443),
  status: text("status").notNull(), // 'valid', 'warning', 'expired', 'error'
  daysUntilExpiration: integer("days_until_expiration"),
  issuer: text("issuer"),
  subject: text("subject"),
  validFrom: timestamp("valid_from"),
  validUntil: timestamp("valid_until"),
  errorMessage: text("error_message"),
  scanTimestamp: timestamp("scan_timestamp").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertCertificateCheckSchema = createInsertSchema(certificateChecks).omit({
  id: true,
  scanTimestamp: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertCertificateCheck = z.infer<typeof insertCertificateCheckSchema>;
export type CertificateCheck = typeof certificateChecks.$inferSelect;
