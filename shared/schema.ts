import { pgTable, text, serial, integer, boolean, timestamp, json } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const hostnameSchema = z
  .string()
  .trim()
  .min(1)
  .max(2048)
  .transform((value) => {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      try {
        return new URL(value).hostname;
      } catch {
        return value.replace(/^https?:\/\//i, "").split("/")[0];
      }
    }
    if (value.includes("/")) {
      return value.split("/")[0];
    }
    return value;
  })
  .transform((value) => value.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase())
  .refine((value) => /^[a-z0-9.:-]+$/.test(value), "Invalid hostname or IP address");

export const portSchema = z.coerce.number().int().min(1).max(65_535);

export const scanTargetSchema = z.object({
  hostname: hostnameSchema,
  port: portSchema.default(443),
});

const optionalEmailSchema = z.preprocess(
  (value) => (value === "" || value === null ? undefined : value),
  z.string().trim().email().max(254).optional(),
);

const optionalHttpsUrlSchema = z.preprocess(
  (value) => (value === "" || value === null ? undefined : value),
  z
    .string()
    .trim()
    .url()
    .max(2_048)
    .refine((value) => new URL(value).protocol === "https:", "Webhook URL must use HTTPS")
    .optional(),
);

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
  batchId: text("batch_id"), // For batch scans
});

export const scheduledScans = pgTable("scheduled_scans", {
  id: serial("id").primaryKey(),
  hostname: text("hostname").notNull(),
  port: integer("port").notNull().default(443),
  scheduleType: text("schedule_type").notNull(), // 'daily', 'weekly', 'monthly'
  isActive: boolean("is_active").notNull().default(true),
  lastScanned: timestamp("last_scanned"),
  nextScan: timestamp("next_scan").notNull(),
  notifyEmail: text("notify_email"),
  notifyWebhook: text("notify_webhook"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const batchScans = pgTable("batch_scans", {
  id: text("id").primaryKey(), // UUID
  name: text("name").notNull(),
  status: text("status").notNull(), // 'pending', 'running', 'completed', 'failed'
  totalHosts: integer("total_hosts").notNull(),
  completedHosts: integer("completed_hosts").notNull().default(0),
  failedHosts: integer("failed_hosts").notNull().default(0),
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
  results: json("results"), // Array of scan results
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export const insertCertificateCheckSchema = createInsertSchema(certificateChecks).omit({
  id: true,
  scanTimestamp: true,
});

export const insertScheduledScanSchema = createInsertSchema(scheduledScans).omit({
  id: true,
  lastScanned: true,
  createdAt: true,
});

export const insertBatchScanSchema = createInsertSchema(batchScans).omit({
  completedAt: true,
  createdAt: true,
});

// API request schemas
export const batchScanRequestSchema = z.object({
  name: z.string().trim().min(1).max(100),
  hosts: z.array(scanTargetSchema).min(1).max(100),
});

export const scheduleScanRequestSchema = scanTargetSchema.extend({
  scheduleType: z.enum(["daily", "weekly", "monthly"]),
  notifyEmail: optionalEmailSchema,
  notifyWebhook: optionalHttpsUrlSchema,
});

export const updateScheduledScanSchema = z
  .object({
    isActive: z.boolean(),
  })
  .strict();

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertCertificateCheck = z.infer<typeof insertCertificateCheckSchema>;
export type CertificateCheck = typeof certificateChecks.$inferSelect;
export type InsertScheduledScan = z.infer<typeof insertScheduledScanSchema>;
export type ScheduledScan = typeof scheduledScans.$inferSelect;
export type InsertBatchScan = z.infer<typeof insertBatchScanSchema>;
export type BatchScan = typeof batchScans.$inferSelect;
export type BatchScanRequest = z.infer<typeof batchScanRequestSchema>;
export type ScheduleScanRequest = z.infer<typeof scheduleScanRequestSchema>;
