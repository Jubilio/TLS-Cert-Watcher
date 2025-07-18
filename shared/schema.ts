import { pgTable, text, serial, integer, boolean, timestamp, json } from "drizzle-orm/pg-core";
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
  name: z.string().min(1),
  hosts: z.array(z.object({
    hostname: z.string().min(1),
    port: z.number().optional().default(443)
  })).min(1).max(100) // Limit to 100 hosts per batch
});

export const scheduleScanRequestSchema = z.object({
  hostname: z.string().min(1),
  port: z.number().optional().default(443),
  scheduleType: z.enum(['daily', 'weekly', 'monthly']),
  notifyEmail: z.string().email().optional(),
  notifyWebhook: z.string().url().optional()
});

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
