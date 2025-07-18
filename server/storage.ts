import { 
  users, 
  certificateChecks, 
  scheduledScans,
  batchScans,
  type User, 
  type InsertUser, 
  type CertificateCheck, 
  type InsertCertificateCheck,
  type ScheduledScan,
  type InsertScheduledScan,
  type BatchScan,
  type InsertBatchScan
} from "@shared/schema";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Certificate check methods
  createCertificateCheck(check: InsertCertificateCheck): Promise<CertificateCheck>;
  getCertificateChecks(): Promise<CertificateCheck[]>;
  getCertificateChecksByHostname(hostname: string): Promise<CertificateCheck[]>;
  getCertificateChecksByBatchId(batchId: string): Promise<CertificateCheck[]>;
  clearCertificateChecks(): Promise<void>;
  
  // Scheduled scan methods
  createScheduledScan(scan: InsertScheduledScan): Promise<ScheduledScan>;
  getScheduledScans(): Promise<ScheduledScan[]>;
  getActiveScheduledScans(): Promise<ScheduledScan[]>;
  updateScheduledScan(id: number, updates: Partial<ScheduledScan>): Promise<ScheduledScan | undefined>;
  deleteScheduledScan(id: number): Promise<boolean>;
  
  // Batch scan methods
  createBatchScan(batch: InsertBatchScan): Promise<BatchScan>;
  getBatchScans(): Promise<BatchScan[]>;
  getBatchScan(id: string): Promise<BatchScan | undefined>;
  updateBatchScan(id: string, updates: Partial<BatchScan>): Promise<BatchScan | undefined>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private certificateChecks: Map<number, CertificateCheck>;
  private scheduledScans: Map<number, ScheduledScan>;
  private batchScans: Map<string, BatchScan>;
  currentUserId: number;
  currentCheckId: number;
  currentScheduledScanId: number;

  constructor() {
    this.users = new Map();
    this.certificateChecks = new Map();
    this.scheduledScans = new Map();
    this.batchScans = new Map();
    this.currentUserId = 1;
    this.currentCheckId = 1;
    this.currentScheduledScanId = 1;
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId++;
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  async createCertificateCheck(insertCheck: InsertCertificateCheck): Promise<CertificateCheck> {
    const id = this.currentCheckId++;
    const check: CertificateCheck = { 
      ...insertCheck,
      port: insertCheck.port ?? 443,
      daysUntilExpiration: insertCheck.daysUntilExpiration ?? null,
      issuer: insertCheck.issuer ?? null,
      subject: insertCheck.subject ?? null,
      validFrom: insertCheck.validFrom ?? null,
      validUntil: insertCheck.validUntil ?? null,
      errorMessage: insertCheck.errorMessage ?? null,
      batchId: insertCheck.batchId ?? null,
      id,
      scanTimestamp: new Date()
    };
    this.certificateChecks.set(id, check);
    return check;
  }

  async getCertificateChecks(): Promise<CertificateCheck[]> {
    return Array.from(this.certificateChecks.values()).sort(
      (a, b) => (b.scanTimestamp?.getTime() || 0) - (a.scanTimestamp?.getTime() || 0)
    );
  }

  async getCertificateChecksByHostname(hostname: string): Promise<CertificateCheck[]> {
    return Array.from(this.certificateChecks.values())
      .filter(check => check.hostname === hostname)
      .sort((a, b) => (b.scanTimestamp?.getTime() || 0) - (a.scanTimestamp?.getTime() || 0));
  }

  async getCertificateChecksByBatchId(batchId: string): Promise<CertificateCheck[]> {
    return Array.from(this.certificateChecks.values())
      .filter(check => check.batchId === batchId)
      .sort((a, b) => (b.scanTimestamp?.getTime() || 0) - (a.scanTimestamp?.getTime() || 0));
  }

  async clearCertificateChecks(): Promise<void> {
    this.certificateChecks.clear();
  }

  // Scheduled scan methods
  async createScheduledScan(insertScan: InsertScheduledScan): Promise<ScheduledScan> {
    const id = this.currentScheduledScanId++;
    const scan: ScheduledScan = {
      ...insertScan,
      port: insertScan.port ?? 443,
      isActive: insertScan.isActive ?? true,
      notifyEmail: insertScan.notifyEmail ?? null,
      notifyWebhook: insertScan.notifyWebhook ?? null,
      id,
      lastScanned: null,
      createdAt: new Date()
    };
    this.scheduledScans.set(id, scan);
    return scan;
  }

  async getScheduledScans(): Promise<ScheduledScan[]> {
    return Array.from(this.scheduledScans.values()).sort(
      (a, b) => (b.createdAt?.getTime() || 0) - (a.createdAt?.getTime() || 0)
    );
  }

  async getActiveScheduledScans(): Promise<ScheduledScan[]> {
    return Array.from(this.scheduledScans.values())
      .filter(scan => scan.isActive)
      .sort((a, b) => (a.nextScan?.getTime() || 0) - (b.nextScan?.getTime() || 0));
  }

  async updateScheduledScan(id: number, updates: Partial<ScheduledScan>): Promise<ScheduledScan | undefined> {
    const existing = this.scheduledScans.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...updates };
    this.scheduledScans.set(id, updated);
    return updated;
  }

  async deleteScheduledScan(id: number): Promise<boolean> {
    return this.scheduledScans.delete(id);
  }

  // Batch scan methods
  async createBatchScan(insertBatch: InsertBatchScan): Promise<BatchScan> {
    const batch: BatchScan = {
      ...insertBatch,
      completedHosts: insertBatch.completedHosts ?? 0,
      failedHosts: insertBatch.failedHosts ?? 0,
      createdAt: new Date(),
      completedAt: null,
      results: null
    };
    this.batchScans.set(batch.id, batch);
    return batch;
  }

  async getBatchScans(): Promise<BatchScan[]> {
    return Array.from(this.batchScans.values()).sort(
      (a, b) => (b.createdAt?.getTime() || 0) - (a.createdAt?.getTime() || 0)
    );
  }

  async getBatchScan(id: string): Promise<BatchScan | undefined> {
    return this.batchScans.get(id);
  }

  async updateBatchScan(id: string, updates: Partial<BatchScan>): Promise<BatchScan | undefined> {
    const existing = this.batchScans.get(id);
    if (!existing) return undefined;
    
    const updated = { ...existing, ...updates };
    this.batchScans.set(id, updated);
    return updated;
  }
}

export const storage = new MemStorage();
