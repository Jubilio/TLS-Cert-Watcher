import { users, certificateChecks, type User, type InsertUser, type CertificateCheck, type InsertCertificateCheck } from "@shared/schema";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Certificate check methods
  createCertificateCheck(check: InsertCertificateCheck): Promise<CertificateCheck>;
  getCertificateChecks(): Promise<CertificateCheck[]>;
  getCertificateChecksByHostname(hostname: string): Promise<CertificateCheck[]>;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private certificateChecks: Map<number, CertificateCheck>;
  currentUserId: number;
  currentCheckId: number;

  constructor() {
    this.users = new Map();
    this.certificateChecks = new Map();
    this.currentUserId = 1;
    this.currentCheckId = 1;
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
}

export const storage = new MemStorage();
