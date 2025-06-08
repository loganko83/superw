import { users, dids, credentials, documents, assets, transactions, taxRefunds, vanTransactions, contractDeployments, contractInteractions, type User, type InsertUser } from "@shared/schema";
import { db } from "./db";
import { eq, and } from "drizzle-orm";

// Interface for storage operations
export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(insertUser: InsertUser): Promise<User>;
  updateUser(id: number, data: Partial<User>): Promise<User>;
  
  // DID operations
  createDID(didData: any): Promise<any>;
  getDIDsByUserId(userId: number): Promise<any[]>;
  
  // Document operations
  createDocument(documentData: any): Promise<any>;
  getDocumentsByUserId(userId: number): Promise<any[]>;
  signDocument(documentId: number, userId: number, signature: string): Promise<any>;
  
  // Asset operations
  createAsset(assetData: any): Promise<any>;
  getAssetsByUserId(userId: number): Promise<any[]>;
  getAssetByType(userId: number, assetType: string): Promise<any>;
  updateAsset(assetId: number, updateData: any): Promise<any>;
  
  // Transaction operations
  createTransaction(transactionData: any): Promise<any>;
  getTransactionsByUserId(userId: number): Promise<any[]>;
  updateTransaction(transactionId: number, updateData: any): Promise<any>;
  
  // Tax refund operations
  createTaxRefund(taxRefundData: any): Promise<any>;
  getTaxRefundsByUserId(userId: number): Promise<any[]>;
  processTaxRefund(refundId: number, action: string): Promise<any>;
  
  // VAN transaction operations
  createVanTransaction(vanData: any): Promise<any>;
  getVanTransactionsByUserId(userId: number): Promise<any[]>;
  updateVanTransaction(transactionId: string, updateData: any): Promise<any>;
  
  // Contract deployment operations
  createContractDeployment(deploymentData: any): Promise<any>;
  getContractDeploymentsByUserId(userId: number): Promise<any[]>;
  updateContractDeployment(deploymentId: number, updateData: any): Promise<any>;
  getContractDeploymentByAddress(contractAddress: string): Promise<any>;
  
  // Contract interaction operations
  createContractInteraction(interactionData: any): Promise<any>;
  getContractInteractionsByUserId(userId: number): Promise<any[]>;
  updateContractInteraction(interactionId: number, updateData: any): Promise<any>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async updateUser(id: number, data: Partial<User>): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return user;
  }

  // DID operations
  async createDID(didData: any): Promise<any> {
    const [did] = await db.insert(dids).values(didData).returning();
    return did;
  }

  async getDIDsByUserId(userId: number): Promise<any[]> {
    return await db.select().from(dids).where(eq(dids.userId, userId));
  }

  // Document operations
  async createDocument(documentData: any): Promise<any> {
    const [document] = await db.insert(documents).values(documentData).returning();
    return document;
  }

  async getDocumentsByUserId(userId: number): Promise<any[]> {
    return await db.select().from(documents).where(eq(documents.userId, userId));
  }

  async signDocument(documentId: number, userId: number, signature: string): Promise<any> {
    const [document] = await db
      .update(documents)
      .set({ signature, signedAt: new Date() })
      .where(eq(documents.id, documentId))
      .returning();
    return document;
  }

  // Asset operations
  async getAssetsByUserId(userId: number): Promise<any[]> {
    return await db.select().from(assets).where(eq(assets.userId, userId));
  }

  async getAssetByType(userId: number, assetType: string): Promise<any> {
    const [asset] = await db
      .select()
      .from(assets)
      .where(and(eq(assets.userId, userId), eq(assets.assetType, assetType)));
    return asset;
  }

  // Transaction operations
  async createTransaction(transactionData: any): Promise<any> {
    const [transaction] = await db.insert(transactions).values(transactionData).returning();
    return transaction;
  }

  async getTransactionsByUserId(userId: number): Promise<any[]> {
    return await db.select().from(transactions).where(eq(transactions.userId, userId));
  }

  // Tax refund operations
  async createTaxRefund(taxRefundData: any): Promise<any> {
    const [taxRefund] = await db.insert(taxRefunds).values(taxRefundData).returning();
    return taxRefund;
  }

  async getTaxRefundsByUserId(userId: number): Promise<any[]> {
    return await db.select().from(taxRefunds).where(eq(taxRefunds.userId, userId));
  }

  async processTaxRefund(refundId: number, action: string): Promise<any> {
    const status = action === 'approve' ? 'approved' : 'rejected';
    const [taxRefund] = await db
      .update(taxRefunds)
      .set({ status, processedAt: new Date() })
      .where(eq(taxRefunds.id, refundId))
      .returning();
    return taxRefund;
  }

  async createAsset(assetData: any): Promise<any> {
    // Mock implementation - create asset record
    const mockAsset = {
      id: Math.floor(Math.random() * 1000),
      userId: assetData.userId,
      assetType: assetData.assetType,
      balance: assetData.balance || "0",
      contractAddress: assetData.contractAddress,
      networkId: assetData.networkId || "xphere",
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    return mockAsset;
  }

  async updateAsset(assetId: number, updateData: any): Promise<any> {
    // Mock implementation - update asset
    return {
      id: assetId,
      ...updateData,
      updatedAt: new Date()
    };
  }

  async updateTransaction(transactionId: number, updateData: any): Promise<any> {
    const [transaction] = await db
      .update(transactions)
      .set(updateData)
      .where(eq(transactions.id, transactionId))
      .returning();
    return transaction;
  }

  // VAN transaction operations
  async createVanTransaction(vanData: any): Promise<any> {
    const [vanTransaction] = await db
      .insert(vanTransactions)
      .values(vanData)
      .returning();
    return vanTransaction;
  }

  async getVanTransactionsByUserId(userId: number): Promise<any[]> {
    return await db
      .select()
      .from(vanTransactions)
      .where(eq(vanTransactions.userId, userId))
      .orderBy(vanTransactions.processedAt);
  }

  async updateVanTransaction(transactionId: string, updateData: any): Promise<any> {
    const [vanTransaction] = await db
      .update(vanTransactions)
      .set(updateData)
      .where(eq(vanTransactions.transactionId, transactionId))
      .returning();
    return vanTransaction;
  }

  // Contract deployment operations
  async createContractDeployment(deploymentData: any): Promise<any> {
    const [deployment] = await db
      .insert(contractDeployments)
      .values(deploymentData)
      .returning();
    return deployment;
  }

  async getContractDeploymentsByUserId(userId: number): Promise<any[]> {
    return await db
      .select()
      .from(contractDeployments)
      .where(eq(contractDeployments.userId, userId))
      .orderBy(contractDeployments.createdAt);
  }

  async updateContractDeployment(deploymentId: number, updateData: any): Promise<any> {
    const [deployment] = await db
      .update(contractDeployments)
      .set(updateData)
      .where(eq(contractDeployments.id, deploymentId))
      .returning();
    return deployment;
  }

  async getContractDeploymentByAddress(contractAddress: string): Promise<any> {
    const [deployment] = await db
      .select()
      .from(contractDeployments)
      .where(eq(contractDeployments.contractAddress, contractAddress));
    return deployment;
  }

  // Contract interaction operations
  async createContractInteraction(interactionData: any): Promise<any> {
    const [interaction] = await db
      .insert(contractInteractions)
      .values(interactionData)
      .returning();
    return interaction;
  }

  async getContractInteractionsByUserId(userId: number): Promise<any[]> {
    return await db
      .select()
      .from(contractInteractions)
      .where(eq(contractInteractions.userId, userId))
      .orderBy(contractInteractions.createdAt);
  }

  async updateContractInteraction(interactionId: number, updateData: any): Promise<any> {
    const [interaction] = await db
      .update(contractInteractions)
      .set(updateData)
      .where(eq(contractInteractions.id, interactionId))
      .returning();
    return interaction;
  }
}

export const storage = new DatabaseStorage();