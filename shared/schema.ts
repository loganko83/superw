import { pgTable, text, serial, timestamp, jsonb, varchar, integer, boolean, numeric } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Users table for authentication
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  nationality: text("nationality"),
  passportNumber: text("passport_number"),
  xphereWalletAddress: text("xphere_wallet_address").unique(),
  language: text("language").default("ko"),
  country: text("country").default("KR"),
  isVerified: boolean("is_verified").default(false),
  biometricEnabled: boolean("biometric_enabled").default(false),
  fingerprintHash: text("fingerprint_hash"),
  faceEncodingHash: text("face_encoding_hash"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// DID (Decentralized Identity) records
export const dids = pgTable("dids", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  didIdentifier: text("did_identifier").notNull().unique(),
  didDocument: jsonb("did_document").notNull(),
  publicKey: text("public_key").notNull(),
  privateKeyHash: text("private_key_hash").notNull(),
  blockchainTxHash: text("blockchain_tx_hash"),
  status: text("status").notNull().default("pending"), // pending, active, revoked
  issuedAt: timestamp("issued_at").defaultNow(),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Verifiable Credentials
export const credentials = pgTable("credentials", {
  id: serial("id").primaryKey(),
  didId: integer("did_id").references(() => dids.id).notNull(),
  credentialType: text("credential_type").notNull(), // passport, certificate, etc.
  credentialData: jsonb("credential_data").notNull(),
  issuerDid: text("issuer_did").notNull(),
  issuerSignature: text("issuer_signature").notNull(),
  blockchainTxHash: text("blockchain_tx_hash"),
  status: text("status").notNull().default("valid"), // valid, revoked, expired
  issuedAt: timestamp("issued_at").defaultNow(),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Electronic Documents
export const documents = pgTable("documents", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  title: text("title").notNull(),
  documentType: text("document_type").notNull(), // contract, certificate, report
  content: text("content").notNull(),
  contentHash: text("content_hash").notNull(),
  signatures: jsonb("signatures").default('[]'),
  blockchainTxHash: text("blockchain_tx_hash"),
  ipfsHash: text("ipfs_hash"),
  status: text("status").notNull().default("draft"), // draft, signed, finalized
  version: integer("version").default(1),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Virtual Assets (Wallets)
export const assets = pgTable("assets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  assetType: text("asset_type").notNull(), // XP, CBDC, KWAN, BTC, ETH
  balance: numeric("balance", { precision: 18, scale: 8 }).notNull().default("0"),
  address: text("address").notNull(),
  privateKeyHash: text("private_key_hash").notNull(),
  networkId: text("network_id").notNull(), // xphere, ethereum, etc.
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Payment Transactions
export const transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  fromAddress: text("from_address").notNull(),
  toAddress: text("to_address").notNull(),
  assetType: text("asset_type").notNull(),
  amount: numeric("amount", { precision: 18, scale: 8 }).notNull(),
  fee: numeric("fee", { precision: 18, scale: 8 }).default("0"),
  txHash: text("tx_hash").notNull().unique(),
  blockNumber: integer("block_number"),
  status: text("status").notNull().default("pending"), // pending, confirmed, failed
  transactionType: text("transaction_type").notNull(), // send, receive, payment
  merchantInfo: jsonb("merchant_info"),
  createdAt: timestamp("created_at").defaultNow(),
  confirmedAt: timestamp("confirmed_at"),
});

// Tax Refund Records
export const taxRefunds = pgTable("tax_refunds", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  passportNumber: text("passport_number").notNull(),
  purchaseAmount: numeric("purchase_amount", { precision: 10, scale: 2 }).notNull(),
  taxAmount: numeric("tax_amount", { precision: 10, scale: 2 }).notNull(),
  refundAmount: numeric("refund_amount", { precision: 10, scale: 2 }).notNull(),
  merchantName: text("merchant_name").notNull(),
  receiptHash: text("receipt_hash").notNull(),
  receiptImage: text("receipt_image"),
  kwanAmount: numeric("kwan_amount", { precision: 18, scale: 8 }),
  blockchainTxHash: text("blockchain_tx_hash"),
  status: text("status").notNull().default("pending"), // pending, approved, completed, rejected
  processedAt: timestamp("processed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// VAN Integration Records
export const vanTransactions = pgTable("van_transactions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  transactionId: integer("transaction_id").references(() => transactions.id),
  vanProvider: text("van_provider").notNull(), // provider name
  merchantId: text("merchant_id").notNull(),
  terminalId: text("terminal_id"),
  vanTxId: text("van_tx_id").notNull(),
  amount: numeric("amount", { precision: 10, scale: 2 }).notNull(),
  currency: text("currency").notNull().default("KRW"),
  exchangeRate: numeric("exchange_rate", { precision: 10, scale: 6 }),
  status: text("status").notNull().default("pending"),
  createdAt: timestamp("created_at").defaultNow(),
  processedAt: timestamp("processed_at"),
});

// Wallet Balance Tracking
export const walletBalances = pgTable("wallet_balances", {
  id: serial("id").primaryKey(),
  address: text("address").notNull().unique(),
  balance: numeric("balance", { precision: 18, scale: 8 }).notNull().default("0"),
  assetType: text("asset_type").notNull().default("XP"),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Biometric authentication sessions
export const biometricSessions = pgTable("biometric_sessions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  sessionId: text("session_id").notNull().unique(),
  authType: text("auth_type").notNull(), // fingerprint, facial, both
  livenessVerified: boolean("liveness_verified").default(false),
  qualityScore: numeric("quality_score", { precision: 5, scale: 2 }),
  deviceInfo: jsonb("device_info"),
  ipAddress: text("ip_address"),
  status: text("status").notNull().default("pending"), // pending, verified, failed, expired
  expiresAt: timestamp("expires_at").notNull(),
  verifiedAt: timestamp("verified_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Contract deployments table for smart contract management
export const contractDeployments = pgTable("contract_deployments", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  contractName: text("contract_name").notNull(),
  contractAddress: text("contract_address").notNull().unique(),
  deployerAddress: text("deployer_address").notNull(),
  txHash: text("tx_hash").notNull().unique(),
  blockNumber: integer("block_number").notNull(),
  gasUsed: integer("gas_used").notNull(),
  status: text("status").notNull().default("pending"), // pending, deployed, verified, failed
  abi: jsonb("abi").notNull(),
  bytecode: text("bytecode").notNull(),
  constructorArgs: jsonb("constructor_args").notNull(),
  compilationMetadata: jsonb("compilation_metadata"),
  deploymentDate: timestamp("deployment_date").defaultNow(),
  verifiedAt: timestamp("verified_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Contract interactions table for tracking function calls
export const contractInteractions = pgTable("contract_interactions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  contractAddress: text("contract_address").notNull(),
  functionName: text("function_name").notNull(),
  args: jsonb("args").notNull(),
  txHash: text("tx_hash"),
  blockNumber: integer("block_number"),
  gasUsed: integer("gas_used"),
  status: text("status").notNull().default("pending"), // pending, success, failed
  result: jsonb("result"),
  errorMessage: text("error_message"),
  value: text("value"), // ETH/XP value sent with transaction
  createdAt: timestamp("created_at").defaultNow(),
});

// Schema exports for validation
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertDIDSchema = createInsertSchema(dids).omit({
  id: true,
  createdAt: true,
});

export const insertCredentialSchema = createInsertSchema(credentials).omit({
  id: true,
  createdAt: true,
});

export const insertDocumentSchema = createInsertSchema(documents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertAssetSchema = createInsertSchema(assets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertTransactionSchema = createInsertSchema(transactions).omit({
  id: true,
  createdAt: true,
  confirmedAt: true,
});

export const insertTaxRefundSchema = createInsertSchema(taxRefunds).omit({
  id: true,
  createdAt: true,
  processedAt: true,
});

export const insertVanTransactionSchema = createInsertSchema(vanTransactions).omit({
  id: true,
  createdAt: true,
  processedAt: true,
});

export const insertWalletBalanceSchema = createInsertSchema(walletBalances).omit({
  id: true,
  updatedAt: true,
});

export const insertBiometricSessionSchema = createInsertSchema(biometricSessions).omit({
  id: true,
  createdAt: true,
  verifiedAt: true,
});

// Type exports
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export type InsertDID = z.infer<typeof insertDIDSchema>;
export type DID = typeof dids.$inferSelect;

export type InsertCredential = z.infer<typeof insertCredentialSchema>;
export type Credential = typeof credentials.$inferSelect;

export type InsertDocument = z.infer<typeof insertDocumentSchema>;
export type Document = typeof documents.$inferSelect;

export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assets.$inferSelect;

export type InsertTransaction = z.infer<typeof insertTransactionSchema>;
export type Transaction = typeof transactions.$inferSelect;

export type InsertTaxRefund = z.infer<typeof insertTaxRefundSchema>;
export type TaxRefund = typeof taxRefunds.$inferSelect;

export type InsertVanTransaction = z.infer<typeof insertVanTransactionSchema>;
export type VanTransaction = typeof vanTransactions.$inferSelect;

export type InsertWalletBalance = z.infer<typeof insertWalletBalanceSchema>;
export type WalletBalance = typeof walletBalances.$inferSelect;

export type InsertBiometricSession = z.infer<typeof insertBiometricSessionSchema>;
export type BiometricSession = typeof biometricSessions.$inferSelect;

export const insertContractDeploymentSchema = createInsertSchema(contractDeployments).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertContractInteractionSchema = createInsertSchema(contractInteractions).omit({
  id: true,
  createdAt: true,
});

export type InsertContractDeployment = z.infer<typeof insertContractDeploymentSchema>;
export type ContractDeployment = typeof contractDeployments.$inferSelect;

export type InsertContractInteraction = z.infer<typeof insertContractInteractionSchema>;
export type ContractInteraction = typeof contractInteractions.$inferSelect;
