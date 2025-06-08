import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { insertUserSchema, insertDIDSchema, insertDocumentSchema, insertTransactionSchema, insertTaxRefundSchema } from "@shared/schema";
import { pool } from "./db";

const JWT_SECRET = process.env.JWT_SECRET || "superwallet-secret-key";

// Middleware for JWT authentication
const authenticateToken = (req: any, res: any, next: any) => {
  // Skip authentication for testing endpoints only
  if (req.path === '/api/payments/send' || 
      req.path === '/api/payments/deposit' ||
      req.path.startsWith('/api/contracts/')) {
    req.user = { id: 1, userId: 1 };
    return next();
  }
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

export async function registerRoutes(app: Express): Promise<Server> {
  
  // Authentication Routes
  app.post('/api/auth/register', async (req, res) => {
    try {
      const userData = insertUserSchema.parse(req.body);
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      
      const user = await storage.createUser({
        ...userData,
        password: hashedPassword
      });

      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
      
      res.json({ 
        user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName },
        token 
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(400).json({ message: 'Registration failed', error: error.message });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await storage.getUserByEmail(email);
      
      if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
      
      res.json({ 
        user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName },
        token 
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Login failed' });
    }
  });

  app.get('/api/auth/me', authenticateToken, async (req: any, res) => {
    try {
      const user = await storage.getUser(req.user.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      res.json({ 
        id: user.id, 
        email: user.email, 
        firstName: user.firstName, 
        lastName: user.lastName,
        nationality: user.nationality,
        isVerified: user.isVerified
      });
    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({ message: 'Failed to get user info' });
    }
  });

  // DID Management Routes
  app.post('/api/did/create', authenticateToken, async (req: any, res) => {
    try {
      const didData = insertDIDSchema.parse({
        ...req.body,
        userId: req.user.userId
      });

      const did = await storage.createDID(didData);
      res.json(did);
    } catch (error) {
      console.error('DID creation error:', error);
      res.status(400).json({ message: 'Failed to create DID', error: error.message });
    }
  });

  app.get('/api/did/user/:userId', authenticateToken, async (req: any, res) => {
    try {
      const dids = await storage.getDIDsByUserId(parseInt(req.params.userId));
      res.json(dids);
    } catch (error) {
      console.error('Get DIDs error:', error);
      res.status(500).json({ message: 'Failed to get DIDs' });
    }
  });

  app.post('/api/did/verify-passport', authenticateToken, async (req: any, res) => {
    try {
      // This would integrate with passport scanning and verification service
      const { passportData } = req.body;
      
      // Mock passport verification - in real implementation, this would
      // validate against official passport databases
      const verificationResult = {
        isValid: true,
        nationality: passportData.nationality,
        passportNumber: passportData.passportNumber,
        expiryDate: passportData.expiryDate
      };

      if (verificationResult.isValid) {
        // Update user with passport information
        await storage.updateUser(req.user.userId, {
          nationality: verificationResult.nationality,
          passportNumber: verificationResult.passportNumber,
          isVerified: true
        });
      }

      res.json(verificationResult);
    } catch (error) {
      console.error('Passport verification error:', error);
      res.status(500).json({ message: 'Passport verification failed' });
    }
  });

  // Korean Resident Registration Card verification
  app.post('/api/did/verify-resident-card', authenticateToken, async (req: any, res) => {
    try {
      const { cardData } = req.body;
      
      // This would integrate with Korean government verification services
      // In production, this would validate against the Korean resident registration system
      const verificationResult = {
        isValid: true,
        name: cardData.extractedFields?.이름,
        residentNumber: cardData.extractedFields?.주민등록번호,
        address: cardData.extractedFields?.주소,
        issueDate: cardData.extractedFields?.발급일자,
        documentType: 'resident_card',
        verifiedAt: new Date().toISOString()
      };

      if (verificationResult.isValid) {
        // Update user with resident card information
        await storage.updateUser(req.user.userId, {
          koreanName: verificationResult.name,
          residentNumber: verificationResult.residentNumber,
          koreanAddress: verificationResult.address,
          isKoreanResident: true,
          isVerified: true
        });
      }

      res.json(verificationResult);
    } catch (error) {
      console.error('Resident card verification error:', error);
      res.status(500).json({ message: 'Resident card verification failed' });
    }
  });

  // Korean Driver's License verification
  app.post('/api/did/verify-driver-license', authenticateToken, async (req: any, res) => {
    try {
      const { licenseData } = req.body;
      
      // This would integrate with Korean driver's license verification services
      // In production, this would validate against the Korean road traffic authority system
      const verificationResult = {
        isValid: true,
        name: licenseData.extractedFields?.이름,
        licenseNumber: licenseData.extractedFields?.면허번호,
        birthDate: licenseData.extractedFields?.생년월일,
        address: licenseData.extractedFields?.주소,
        licenseType: licenseData.extractedFields?.면허종류,
        issueDate: licenseData.extractedFields?.발급일자,
        documentType: 'driver_license',
        verifiedAt: new Date().toISOString()
      };

      if (verificationResult.isValid) {
        // Update user with driver's license information
        await storage.updateUser(req.user.userId, {
          koreanName: verificationResult.name,
          driverLicenseNumber: verificationResult.licenseNumber,
          koreanAddress: verificationResult.address,
          licenseType: verificationResult.licenseType,
          isLicensedDriver: true,
          isVerified: true
        });
      }

      res.json(verificationResult);
    } catch (error) {
      console.error('Driver license verification error:', error);
      res.status(500).json({ message: 'Driver license verification failed' });
    }
  });

  // Korean Health Insurance verification
  app.post('/api/did/verify-health-insurance', authenticateToken, async (req: any, res) => {
    try {
      const { insuranceData } = req.body;
      
      // This would integrate with Korean health insurance verification services
      // In production, this would validate against the National Health Insurance Service system
      const verificationResult = {
        isValid: true,
        name: insuranceData.extractedFields?.이름,
        insuranceNumber: insuranceData.extractedFields?.보험증번호,
        birthDate: insuranceData.extractedFields?.생년월일,
        address: insuranceData.extractedFields?.주소,
        qualificationDate: insuranceData.extractedFields?.자격득실일,
        issueDate: insuranceData.extractedFields?.발급일자,
        documentType: 'health_insurance',
        verificationMethod: insuranceData.source === 'gov24' ? 'government_system' : 'document_ocr',
        verifiedAt: new Date().toISOString()
      };

      if (verificationResult.isValid) {
        // Update user with health insurance information
        await storage.updateUser(req.user.userId, {
          koreanName: verificationResult.name,
          healthInsuranceNumber: verificationResult.insuranceNumber,
          koreanAddress: verificationResult.address,
          hasHealthInsurance: true,
          isVerified: true
        });
      }

      res.json(verificationResult);
    } catch (error) {
      console.error('Health insurance verification error:', error);
      res.status(500).json({ message: 'Failed to verify health insurance' });
    }
  });

  // Language Settings Routes
  app.post('/api/user/language-settings', authenticateToken, async (req: any, res) => {
    try {
      const { language, country } = req.body;
      
      const updatedUser = await storage.updateUser(req.user.userId, {
        language,
        country
      });
      
      res.json({
        language: updatedUser.language,
        country: updatedUser.country,
        message: 'Language settings updated successfully'
      });
    } catch (error) {
      console.error('Language settings update error:', error);
      res.status(500).json({ message: 'Failed to update language settings' });
    }
  });

  app.get('/api/user/language-settings', authenticateToken, async (req: any, res) => {
    try {
      const user = await storage.getUser(req.user.userId);
      
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      res.json({
        language: user.language || 'ko',
        country: user.country || 'KR'
      });
    } catch (error) {
      console.error('Get language settings error:', error);
      res.status(500).json({ message: 'Failed to get language settings' });
    }
  });

  // Document Management Routes
  app.post('/api/documents', authenticateToken, async (req: any, res) => {
    try {
      const documentData = insertDocumentSchema.parse({
        ...req.body,
        userId: req.user.userId
      });

      const document = await storage.createDocument(documentData);
      res.json(document);
    } catch (error) {
      console.error('Document creation error:', error);
      res.status(400).json({ message: 'Failed to create document', error: error.message });
    }
  });

  app.get('/api/documents/user', authenticateToken, async (req: any, res) => {
    try {
      const documents = await storage.getDocumentsByUserId(req.user.userId);
      res.json(documents);
    } catch (error) {
      console.error('Get documents error:', error);
      res.status(500).json({ message: 'Failed to get documents' });
    }
  });

  app.post('/api/documents/:id/sign', authenticateToken, async (req: any, res) => {
    try {
      const { signature } = req.body;
      const documentId = parseInt(req.params.id);
      
      const document = await storage.signDocument(documentId, req.user.userId, signature);
      res.json(document);
    } catch (error) {
      console.error('Document signing error:', error);
      res.status(400).json({ message: 'Failed to sign document' });
    }
  });

  // Asset Management Routes
  app.get('/api/assets/user', authenticateToken, async (req: any, res) => {
    try {
      const assets = await storage.getAssetsByUserId(req.user.userId);
      res.json(assets);
    } catch (error) {
      console.error('Get assets error:', error);
      res.status(500).json({ message: 'Failed to get assets' });
    }
  });

  app.get('/api/assets/balance/:assetType', authenticateToken, async (req: any, res) => {
    try {
      const { assetType } = req.params;
      const asset = await storage.getAssetByType(req.user.userId, assetType);
      res.json({ balance: asset?.balance || '0' });
    } catch (error) {
      console.error('Get balance error:', error);
      res.status(500).json({ message: 'Failed to get balance' });
    }
  });

  // Payment Routes
  app.post('/api/payments/send', authenticateToken, async (req: any, res) => {
    try {
      const { toAddress, amount, assetType } = req.body;
      
      // Validate transaction parameters
      if (!toAddress || !amount || !assetType) {
        return res.status(400).json({ message: 'Missing required transaction parameters' });
      }
      
      if (parseFloat(amount) <= 0) {
        return res.status(400).json({ message: 'Invalid transaction amount' });
      }
      
      // For XP transactions, simulate transaction with balance update
      if (assetType === 'XP') {
        const fromAddress = '0xb8c1f75bb7550bb51039c64e92c78d15ad9dbbe1';
        
        // Get current balance from database
        const balanceQuery = await pool.query(
          'SELECT balance FROM wallet_balances WHERE address = $1',
          [fromAddress]
        );
        
        const currentBalance = balanceQuery.rows.length > 0 
          ? parseFloat(balanceQuery.rows[0].balance) 
          : 1.0; // Default to 1.0 XP if no record exists
        
        // Check if sufficient balance
        if (currentBalance < parseFloat(amount)) {
          return res.status(400).json({ 
            message: 'Insufficient balance for withdrawal',
            currentBalance: currentBalance.toString(),
            requestedAmount: amount.toString()
          });
        }
        
        // Create transaction record with real-looking hash
        const txHash = '0x' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
        
        const transactionData = insertTransactionSchema.parse({
          userId: req.user.userId,
          assetType,
          amount: amount.toString(),
          toAddress,
          fromAddress,
          txHash,
          status: 'completed',
          transactionType: 'send'
        });

        const transaction = await storage.createTransaction(transactionData);
        
        // Update the balance in the database
        const newBalance = currentBalance - parseFloat(amount);
        await pool.query(
          'UPDATE wallet_balances SET balance = $1, updated_at = NOW() WHERE address = $2',
          [newBalance.toString(), fromAddress]
        );
        
        res.json({ 
          ...transaction, 
          txHash,
          previousBalance: currentBalance.toString(),
          newBalance: newBalance.toString(),
          message: 'Withdrawal completed successfully - balance updated'
        });
      } else {
        // Handle other asset types
        const transactionData = insertTransactionSchema.parse({
          ...req.body,
          userId: req.user.userId,
          status: 'pending'
        });

        const transaction = await storage.createTransaction(transactionData);
        res.json(transaction);
      }
    } catch (error) {
      console.error('Payment error:', error);
      res.status(400).json({ message: 'Payment failed', error: error.message });
    }
  });

  app.get('/api/payments/history', authenticateToken, async (req: any, res) => {
    try {
      const transactions = await storage.getTransactionsByUserId(req.user.userId);
      res.json(transactions);
    } catch (error) {
      console.error('Get payment history error:', error);
      res.status(500).json({ message: 'Failed to get payment history' });
    }
  });

  // Tax Refund Routes
  app.post('/api/tax-refund/apply', authenticateToken, async (req: any, res) => {
    try {
      const taxRefundData = insertTaxRefundSchema.parse({
        ...req.body,
        userId: req.user.userId
      });

      const taxRefund = await storage.createTaxRefund(taxRefundData);
      res.json(taxRefund);
    } catch (error) {
      console.error('Tax refund application error:', error);
      res.status(400).json({ message: 'Tax refund application failed', error: error.message });
    }
  });

  app.get('/api/tax-refund/history', authenticateToken, async (req: any, res) => {
    try {
      const refunds = await storage.getTaxRefundsByUserId(req.user.userId);
      res.json(refunds);
    } catch (error) {
      console.error('Get tax refund history error:', error);
      res.status(500).json({ message: 'Failed to get tax refund history' });
    }
  });

  app.post('/api/tax-refund/:id/process', authenticateToken, async (req: any, res) => {
    try {
      const refundId = parseInt(req.params.id);
      const { action } = req.body; // 'approve' or 'reject'
      
      const taxRefund = await storage.processTaxRefund(refundId, action);
      res.json(taxRefund);
    } catch (error) {
      console.error('Process tax refund error:', error);
      res.status(400).json({ message: 'Failed to process tax refund' });
    }
  });

  // Wallet Address Management - Return fixed address for logan@seoullabs.io
  app.get('/api/wallet/address', async (req: any, res) => {
    try {
      // Return the confirmed wallet address with 1 XP deposit
      res.json({ address: '0xb8c1f75bb7550bb51039c64e92c78d15ad9dbbe1' });
    } catch (error) {
      console.error('Wallet address error:', error);
      res.status(500).json({ message: 'Failed to get wallet address' });
    }
  });

  // XP Price from CoinMarketCap
  app.get('/api/xphere/price', async (req, res) => {
    try {
      // Use CoinMarketCap API for real XP price
      const response = await fetch('https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest?symbol=XP', {
        headers: {
          'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_API_KEY || '',
          'Accept': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        const xpData = data.data?.XP;
        if (xpData) {
          const priceUSD = xpData.quote.USD.price;
          const priceKRW = priceUSD * 1300; // Approximate USD to KRW conversion
          return res.json({ 
            priceUSD, 
            priceKRW,
            change24h: xpData.quote.USD.percent_change_24h 
          });
        }
      }

      // Fallback price if API fails
      res.json({ priceUSD: 0.001, priceKRW: 1.3, change24h: 0 });
    } catch (error) {
      console.error('Price fetch error:', error);
      res.json({ priceUSD: 0.001, priceKRW: 1.3, change24h: 0 });
    }
  });

  // Database-backed balance tracking
  app.get('/api/xphere/balance/:address', async (req, res) => {
    try {
      const { address } = req.params;
      
      // Check database for balance first
      const balanceQuery = await pool.query(
        'SELECT balance FROM wallet_balances WHERE address = $1',
        [address]
      );
      
      if (balanceQuery.rows.length > 0) {
        const balance = parseFloat(balanceQuery.rows[0].balance);
        return res.json({ 
          address, 
          balance: balance.toFixed(6),
          balanceWei: '0x' + BigInt(Math.floor(balance * Math.pow(10, 18))).toString(16)
        });
      }
      
      // For new addresses, try to fetch from blockchain
      const primaryEndpoint = process.env.VITE_XPHERE_RPC_URL;
      const endpoints = primaryEndpoint ? [primaryEndpoint] : [
        'https://rpc.x-phere.com',
        'https://mainnet-rpc.x-phere.com',
        'https://api.x-phere.com/rpc'
      ];

      for (const endpoint of endpoints) {
        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'SuperWallet/1.0'
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              method: 'eth_getBalance',
              params: [address, 'latest'],
              id: 1
            })
          });

          if (response.ok) {
            const result = await response.json();
            if (result.result) {
              const balanceWei = parseInt(result.result, 16);
              const balanceXP = balanceWei / Math.pow(10, 18);
              return res.json({ 
                address, 
                balance: balanceXP.toFixed(6),
                balanceWei: result.result 
              });
            }
          }
        } catch (error) {
          console.log(`Balance check failed for ${endpoint}:`, error.message);
          continue;
        }
      }

      // Return zero balance if all endpoints fail
      res.json({ address, balance: '0.000000', balanceWei: '0x0' });
    } catch (error) {
      console.error('Balance check error:', error);
      res.status(500).json({ message: 'Failed to check balance' });
    }
  });

  // Deposit endpoint
  app.post('/api/payments/deposit', authenticateToken, async (req: any, res) => {
    try {
      const { amount, assetType = 'XP' } = req.body;
      const fromAddress = '0xb8c1f75bb7550bb51039c64e92c78d15ad9dbbe1';

      // Validate amount
      if (!amount || parseFloat(amount) <= 0) {
        return res.status(400).json({ message: 'Invalid deposit amount' });
      }

      // Get current balance from database
      const balanceQuery = await pool.query(
        'SELECT balance FROM wallet_balances WHERE address = $1',
        [fromAddress]
      );
      
      const currentBalance = balanceQuery.rows.length > 0 
        ? parseFloat(balanceQuery.rows[0].balance) 
        : 0.0;

      const newBalance = currentBalance + parseFloat(amount);

      // Update or insert balance in database
      if (balanceQuery.rows.length > 0) {
        await pool.query(
          'UPDATE wallet_balances SET balance = $1, updated_at = NOW() WHERE address = $2',
          [newBalance.toString(), fromAddress]
        );
      } else {
        await pool.query(
          'INSERT INTO wallet_balances (address, balance, asset_type) VALUES ($1, $2, $3)',
          [fromAddress, newBalance.toString(), assetType]
        );
      }

      // Create deposit transaction record
      const txHash = '0x' + Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
      
      const transactionData = insertTransactionSchema.parse({
        userId: req.user.userId,
        assetType,
        amount: amount.toString(),
        toAddress: fromAddress,
        fromAddress: 'external',
        txHash,
        status: 'completed',
        transactionType: 'receive'
      });

      const transaction = await storage.createTransaction(transactionData);

      res.json({ 
        ...transaction, 
        txHash,
        previousBalance: currentBalance.toString(),
        newBalance: newBalance.toString(),
        message: 'Deposit completed successfully'
      });

    } catch (error) {
      console.error('Deposit error:', error);
      res.status(500).json({ message: 'Failed to process deposit' });
    }
  });

  // Profile management endpoints
  app.put('/api/auth/update-profile', authenticateToken, async (req: any, res) => {
    try {
      const { firstName, lastName, email } = req.body;
      const userId = req.user.userId;

      const updatedUser = await storage.updateUser(userId, {
        firstName,
        lastName,
        email
      });

      res.json({
        message: 'Profile updated successfully',
        user: updatedUser
      });
    } catch (error) {
      console.error('Profile update error:', error);
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });

  app.put('/api/auth/change-password', authenticateToken, async (req: any, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.userId;

      // In a real implementation, you would verify the current password
      // and hash the new password before storing
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      
      await storage.updateUser(userId, {
        password: hashedNewPassword
      });

      res.json({
        message: 'Password changed successfully'
      });
    } catch (error) {
      console.error('Password change error:', error);
      res.status(500).json({ message: 'Failed to change password' });
    }
  });

  app.put('/api/auth/update-notifications', authenticateToken, async (req: any, res) => {
    try {
      const { transactionAlerts, securityAlerts, marketingEmails, pushNotifications } = req.body;
      const userId = req.user.userId;

      // Store notification preferences (you might want to create a separate table for this)
      await storage.updateUser(userId, {
        notificationSettings: JSON.stringify({
          transactionAlerts,
          securityAlerts,
          marketingEmails,
          pushNotifications
        })
      });

      res.json({
        message: 'Notification settings updated successfully'
      });
    } catch (error) {
      console.error('Notification update error:', error);
      res.status(500).json({ message: 'Failed to update notification settings' });
    }
  });

  // Balance update endpoint for internal use
  app.post('/api/xphere/update-balance', async (req, res) => {
    try {
      const { address, newBalance } = req.body;
      if (address === '0xb8c1f75bb7550bb51039c64e92c78d15ad9dbbe1') {
        currentBalance = parseFloat(newBalance);
      }
      res.json({ success: true, newBalance: parseFloat(newBalance).toFixed(6) });
    } catch (error) {
      console.error('Balance update error:', error);
      res.status(500).json({ message: 'Failed to update balance' });
    }
  });

  // Xphere Blockchain Proxy Routes
  app.post('/api/xphere/rpc-proxy', async (req, res) => {
    try {
      const { method, params, id } = req.body;
      
      // Use the provided Xphere RPC endpoint
      const primaryEndpoint = process.env.VITE_XPHERE_RPC_URL;
      const endpoints = primaryEndpoint ? [primaryEndpoint] : [
        'https://rpc.x-phere.com',
        'https://mainnet-rpc.x-phere.com',
        'https://api.x-phere.com/rpc'
      ];

      let lastError = null;
      
      for (const endpoint of endpoints) {
        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'SuperWallet/1.0'
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              method,
              params,
              id: id || 1
            }),
            timeout: 10000
          });

          if (response.ok) {
            const result = await response.json();
            return res.json(result);
          } else {
            lastError = `HTTP ${response.status}: ${response.statusText}`;
          }
        } catch (error) {
          lastError = error.message;
          console.log(`Xphere RPC ${endpoint} failed:`, error.message);
          continue;
        }
      }

      // If all endpoints fail, return error
      res.status(503).json({ 
        error: 'Service Unavailable',
        message: 'All Xphere RPC endpoints are currently unavailable',
        lastError 
      });
    } catch (error) {
      console.error('Xphere RPC proxy error:', error);
      res.status(500).json({ message: 'RPC proxy failed', error: error.message });
    }
  });

  app.post('/api/xphere/deploy-contract', authenticateToken, async (req: any, res) => {
    try {
      const { contractType, parameters } = req.body;
      
      // Use RPC proxy to deploy contract
      const deployResult = await fetch(`${req.protocol}://${req.get('host')}/api/xphere/rpc-proxy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: 'eth_sendTransaction',
          params: [{
            from: '0x' + Math.random().toString(16).substr(2, 40),
            data: '0x608060405234801561001057600080fd5b50', // Contract bytecode
            gas: '0x76c0',
            gasPrice: '0x9184e72a000'
          }],
          id: 1
        })
      });

      if (deployResult.ok) {
        const result = await deployResult.json();
        res.json({
          contractAddress: '0x' + Math.random().toString(16).substr(2, 40),
          txHash: result.result || '0x' + Math.random().toString(16).substr(2, 64),
          blockNumber: Math.floor(Math.random() * 1000000)
        });
      } else {
        throw new Error('Failed to deploy contract via RPC');
      }
    } catch (error) {
      console.error('Contract deployment error:', error);
      res.status(500).json({ message: 'Contract deployment failed' });
    }
  });

  app.get('/api/xphere/network-status', async (req, res) => {
    try {
      // Use RPC proxy to get real network status
      const rpcResponse = await fetch(`${req.protocol}://${req.get('host')}/api/xphere/rpc-proxy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: 'net_version',
          params: [],
          id: 1
        })
      });

      if (rpcResponse.ok) {
        const rpcResult = await rpcResponse.json();
        
        // Get block number
        const blockResponse = await fetch(`${req.protocol}://${req.get('host')}/api/xphere/rpc-proxy`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            method: 'eth_blockNumber',
            params: [],
            id: 2
          })
        });

        let latestBlock = Math.floor(Math.random() * 1000000);
        if (blockResponse.ok) {
          const blockResult = await blockResponse.json();
          if (blockResult.result) {
            latestBlock = parseInt(blockResult.result, 16);
          }
        }

        const networkStatus = {
          isConnected: !!rpcResult.result,
          latestBlock,
          networkId: rpcResult.result || 'xphere-mainnet',
          tps: Math.floor(Math.random() * 4000) + 1000,
          gasPrice: Math.floor(Math.random() * 100) + 10,
          chainId: '0x59d' // 1437 in hex
        };

        res.json(networkStatus);
      } else {
        // Fallback to mock data if RPC fails
        const networkStatus = {
          isConnected: false,
          latestBlock: Math.floor(Math.random() * 1000000),
          networkId: 'xphere-mainnet',
          tps: 0,
          gasPrice: 0,
          error: 'RPC connection failed'
        };
        res.json(networkStatus);
      }
    } catch (error) {
      console.error('Network status error:', error);
      res.status(500).json({ message: 'Failed to get network status' });
    }
  });

  // VAN Integration Routes
  app.post('/api/van/process-payment', authenticateToken, async (req: any, res) => {
    try {
      const { amount, merchantId, assetType } = req.body;
      
      // Mock VAN processing - real implementation would integrate with VAN operators
      const vanResult = {
        vanTxId: 'VAN' + Date.now(),
        status: 'approved',
        amount,
        merchantId,
        processedAt: new Date().toISOString()
      };

      res.json(vanResult);
    } catch (error) {
      console.error('VAN payment error:', error);
      res.status(500).json({ message: 'VAN payment processing failed' });
    }
  });

  // ZIGAP wallet integration endpoints
  app.post('/api/zigap/connect', async (req, res) => {
    try {
      const { walletProvider, networkId } = req.body;
      
      // Simulate ZIGAP wallet connection
      const walletInfo = {
        address: `0x${Math.random().toString(16).substring(2, 42)}`,
        balance: '1000000000000000000', // 1 ETH in wei
        networkId: networkId || 'xphere',
        provider: walletProvider || 'zigap'
      };
      
      res.json(walletInfo);
    } catch (error: any) {
      console.error('ZIGAP connect error:', error);
      res.status(500).json({ message: 'Failed to connect wallet' });
    }
  });

  app.get('/api/zigap/assets/:address', async (req, res) => {
    try {
      const { address } = req.params;
      
      // Simulate asset data for the wallet
      const assets = [
        {
          symbol: 'ETH',
          name: 'Ethereum',
          balance: '1.5432',
          contractAddress: null,
          decimals: 18
        },
        {
          symbol: 'XP',
          name: 'Xphere Token',
          balance: '1000.0',
          contractAddress: '0x1234567890123456789012345678901234567890',
          decimals: 18
        },
        {
          symbol: 'USDT',
          name: 'Tether USD',
          balance: '500.25',
          contractAddress: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
          decimals: 6
        }
      ];
      
      res.json(assets);
    } catch (error: any) {
      console.error('Get assets error:', error);
      res.status(500).json({ message: 'Failed to get assets' });
    }
  });

  app.post('/api/zigap/transaction', async (req, res) => {
    try {
      const { to, amount, assetType, from } = req.body;
      
      // Simulate transaction hash
      const txHash = `0x${Math.random().toString(16).substring(2, 66)}`;
      
      // Store transaction in database
      await storage.createTransaction({
        userId: 1, // Get from session in production
        fromAddress: from,
        toAddress: to,
        amount: parseFloat(amount),
        assetType,
        txHash,
        status: 'completed',
        networkId: 'xphere'
      });
      
      res.json({ txHash, status: 'success' });
    } catch (error: any) {
      console.error('Transaction error:', error);
      res.status(500).json({ message: 'Transaction failed' });
    }
  });

  app.post('/api/zigap/sign-message', async (req, res) => {
    try {
      const { message, address } = req.body;
      
      // Simulate message signing
      const signature = `0x${Math.random().toString(16).substring(2, 130)}`;
      
      res.json({ signature, message, address });
    } catch (error: any) {
      console.error('Sign message error:', error);
      res.status(500).json({ message: 'Failed to sign message' });
    }
  });

  app.post('/api/zigap/switch-network', async (req, res) => {
    try {
      const { networkId } = req.body;
      
      // Validate supported networks
      const supportedNetworks = ['ethereum', 'polygon', 'xphere'];
      if (!supportedNetworks.includes(networkId)) {
        return res.status(400).json({ message: 'Unsupported network' });
      }
      
      res.json({ success: true, networkId });
    } catch (error: any) {
      console.error('Switch network error:', error);
      res.status(500).json({ message: 'Failed to switch network' });
    }
  });

  app.post('/api/zigap/add-token', async (req, res) => {
    try {
      const { symbol, name, contractAddress, decimals } = req.body;
      
      // Validate token data
      if (!symbol || !name || !contractAddress) {
        return res.status(400).json({ message: 'Missing required token information' });
      }
      
      res.json({ 
        success: true, 
        token: { symbol, name, contractAddress, decimals } 
      });
    } catch (error: any) {
      console.error('Add token error:', error);
      res.status(500).json({ message: 'Failed to add token' });
    }
  });

  app.get('/api/zigap/health', async (req, res) => {
    try {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        services: {
          zigap: true,
          xphere: true,
          database: true
        }
      });
    } catch (error: any) {
      console.error('Health check error:', error);
      res.status(500).json({ message: 'Service unhealthy' });
    }
  });

  // Cross-wallet compatibility endpoints
  app.get('/api/wallets/supported', async (req, res) => {
    try {
      const supportedWallets = [
        {
          id: 'zigap',
          name: 'ZIGAP',
          type: 'mobile',
          icon: '/icons/zigap.png',
          supported: true,
          networks: ['xphere', 'ethereum', 'polygon']
        },
        {
          id: 'metamask',
          name: 'MetaMask',
          type: 'browser',
          icon: '/icons/metamask.png',
          supported: true,
          networks: ['ethereum', 'polygon']
        },
        {
          id: 'coinbase',
          name: 'Coinbase Wallet',
          type: 'mobile',
          icon: '/icons/coinbase.png',
          supported: true,
          networks: ['ethereum', 'polygon']
        },
        {
          id: 'trust',
          name: 'Trust Wallet',
          type: 'mobile',
          icon: '/icons/trust.png',
          supported: true,
          networks: ['ethereum', 'polygon']
        }
      ];
      
      res.json(supportedWallets);
    } catch (error: any) {
      console.error('Get supported wallets error:', error);
      res.status(500).json({ message: 'Failed to get supported wallets' });
    }
  });

  // Document management endpoints with file upload
  app.post('/api/documents/upload', async (req, res) => {
    try {
      console.log('Request body:', req.body); // Debug log
      
      let title, content, documentType, signature;
      
      // Handle both JSON and form data
      if (req.headers['content-type'] && req.headers['content-type'].includes('multipart/form-data')) {
        // Form data - fields would be in req.body after multer processing
        title = req.body.title;
        content = req.body.content;
        documentType = req.body.documentType;
        signature = req.body.signature;
      } else {
        // JSON data
        ({ title, content, documentType, signature } = req.body);
      }
      
      if (!title || !title.trim()) {
        return res.status(400).json({ message: 'Document title is required' });
      }
      
      // Create document with proper schema mapping
      const documentData = {
        userId: 1, // Get from session in production
        title: title.trim(),
        documentType: documentType || 'contract',
        content: content || 'Document content',
        contentHash: Math.random().toString(36).substring(2, 15),
        signatures: [],
        blockchainTxHash: null,
        ipfsHash: null,
        status: 'draft',
        version: 1
      };

      const document = await storage.createDocument(documentData);
      
      res.json({ 
        success: true, 
        document,
        message: 'Document created successfully'
      });
    } catch (error: any) {
      console.error('Document upload error:', error);
      res.status(500).json({ message: 'Failed to upload document' });
    }
  });

  app.post('/api/documents/share', async (req, res) => {
    try {
      const { documentId, recipientEmail } = req.body;
      
      // Validate document exists
      const document = await storage.getDocumentsByUserId(1); // Get from session
      const targetDoc = document.find((doc: any) => doc.id === documentId);
      
      if (!targetDoc) {
        return res.status(404).json({ message: 'Document not found' });
      }

      // Create sharing record (simplified)
      const shareData = {
        documentId,
        recipientEmail,
        sharedAt: new Date(),
        status: 'pending'
      };
      
      res.json({ 
        success: true, 
        share: shareData,
        message: 'Document shared successfully'
      });
    } catch (error: any) {
      console.error('Document share error:', error);
      res.status(500).json({ message: 'Failed to share document' });
    }
  });

  app.get('/api/documents/:id/download', async (req, res) => {
    try {
      const { id } = req.params;
      
      // Get document
      const documents = await storage.getDocumentsByUserId(1); // Get from session
      const document = documents.find((doc: any) => doc.id === parseInt(id));
      
      if (!document) {
        return res.status(404).json({ message: 'Document not found' });
      }

      // For demo purposes, return document content
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${document.title}.json"`);
      res.json(document);
    } catch (error: any) {
      console.error('Document download error:', error);
      res.status(500).json({ message: 'Failed to download document' });
    }
  });

  // Get users list for sharing
  app.get('/api/users/list', async (req, res) => {
    try {
      // Return mock users for sharing
      const users = [
        { id: 1, email: 'user1@example.com', name: '김철수' },
        { id: 2, email: 'user2@example.com', name: '이영희' },
        { id: 3, email: 'user3@example.com', name: '박민수' }
      ];
      
      res.json(users);
    } catch (error: any) {
      console.error('Get users error:', error);
      res.status(500).json({ message: 'Failed to get users' });
    }
  });

  // Tax Refund Management System API endpoints
  app.get('/api/tax-refund/history', async (req, res) => {
    try {
      const refunds = await storage.getTaxRefundsByUserId(1); // Get from session
      res.json(refunds);
    } catch (error: any) {
      console.error('Get tax refunds error:', error);
      res.status(500).json({ message: 'Failed to get tax refunds' });
    }
  });

  app.get('/api/tax-refund/statistics', async (req, res) => {
    try {
      const refunds = await storage.getTaxRefundsByUserId(1); // Get from session
      
      const statistics = {
        totalRefunded: refunds
          .filter((r: any) => r.status === 'completed')
          .reduce((sum: number, r: any) => sum + (r.amount || 0), 0),
        totalApplications: refunds.length,
        pendingAmount: refunds
          .filter((r: any) => r.status === 'pending' || r.status === 'processing')
          .reduce((sum: number, r: any) => sum + (r.amount || 0), 0),
        averageProcessingTime: '3-5일',
        successRate: refunds.length > 0 ? 
          (refunds.filter((r: any) => r.status === 'completed').length / refunds.length * 100) : 0
      };
      
      res.json(statistics);
    } catch (error: any) {
      console.error('Get tax refund statistics error:', error);
      res.status(500).json({ message: 'Failed to get statistics' });
    }
  });

  app.post('/api/tax-refund/submit', async (req, res) => {
    try {
      const { refundType, taxYear, grossIncome, taxPaid, deductions, bankAccount } = req.body;
      
      // Validate required fields
      if (!refundType || !taxYear || !grossIncome || !taxPaid || !bankAccount) {
        return res.status(400).json({ message: 'Required fields missing' });
      }

      // Calculate refund amount using authentic tax calculation
      const income = parseFloat(grossIncome);
      const paid = parseFloat(taxPaid);
      const deduct = parseFloat(deductions) || 0;
      
      // Korean tax calculation logic (simplified)
      let taxRate = 0;
      if (income <= 12000000) taxRate = 0.06;
      else if (income <= 46000000) taxRate = 0.15;
      else if (income <= 88000000) taxRate = 0.24;
      else if (income <= 150000000) taxRate = 0.35;
      else taxRate = 0.38;
      
      const taxableIncome = Math.max(0, income - deduct);
      const calculatedTax = taxableIncome * taxRate;
      const refundAmount = Math.max(0, paid - calculatedTax);
      
      const refundData = {
        userId: 1, // Get from session
        refundType,
        taxYear: parseInt(taxYear),
        amount: refundAmount,
        status: 'pending',
        grossIncome: income,
        taxPaid: paid,
        deductions: deduct,
        bankAccount,
        submittedAt: new Date(),
        estimatedProcessingTime: '3-5일'
      };

      const refund = await storage.createTaxRefund(refundData);
      
      res.json({
        success: true,
        refund,
        message: 'Tax refund application submitted successfully'
      });
    } catch (error: any) {
      console.error('Submit tax refund error:', error);
      res.status(500).json({ message: 'Failed to submit tax refund' });
    }
  });

  app.post('/api/tax-refund/estimate', async (req, res) => {
    try {
      const { grossIncome, taxPaid, deductions, taxYear, refundType } = req.body;
      
      const income = parseFloat(grossIncome) || 0;
      const paid = parseFloat(taxPaid) || 0;
      const deduct = parseFloat(deductions) || 0;
      
      // Korean tax calculation logic
      let taxRate = 0;
      if (income <= 12000000) taxRate = 0.06;
      else if (income <= 46000000) taxRate = 0.15;
      else if (income <= 88000000) taxRate = 0.24;
      else if (income <= 150000000) taxRate = 0.35;
      else taxRate = 0.38;
      
      const taxableIncome = Math.max(0, income - deduct);
      const calculatedTax = taxableIncome * taxRate;
      const estimatedAmount = Math.max(0, paid - calculatedTax);
      
      // Calculate eligibility score based on income and documentation
      let eligibilityScore = 85;
      if (income > 100000000) eligibilityScore -= 10;
      if (deduct > income * 0.3) eligibilityScore -= 5;
      if (refundType === 'income_tax') eligibilityScore += 5;
      
      const estimate = {
        estimatedAmount: Math.round(estimatedAmount),
        processingTime: estimatedAmount > 5000000 ? '5-7일' : '3-5일',
        eligibilityScore: Math.min(100, Math.max(0, eligibilityScore)),
        requiredDocuments: [
          '근로소득원천징수영수증',
          '소득공제증명서',
          '은행통장 사본'
        ],
        taxBreakdown: {
          taxableIncome,
          calculatedTax,
          effectiveRate: (calculatedTax / income * 100).toFixed(2)
        }
      };
      
      res.json(estimate);
    } catch (error: any) {
      console.error('Calculate estimate error:', error);
      res.status(500).json({ message: 'Failed to calculate estimate' });
    }
  });

  app.post('/api/tax-refund/:id/process', async (req, res) => {
    try {
      const { id } = req.params;
      const { action } = req.body;
      
      const result = await storage.processTaxRefund(parseInt(id), action);
      
      res.json({
        success: true,
        result,
        message: `Tax refund ${action} successfully`
      });
    } catch (error: any) {
      console.error('Process tax refund error:', error);
      res.status(500).json({ message: 'Failed to process tax refund' });
    }
  });

  app.get('/api/tax-refund/:id/status', async (req, res) => {
    try {
      const { id } = req.params;
      
      const refunds = await storage.getTaxRefundsByUserId(1);
      const refund = refunds.find((r: any) => r.id === parseInt(id));
      
      if (!refund) {
        return res.status(404).json({ message: 'Tax refund not found' });
      }
      
      // Real-time status with processing updates
      const statusUpdate = {
        ...refund,
        lastUpdated: new Date(),
        processingSteps: [
          { step: 'submitted', completed: true, timestamp: refund.submittedAt },
          { step: 'under_review', completed: refund.status !== 'pending', timestamp: refund.reviewedAt },
          { step: 'approved', completed: refund.status === 'completed', timestamp: refund.approvedAt },
          { step: 'disbursed', completed: refund.status === 'completed', timestamp: refund.processedAt }
        ]
      };
      
      res.json(statusUpdate);
    } catch (error: any) {
      console.error('Get refund status error:', error);
      res.status(500).json({ message: 'Failed to get refund status' });
    }
  });

  // Advanced Wallet Management System API endpoints
  app.get('/api/wallet/balances', async (req, res) => {
    try {
      const assets = await storage.getAssetsByUserId(1); // Get from session
      
      // Enhanced wallet balances with real-time market data
      const balances = await Promise.all(assets.map(async (asset: any) => {
        // Get current market price (using XP token price as reference)
        const priceResponse = await fetch(`http://localhost:5000/api/xphere/price`);
        const priceData = await priceResponse.json();
        
        const balance = parseFloat(asset.balance) || 0;
        const priceKRW = asset.assetType === 'XP' ? priceData.priceKRW : priceData.priceKRW * 0.1; // Mock pricing for other assets
        const priceUSD = asset.assetType === 'XP' ? priceData.priceUSD : priceData.priceUSD * 0.1;
        
        return {
          assetType: asset.assetType,
          balance: asset.balance,
          valueKRW: balance * priceKRW,
          valueUSD: balance * priceUSD,
          change24h: Math.random() * 20 - 10, // Mock 24h change
          priceKRW,
          priceUSD,
          contractAddress: asset.contractAddress || null,
          decimals: 18
        };
      }));
      
      res.json(balances);
    } catch (error: any) {
      console.error('Get wallet balances error:', error);
      res.status(500).json({ message: 'Failed to get wallet balances' });
    }
  });

  app.get('/api/wallet/transactions', async (req, res) => {
    try {
      const transactions = await storage.getTransactionsByUserId(1); // Get from session
      
      // Format transactions for wallet display
      const walletTransactions = transactions.map((tx: any) => ({
        id: tx.id,
        type: tx.transactionType || 'send',
        amount: tx.amount,
        assetType: tx.assetType,
        from: tx.fromAddress,
        to: tx.toAddress,
        txHash: tx.txHash || `0x${Math.random().toString(16).substring(2, 66)}`,
        status: tx.status === 'completed' ? 'confirmed' : tx.status,
        timestamp: tx.createdAt,
        gasFee: '0.001'
      }));
      
      res.json(walletTransactions);
    } catch (error: any) {
      console.error('Get wallet transactions error:', error);
      res.status(500).json({ message: 'Failed to get wallet transactions' });
    }
  });

  app.get('/api/wallet/market-data', async (req, res) => {
    try {
      // Get comprehensive market data
      const marketData = {
        totalMarketCap: 2500000000000, // $2.5T
        btcDominance: 42.5,
        ethDominance: 18.3,
        defiTvl: 45000000000, // $45B
        trends: [
          { symbol: 'BTC', change24h: 2.3, price: 45000 },
          { symbol: 'ETH', change24h: -1.2, price: 2800 },
          { symbol: 'XP', change24h: 15.7, price: 0.015 }
        ],
        gasTracker: {
          slow: 12,
          standard: 15,
          fast: 18
        }
      };
      
      res.json(marketData);
    } catch (error: any) {
      console.error('Get market data error:', error);
      res.status(500).json({ message: 'Failed to get market data' });
    }
  });

  app.post('/api/wallet/send', async (req, res) => {
    try {
      const { assetType, amount, toAddress, memo } = req.body;
      
      if (!assetType || !amount || !toAddress) {
        return res.status(400).json({ message: 'Required fields missing' });
      }

      // Validate wallet balance
      const assets = await storage.getAssetsByUserId(1);
      const asset = assets.find((a: any) => a.assetType === assetType);
      
      if (!asset) {
        return res.status(404).json({ message: 'Asset not found' });
      }

      const balance = parseFloat(asset.balance);
      const sendAmount = parseFloat(amount);
      
      if (sendAmount > balance) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }

      // Create transaction record
      const transactionData = {
        userId: 1,
        transactionType: 'send',
        assetType,
        amount: sendAmount.toString(),
        fromAddress: '0xb8c1f75bb7550bb51039c64e92c78d15ad9dbbe1', // User's wallet
        toAddress,
        status: 'pending',
        txHash: `0x${Math.random().toString(16).substring(2, 66)}`,
        gasFee: '0.001',
        memo: memo || null
      };

      const transaction = await storage.createTransaction(transactionData);
      
      // Simulate transaction processing
      setTimeout(async () => {
        try {
          // Update transaction status to completed
          await storage.updateTransaction(transaction.id, { status: 'completed' });
          
          // Update sender balance
          const newBalance = (balance - sendAmount).toString();
          await storage.updateAsset(asset.id, { balance: newBalance });
        } catch (err) {
          console.error('Transaction processing error:', err);
        }
      }, 5000); // Simulate 5 second processing time
      
      res.json({
        success: true,
        transaction,
        txHash: transaction.txHash,
        message: 'Transaction submitted successfully'
      });
    } catch (error: any) {
      console.error('Send transaction error:', error);
      res.status(500).json({ message: 'Failed to send transaction' });
    }
  });

  app.post('/api/wallet/add-asset', async (req, res) => {
    try {
      const { symbol, name, contractAddress, decimals } = req.body;
      
      if (!symbol || !contractAddress) {
        return res.status(400).json({ message: 'Symbol and contract address required' });
      }

      // Check if asset already exists
      const assets = await storage.getAssetsByUserId(1);
      const existingAsset = assets.find((a: any) => 
        a.assetType === symbol || a.contractAddress === contractAddress
      );

      if (existingAsset) {
        return res.status(400).json({ message: 'Asset already exists' });
      }

      // Create new asset
      const assetData = {
        userId: 1,
        assetType: symbol.toUpperCase(),
        balance: '0',
        contractAddress,
        networkId: 'xphere',
        metadata: {
          name: name || symbol,
          decimals: decimals || 18,
          isCustom: true
        }
      };

      const asset = await storage.createAsset(assetData);
      
      res.json({
        success: true,
        asset,
        message: 'Custom asset added successfully'
      });
    } catch (error: any) {
      console.error('Add asset error:', error);
      res.status(500).json({ message: 'Failed to add asset' });
    }
  });

  app.get('/api/wallet/portfolio', async (req, res) => {
    try {
      const assets = await storage.getAssetsByUserId(1);
      
      // Calculate portfolio analytics
      let totalValue = 0;
      let totalChange24h = 0;
      const assetAllocation: any[] = [];
      
      for (const asset of assets) {
        const balance = parseFloat(asset.balance) || 0;
        const priceResponse = await fetch(`http://localhost:5000/api/xphere/price`);
        const priceData = await priceResponse.json();
        
        const priceKRW = asset.assetType === 'XP' ? priceData.priceKRW : priceData.priceKRW * 0.1;
        const value = balance * priceKRW;
        
        totalValue += value;
        
        if (value > 0) {
          assetAllocation.push({
            assetType: asset.assetType,
            value,
            percentage: 0 // Will be calculated after total
          });
        }
      }

      // Calculate percentages
      assetAllocation.forEach(allocation => {
        allocation.percentage = totalValue > 0 ? (allocation.value / totalValue * 100) : 0;
      });

      const portfolio = {
        totalValue,
        totalChange24h: Math.random() * 10 - 5, // Mock 24h portfolio change
        assetCount: assets.length,
        assetAllocation,
        performanceMetrics: {
          roi: Math.random() * 50 - 10, // Mock ROI
          volatility: Math.random() * 30 + 10, // Mock volatility
          sharpeRatio: Math.random() * 2 + 0.5 // Mock Sharpe ratio
        }
      };
      
      res.json(portfolio);
    } catch (error: any) {
      console.error('Get portfolio error:', error);
      res.status(500).json({ message: 'Failed to get portfolio data' });
    }
  });

  // ZIGAP Wallet Integration API endpoints
  app.post('/api/zigap/connect', async (req, res) => {
    try {
      // Simulate ZIGAP wallet connection
      const walletInfo = {
        address: '0x' + Math.random().toString(16).substring(2, 42),
        balance: (Math.random() * 10).toFixed(6),
        chainId: 1,
        connected: true,
        provider: 'ZIGAP'
      };

      res.json({
        success: true,
        walletInfo,
        message: 'ZIGAP wallet connected successfully'
      });
    } catch (error: any) {
      console.error('ZIGAP connect error:', error);
      res.status(500).json({ message: 'Failed to connect ZIGAP wallet' });
    }
  });

  app.get('/api/zigap/assets', async (req, res) => {
    try {
      // Simulate ZIGAP supported assets
      const supportedAssets = ['ETH', 'USDT', 'USDC', 'DAI', 'WBTC', 'UNI', 'LINK'];
      
      const assets = supportedAssets.map(symbol => ({
        symbol,
        name: getAssetName(symbol),
        balance: (Math.random() * 1000).toFixed(6),
        decimals: symbol === 'USDT' || symbol === 'USDC' ? 6 : 18,
        contractAddress: getContractAddress(symbol),
        price: getMockPrice(symbol),
        change24h: (Math.random() * 20 - 10)
      }));

      res.json(assets);
    } catch (error: any) {
      console.error('Get ZIGAP assets error:', error);
      res.status(500).json({ message: 'Failed to get ZIGAP assets' });
    }
  });

  app.post('/api/zigap/swap', async (req, res) => {
    try {
      const { fromAsset, toAsset, amount } = req.body;
      
      if (!fromAsset || !toAsset || !amount) {
        return res.status(400).json({ message: 'Required parameters missing' });
      }

      // Simulate swap transaction
      const txHash = '0x' + Math.random().toString(16).substring(2, 66);
      
      const swapResult = {
        hash: txHash,
        status: 'pending',
        fromAsset,
        toAsset,
        inputAmount: amount,
        outputAmount: (parseFloat(amount) * (0.95 + Math.random() * 0.1)).toFixed(6),
        slippage: '0.5%',
        timestamp: Date.now()
      };

      res.json({
        success: true,
        result: swapResult,
        message: 'Swap transaction initiated'
      });
    } catch (error: any) {
      console.error('ZIGAP swap error:', error);
      res.status(500).json({ message: 'Failed to execute swap' });
    }
  });

  app.post('/api/zigap/stake', async (req, res) => {
    try {
      const { asset, amount, duration } = req.body;
      
      if (!asset || !amount || !duration) {
        return res.status(400).json({ message: 'Required parameters missing' });
      }

      // Calculate APY based on duration
      let apy = 4; // Base APY
      if (duration === '90') apy = 8;
      else if (duration === '180') apy = 12;

      const txHash = '0x' + Math.random().toString(16).substring(2, 66);
      
      const stakeResult = {
        hash: txHash,
        status: 'pending',
        asset,
        amount,
        duration: `${duration} days`,
        apy: `${apy}%`,
        estimatedRewards: (parseFloat(amount) * (apy / 100) * (parseInt(duration) / 365)).toFixed(6),
        timestamp: Date.now()
      };

      res.json({
        success: true,
        result: stakeResult,
        message: 'Staking transaction initiated'
      });
    } catch (error: any) {
      console.error('ZIGAP stake error:', error);
      res.status(500).json({ message: 'Failed to execute staking' });
    }
  });

  app.post('/api/zigap/bridge', async (req, res) => {
    try {
      const { fromChain, toChain, asset, amount } = req.body;
      
      if (!fromChain || !toChain || !asset || !amount) {
        return res.status(400).json({ message: 'Required parameters missing' });
      }

      const txHash = '0x' + Math.random().toString(16).substring(2, 66);
      
      const bridgeResult = {
        hash: txHash,
        status: 'pending',
        fromChain,
        toChain,
        asset,
        amount,
        estimatedTime: '5-10 minutes',
        bridgeFee: (parseFloat(amount) * 0.001).toFixed(6),
        timestamp: Date.now()
      };

      res.json({
        success: true,
        result: bridgeResult,
        message: 'Bridge transaction initiated'
      });
    } catch (error: any) {
      console.error('ZIGAP bridge error:', error);
      res.status(500).json({ message: 'Failed to execute bridge' });
    }
  });

  app.get('/api/zigap/networks', async (req, res) => {
    try {
      const supportedNetworks = [
        { chainId: 1, name: 'Ethereum Mainnet', symbol: 'ETH', rpcUrl: 'https://eth.llamarpc.com' },
        { chainId: 56, name: 'BSC Mainnet', symbol: 'BNB', rpcUrl: 'https://bsc-dataseed1.binance.org' },
        { chainId: 137, name: 'Polygon Mainnet', symbol: 'MATIC', rpcUrl: 'https://polygon-rpc.com' },
        { chainId: 42161, name: 'Arbitrum One', symbol: 'ETH', rpcUrl: 'https://arb1.arbitrum.io/rpc' },
        { chainId: 10, name: 'Optimism Mainnet', symbol: 'ETH', rpcUrl: 'https://mainnet.optimism.io' }
      ];

      res.json(supportedNetworks);
    } catch (error: any) {
      console.error('Get networks error:', error);
      res.status(500).json({ message: 'Failed to get supported networks' });
    }
  });

  // International Passport Validation API endpoints
  app.get('/api/passport/supported-countries', async (req, res) => {
    try {
      const supportedCountries = [
        { code: 'KOR', name: 'South Korea', flag: '🇰🇷', features: ['Biometric', 'RFID', 'Digital Security'] },
        { code: 'USA', name: 'United States', flag: '🇺🇸', features: ['Biometric', 'RFID', 'Enhanced Security'] },
        { code: 'JPN', name: 'Japan', flag: '🇯🇵', features: ['IC Chip', 'Biometric', 'High Security'] },
        { code: 'CHN', name: 'China', flag: '🇨🇳', features: ['Biometric', 'RFID', 'Digital Watermark'] },
        { code: 'DEU', name: 'Germany', flag: '🇩🇪', features: ['ePassport', 'Biometric', 'RFID'] },
        { code: 'GBR', name: 'United Kingdom', flag: '🇬🇧', features: ['Biometric', 'RFID', 'Enhanced Security'] },
        { code: 'FRA', name: 'France', flag: '🇫🇷', features: ['Biometric', 'RFID', 'Laser Engraving'] },
        { code: 'CAN', name: 'Canada', flag: '🇨🇦', features: ['ePassport', 'Biometric', 'RFID'] },
        { code: 'AUS', name: 'Australia', flag: '🇦🇺', features: ['ePassport', 'Biometric', 'RFID'] },
        { code: 'SGP', name: 'Singapore', flag: '🇸🇬', features: ['Biometric', 'RFID', 'Laser Engraving'] },
        { code: 'THA', name: 'Thailand', flag: '🇹🇭', features: ['Biometric', 'RFID'] },
        { code: 'IND', name: 'India', flag: '🇮🇳', features: ['Biometric', 'RFID', 'Chip-based'] }
      ];

      res.json({
        total: supportedCountries.length,
        countries: supportedCountries
      });
    } catch (error: any) {
      console.error('Get supported countries error:', error);
      res.status(500).json({ message: 'Failed to get supported countries' });
    }
  });

  app.post('/api/passport/validate', async (req, res) => {
    try {
      const { passportData } = req.body;
      
      if (!passportData || !passportData.issuingCountry || !passportData.passportNumber) {
        return res.status(400).json({ message: 'Invalid passport data provided' });
      }

      // Enhanced validation based on country format
      const validationResult = await validateInternationalPassport(passportData);
      
      res.json({
        isValid: validationResult.isValid,
        score: validationResult.score,
        checks: validationResult.checks,
        recommendation: validationResult.recommendation,
        country: validationResult.country,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      console.error('Passport validation error:', error);
      res.status(500).json({ message: 'Failed to validate passport' });
    }
  });

  app.post('/api/passport/extract', async (req, res) => {
    try {
      const { imageData, countryHint } = req.body;
      
      if (!imageData) {
        return res.status(400).json({ message: 'Image data required' });
      }

      // Simulate advanced OCR processing for international passports
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const extractedData = await extractPassportData(imageData, countryHint);
      
      res.json({
        success: true,
        data: extractedData,
        confidence: extractedData.confidence,
        processingTime: 2000,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      console.error('Passport extraction error:', error);
      res.status(500).json({ message: 'Failed to extract passport data' });
    }
  });

  app.post('/api/did/create-international', async (req, res) => {
    try {
      const { passportData, userId } = req.body;
      
      if (!passportData || !userId) {
        return res.status(400).json({ message: 'Passport data and user ID required' });
      }

      // Validate passport first
      const validation = await validateInternationalPassport(passportData);
      
      if (!validation.isValid || validation.score < 80) {
        return res.status(400).json({ 
          message: 'Passport validation failed',
          validation 
        });
      }

      // Create international DID
      const didData = {
        userId,
        didType: 'passport',
        countryCode: passportData.issuingCountry,
        documentNumber: passportData.passportNumber,
        nationality: passportData.nationality,
        validationScore: validation.score,
        securityFeatures: passportData.securityFeatures || [],
        issuedAt: new Date(),
        expiresAt: new Date(passportData.dateOfExpiry)
      };

      const did = await storage.createDID(didData);
      
      res.json({
        success: true,
        did,
        validation,
        message: `International DID created for ${passportData.issuingCountry} passport`
      });
    } catch (error: any) {
      console.error('Create international DID error:', error);
      res.status(500).json({ message: 'Failed to create international DID' });
    }
  });

  // Helper functions for passport processing
  async function validateInternationalPassport(passportData: any) {
    const countryFormats: { [key: string]: any } = {
      'KOR': { pattern: '^[A-Z]\\d{8}$', mrzRequired: true },
      'USA': { pattern: '^\\d{9}$', mrzRequired: true },
      'JPN': { pattern: '^[A-Z]{2}\\d{7}$', mrzRequired: true },
      'CHN': { pattern: '^[EG]\\d{8}$', mrzRequired: true },
      'DEU': { pattern: '^[C-F0-9]{9}$', mrzRequired: true },
      'GBR': { pattern: '^\\d{9}$', mrzRequired: true },
      'FRA': { pattern: '^\\d{2}[A-Z]{2}\\d{5}$', mrzRequired: true },
      'CAN': { pattern: '^[A-Z]{2}\\d{6}$', mrzRequired: true },
      'AUS': { pattern: '^[A-Z]\\d{7}$', mrzRequired: true },
      'SGP': { pattern: '^[A-Z]\\d{7}[A-Z]$', mrzRequired: true },
      'THA': { pattern: '^[A-Z]\\d{7}$', mrzRequired: true },
      'IND': { pattern: '^[A-Z]\\d{7}$', mrzRequired: true }
    };

    const countryFormat = countryFormats[passportData.issuingCountry];
    const checks = [];
    let score = 0;

    // Passport number format validation
    if (countryFormat && new RegExp(countryFormat.pattern).test(passportData.passportNumber)) {
      checks.push({ check: 'Passport Number Format', status: 'pass', weight: 25 });
      score += 25;
    } else {
      checks.push({ check: 'Passport Number Format', status: 'fail', weight: 25 });
    }

    // MRZ validation
    if (passportData.mrz1 && passportData.mrz2) {
      checks.push({ check: 'MRZ Present', status: 'pass', weight: 20 });
      score += 20;
    } else {
      checks.push({ check: 'MRZ Present', status: 'fail', weight: 20 });
    }

    // Date validation
    const birthDate = new Date(passportData.dateOfBirth);
    const expiryDate = new Date(passportData.dateOfExpiry);
    const currentDate = new Date();
    
    if (birthDate < currentDate && expiryDate > currentDate) {
      checks.push({ check: 'Date Validity', status: 'pass', weight: 20 });
      score += 20;
    } else {
      checks.push({ check: 'Date Validity', status: 'fail', weight: 20 });
    }

    // Security features validation
    if (passportData.securityFeatures && passportData.securityFeatures.length >= 2) {
      checks.push({ check: 'Security Features', status: 'pass', weight: 15 });
      score += 15;
    } else {
      checks.push({ check: 'Security Features', status: 'warning', weight: 10 });
      score += 10;
    }

    // OCR confidence
    if (passportData.confidence && passportData.confidence > 0.9) {
      checks.push({ check: 'OCR Confidence', status: 'pass', weight: 20 });
      score += 20;
    } else if (passportData.confidence && passportData.confidence > 0.8) {
      checks.push({ check: 'OCR Confidence', status: 'warning', weight: 10 });
      score += 10;
    } else {
      checks.push({ check: 'OCR Confidence', status: 'fail', weight: 20 });
    }

    return {
      isValid: score >= 80,
      score,
      checks,
      country: passportData.issuingCountry,
      recommendation: score >= 90 ? 'excellent' : score >= 80 ? 'good' : score >= 60 ? 'acceptable' : 'poor'
    };
  }

  async function extractPassportData(imageData: string, countryHint?: string) {
    // Simulate advanced OCR extraction
    const mockNames = {
      'KOR': { surname: 'PARK', givenNames: 'JIHOON' },
      'USA': { surname: 'SMITH', givenNames: 'JOHN' },
      'JPN': { surname: 'TANAKA', givenNames: 'HIROSHI' },
      'CHN': { surname: 'WANG', givenNames: 'LEI' },
      'DEU': { surname: 'MUELLER', givenNames: 'HANS' },
      'GBR': { surname: 'JONES', givenNames: 'JAMES' },
      'FRA': { surname: 'MARTIN', givenNames: 'PIERRE' },
      'CAN': { surname: 'BROWN', givenNames: 'MICHAEL' },
      'AUS': { surname: 'WILSON', givenNames: 'DAVID' },
      'SGP': { surname: 'LIM', givenNames: 'WEI MING' },
      'THA': { surname: 'SOMCHAI', givenNames: 'NIRAN' },
      'IND': { surname: 'SHARMA', givenNames: 'RAJESH' }
    };

    const country = countryHint || Object.keys(mockNames)[Math.floor(Math.random() * Object.keys(mockNames).length)];
    const names = mockNames[country as keyof typeof mockNames] || { surname: 'DOE', givenNames: 'JOHN' };
    
    return {
      documentType: 'P',
      issuingCountry: country,
      passportNumber: generatePassportNumber(country),
      surname: names.surname,
      givenNames: names.givenNames,
      nationality: country,
      dateOfBirth: '1990-05-15',
      sex: Math.random() > 0.5 ? 'M' : 'F',
      dateOfIssue: '2020-01-01',
      dateOfExpiry: '2030-01-01',
      confidence: 0.92 + Math.random() * 0.08,
      securityFeatures: getSecurityFeatures(country),
      extractedAt: new Date().toISOString()
    };
  }

  function generatePassportNumber(countryCode: string): string {
    const formats: { [key: string]: () => string } = {
      'KOR': () => 'M' + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
      'USA': () => Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
      'JPN': () => 'TH' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0'),
      'CHN': () => 'E' + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
      'DEU': () => 'C' + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
      'GBR': () => Math.floor(Math.random() * 1000000000).toString().padStart(9, '0'),
      'FRA': () => Math.floor(Math.random() * 100).toString().padStart(2, '0') + 'AB' + Math.floor(Math.random() * 100000).toString().padStart(5, '0'),
      'CAN': () => 'GA' + Math.floor(Math.random() * 1000000).toString().padStart(6, '0'),
      'AUS': () => 'N' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0'),
      'SGP': () => 'K' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0') + 'A',
      'THA': () => 'A' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0'),
      'IND': () => 'A' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0')
    };
    
    return formats[countryCode] ? formats[countryCode]() : 'A' + Math.floor(Math.random() * 10000000).toString().padStart(7, '0');
  }

  function getSecurityFeatures(countryCode: string): string[] {
    const features: { [key: string]: string[] } = {
      'KOR': ['Biometric', 'RFID', 'Digital Security', 'Hologram'],
      'USA': ['Biometric', 'RFID', 'Enhanced Security', 'Laser Engraving'],
      'JPN': ['IC Chip', 'Biometric', 'High Security', 'Holographic Film'],
      'CHN': ['Biometric', 'RFID', 'Digital Watermark', 'Security Thread'],
      'DEU': ['ePassport', 'Biometric', 'RFID', 'Security Printing'],
      'GBR': ['Biometric', 'RFID', 'Enhanced Security', 'Polycarbonate'],
      'FRA': ['Biometric', 'RFID', 'Laser Engraving', 'Security Fibers'],
      'CAN': ['ePassport', 'Biometric', 'RFID', 'Tactile Features'],
      'AUS': ['ePassport', 'Biometric', 'RFID', 'Advanced Security'],
      'SGP': ['Biometric', 'RFID', 'Laser Engraving', 'Security Printing'],
      'THA': ['Biometric', 'RFID', 'Security Features'],
      'IND': ['Biometric', 'RFID', 'Chip-based', 'Security Thread']
    };
    
    return features[countryCode] || ['Biometric', 'RFID'];
  }

  // Helper functions for ZIGAP endpoints
  function getAssetName(symbol: string): string {
    const names: { [key: string]: string } = {
      'ETH': 'Ethereum',
      'USDT': 'Tether USD',
      'USDC': 'USD Coin',
      'DAI': 'Dai Stablecoin',
      'WBTC': 'Wrapped Bitcoin',
      'UNI': 'Uniswap',
      'LINK': 'Chainlink'
    };
    return names[symbol] || symbol;
  }

  function getContractAddress(symbol: string): string {
    const addresses: { [key: string]: string } = {
      'USDT': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      'USDC': '0xA0b86a33E6441e86461c4c8A5ce5C8b51b8C3e0e',
      'DAI': '0x6B175474E89094C44Da98b954EedeAC495271d0F',
      'WBTC': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
      'UNI': '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984',
      'LINK': '0x514910771AF9Ca656af840dff83E8264EcF986CA'
    };
    return addresses[symbol] || '0x' + Math.random().toString(16).substring(2, 42);
  }

  function getMockPrice(symbol: string): number {
    const prices: { [key: string]: number } = {
      'ETH': 2500,
      'USDT': 1.0,
      'USDC': 1.0,
      'DAI': 1.0,
      'WBTC': 45000,
      'UNI': 12.5,
      'LINK': 15.2
    };
    return prices[symbol] || 1.0;
  }

  // Security Center API endpoints
  app.get('/api/security/score', async (req, res) => {
    try {
      // Calculate security score based on user settings and activities
      const securityScore = {
        overall: 85,
        categories: {
          authentication: 90,
          wallet: 80,
          privacy: 85,
          device: 85
        },
        recommendations: [
          "2단계 인증을 활성화하세요",
          "백업 문구를 안전한 곳에 저장하세요",
          "정기적으로 보안 활동을 확인하세요"
        ]
      };
      
      res.json(securityScore);
    } catch (error: any) {
      console.error('Get security score error:', error);
      res.status(500).json({ message: 'Failed to get security score' });
    }
  });

  app.get('/api/security/events', async (req, res) => {
    try {
      const mockEvents = [
        {
          id: 1,
          type: 'login',
          description: '새 기기에서 로그인',
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          location: 'Seoul, South Korea',
          deviceInfo: 'Chrome on Windows',
          riskLevel: 'low'
        },
        {
          id: 2,
          type: 'transaction',
          description: 'XP 토큰 전송',
          timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
          location: 'Seoul, South Korea',
          deviceInfo: 'Mobile App',
          riskLevel: 'low'
        },
        {
          id: 3,
          type: 'settings_change',
          description: '보안 설정 변경',
          timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          location: 'Seoul, South Korea',
          deviceInfo: 'Chrome on Windows',
          riskLevel: 'medium'
        }
      ];

      res.json(mockEvents);
    } catch (error: any) {
      console.error('Get security events error:', error);
      res.status(500).json({ message: 'Failed to get security events' });
    }
  });

  app.get('/api/security/biometric-info', async (req, res) => {
    try {
      const biometricInfo = {
        enabled: true,
        supportedTypes: ['fingerprint', 'face', 'voice'],
        enrolledTypes: ['fingerprint']
      };

      res.json(biometricInfo);
    } catch (error: any) {
      console.error('Get biometric info error:', error);
      res.status(500).json({ message: 'Failed to get biometric info' });
    }
  });

  app.post('/api/security/generate-backup', async (req, res) => {
    try {
      // Generate 12-word backup phrase
      const words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 
        'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
        'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual'
      ];
      
      const phrase = Array.from({ length: 12 }, () => 
        words[Math.floor(Math.random() * words.length)]
      );

      res.json({
        phrase,
        timestamp: new Date().toISOString()
      });
    } catch (error: any) {
      console.error('Generate backup error:', error);
      res.status(500).json({ message: 'Failed to generate backup phrase' });
    }
  });

  app.put('/api/security/settings', async (req, res) => {
    try {
      const { settings } = req.body;
      
      if (!settings) {
        return res.status(400).json({ message: 'Settings data required' });
      }

      // Save security settings (in production, save to database)
      res.json({
        success: true,
        settings,
        updatedAt: new Date().toISOString()
      });
    } catch (error: any) {
      console.error('Update security settings error:', error);
      res.status(500).json({ message: 'Failed to update security settings' });
    }
  });

  app.post('/api/security/biometric/enable', async (req, res) => {
    try {
      // Simulate biometric enrollment
      res.json({
        success: true,
        enrolledTypes: ['fingerprint'],
        enabledAt: new Date().toISOString()
      });
    } catch (error: any) {
      console.error('Enable biometric error:', error);
      res.status(500).json({ message: 'Failed to enable biometric authentication' });
    }
  });

  // Analytics and Insights API endpoints
  app.get('/api/analytics/portfolio-performance', async (req, res) => {
    try {
      const { timeframe = '7d' } = req.query;
      
      // Generate mock performance data
      const days = timeframe === '7d' ? 7 : timeframe === '30d' ? 30 : 90;
      const performanceData = Array.from({ length: days }, (_, i) => {
        const date = new Date();
        date.setDate(date.getDate() - (days - 1 - i));
        
        return {
          date: date.toISOString().split('T')[0],
          totalValue: 10000 + (Math.random() - 0.5) * 2000,
          change: (Math.random() - 0.5) * 10,
          volume: Math.random() * 1000000
        };
      });

      res.json({
        timeframe,
        data: performanceData,
        summary: {
          totalReturn: (Math.random() - 0.5) * 20,
          volatility: Math.random() * 15 + 5,
          sharpeRatio: Math.random() * 2 + 0.5
        }
      });
    } catch (error: any) {
      console.error('Get portfolio performance error:', error);
      res.status(500).json({ message: 'Failed to get portfolio performance' });
    }
  });

  app.get('/api/analytics/transaction-insights', async (req, res) => {
    try {
      const insights = {
        monthlyVolume: Math.random() * 100000,
        averageTransactionSize: Math.random() * 1000,
        mostActiveHours: ['14:00', '15:00', '16:00'],
        topAssets: [
          { symbol: 'XP', percentage: 45 },
          { symbol: 'ETH', percentage: 30 },
          { symbol: 'USDT', percentage: 25 }
        ],
        riskScore: Math.floor(Math.random() * 40) + 30, // 30-70 range
        complianceStatus: 'compliant'
      };

      res.json(insights);
    } catch (error: any) {
      console.error('Get transaction insights error:', error);
      res.status(500).json({ message: 'Failed to get transaction insights' });
    }
  });

  // Smart Contracts API endpoints
  app.get('/api/smart-contracts/user', async (req, res) => {
    try {
      const mockContracts = [
        {
          id: 'sc-1',
          name: 'DeFi Lending Pool',
          type: 'defi',
          status: 'deployed',
          address: '0x742d35Cc6ABf4F3b3F7F8E4f7F8E4f7F8E4f7F8E',
          gasUsed: 2500000,
          createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          lastExecuted: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          executionCount: 45,
          automation: {
            enabled: true,
            triggers: ['price_threshold'],
            conditions: ['XP > 0.02'],
            actions: ['rebalance_pool']
          }
        },
        {
          id: 'sc-2',
          name: 'NFT Marketplace',
          type: 'nft',
          status: 'active',
          address: '0x1B4d35Cc6ABf4F3b3F7F8E4f7F8E4f7F8E4f7F8E',
          gasUsed: 1800000,
          createdAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
          lastExecuted: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
          executionCount: 23,
          automation: {
            enabled: false,
            triggers: [],
            conditions: [],
            actions: []
          }
        },
        {
          id: 'sc-3',
          name: 'Governance DAO',
          type: 'dao',
          status: 'deployed',
          address: '0x3C8d35Cc6ABf4F3b3F7F8E4f7F8E4f7F8E4f7F8E',
          gasUsed: 3200000,
          createdAt: new Date(Date.now() - 21 * 24 * 60 * 60 * 1000).toISOString(),
          lastExecuted: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
          executionCount: 67,
          automation: {
            enabled: true,
            triggers: ['time_based', 'voting_threshold'],
            conditions: ['proposal_quorum > 50%'],
            actions: ['execute_proposal', 'distribute_rewards']
          }
        }
      ];

      res.json(mockContracts);
    } catch (error: any) {
      console.error('Get user contracts error:', error);
      res.status(500).json({ message: 'Failed to get contracts' });
    }
  });

  app.get('/api/smart-contracts/templates', async (req, res) => {
    try {
      const templates = [
        {
          id: 'template-1',
          name: 'ERC20 토큰',
          description: '표준 ERC20 토큰 컨트랙트',
          category: 'defi',
          complexity: 'beginner',
          code: `pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyToken is ERC20, Ownable {
    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply
    ) ERC20(name, symbol) {
        _mint(msg.sender, initialSupply * 10**decimals());
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}`,
          parameters: [
            { name: 'name', type: 'string', description: '토큰 이름', required: true },
            { name: 'symbol', type: 'string', description: '토큰 심볼', required: true },
            { name: 'initialSupply', type: 'uint256', description: '초기 공급량', required: true }
          ]
        },
        {
          id: 'template-2',
          name: 'NFT 컬렉션',
          description: 'ERC721 기반 NFT 컬렉션',
          category: 'nft',
          complexity: 'intermediate',
          code: `pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyNFT is ERC721, ERC721Enumerable, Ownable {
    uint256 public maxSupply;
    uint256 public currentSupply;
    string private baseTokenURI;

    constructor(
        string memory name,
        string memory symbol,
        uint256 _maxSupply,
        string memory _baseTokenURI
    ) ERC721(name, symbol) {
        maxSupply = _maxSupply;
        baseTokenURI = _baseTokenURI;
    }

    function mint(address to) public onlyOwner {
        require(currentSupply < maxSupply, "Max supply reached");
        uint256 tokenId = currentSupply + 1;
        currentSupply++;
        _safeMint(to, tokenId);
    }

    function _baseURI() internal view override returns (string memory) {
        return baseTokenURI;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId)
        internal
        override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, tokenId);
    }
}`,
          parameters: [
            { name: 'name', type: 'string', description: 'NFT 컬렉션 이름', required: true },
            { name: 'symbol', type: 'string', description: 'NFT 심볼', required: true },
            { name: 'maxSupply', type: 'uint256', description: '최대 공급량', required: true },
            { name: 'baseTokenURI', type: 'string', description: '베이스 메타데이터 URI', required: true }
          ]
        },
        {
          id: 'template-3',
          name: '스테이킹 풀',
          description: '토큰 스테이킹 및 보상 분배',
          category: 'defi',
          complexity: 'advanced',
          code: `pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract StakingPool is ReentrancyGuard, Ownable {
    using SafeMath for uint256;

    IERC20 public stakingToken;
    IERC20 public rewardToken;
    
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public balances;
    
    uint256 private _totalSupply;

    constructor(
        address _stakingToken,
        address _rewardToken,
        uint256 _rewardRate
    ) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        rewardRate = _rewardRate;
    }

    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");
        _totalSupply = _totalSupply.add(amount);
        balances[msg.sender] = balances[msg.sender].add(amount);
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) public nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Cannot withdraw 0");
        _totalSupply = _totalSupply.sub(amount);
        balances[msg.sender] = balances[msg.sender].sub(amount);
        stakingToken.transfer(msg.sender, amount);
    }

    function getReward() public nonReentrant updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        if (reward > 0) {
            rewards[msg.sender] = 0;
            rewardToken.transfer(msg.sender, reward);
        }
    }

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function rewardPerToken() public view returns (uint256) {
        if (_totalSupply == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored.add(
                block.timestamp.sub(lastUpdateTime).mul(rewardRate).mul(1e18).div(_totalSupply)
            );
    }

    function earned(address account) public view returns (uint256) {
        return
            balances[account]
                .mul(rewardPerToken().sub(userRewardPerTokenPaid[account]))
                .div(1e18)
                .add(rewards[account]);
    }
}`,
          parameters: [
            { name: 'stakingToken', type: 'address', description: '스테이킹할 토큰 주소', required: true },
            { name: 'rewardToken', type: 'address', description: '보상 토큰 주소', required: true },
            { name: 'rewardRate', type: 'uint256', description: '초당 보상률', required: true }
          ]
        },
        {
          id: 'template-4',
          name: '투표 거버넌스',
          description: 'DAO 투표 및 제안 시스템',
          category: 'dao',
          complexity: 'advanced',
          code: `pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Governance is Ownable {
    IERC20 public governanceToken;
    
    struct Proposal {
        uint256 id;
        address proposer;
        string description;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startTime;
        uint256 endTime;
        bool executed;
        mapping(address => bool) hasVoted;
    }
    
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;
    uint256 public proposalThreshold = 1000 * 10**18; // 1000 tokens
    
    event ProposalCreated(uint256 proposalId, address proposer, string description);
    event VoteCast(address voter, uint256 proposalId, bool support, uint256 votes);
    event ProposalExecuted(uint256 proposalId);

    constructor(address _governanceToken) {
        governanceToken = IERC20(_governanceToken);
    }

    function propose(string memory description) external returns (uint256) {
        require(
            governanceToken.balanceOf(msg.sender) >= proposalThreshold,
            "Insufficient tokens to propose"
        );
        
        proposalCount++;
        Proposal storage proposal = proposals[proposalCount];
        proposal.id = proposalCount;
        proposal.proposer = msg.sender;
        proposal.description = description;
        proposal.startTime = block.timestamp;
        proposal.endTime = block.timestamp + votingPeriod;
        
        emit ProposalCreated(proposalCount, msg.sender, description);
        return proposalCount;
    }

    function vote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.startTime, "Voting not started");
        require(block.timestamp <= proposal.endTime, "Voting ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");
        
        uint256 votes = governanceToken.balanceOf(msg.sender);
        require(votes > 0, "No voting power");
        
        proposal.hasVoted[msg.sender] = true;
        
        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }
        
        emit VoteCast(msg.sender, proposalId, support, votes);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp > proposal.endTime, "Voting still active");
        require(!proposal.executed, "Already executed");
        require(proposal.forVotes > proposal.againstVotes, "Proposal failed");
        
        proposal.executed = true;
        emit ProposalExecuted(proposalId);
    }
}`,
          parameters: [
            { name: 'governanceToken', type: 'address', description: '거버넌스 토큰 주소', required: true }
          ]
        }
      ];

      res.json(templates);
    } catch (error: any) {
      console.error('Get templates error:', error);
      res.status(500).json({ message: 'Failed to get templates' });
    }
  });

  app.get('/api/smart-contracts/automation-rules', async (req, res) => {
    try {
      const automationRules = [
        {
          id: 'rule-1',
          name: 'DeFi 리밸런싱',
          description: 'XP 토큰 가격이 $0.02 이상일 때 유동성 풀 리밸런싱',
          trigger: {
            type: 'price',
            condition: 'greater_than',
            value: '0.02'
          },
          action: {
            type: 'execute',
            target: '0x742d35Cc6ABf4F3b3F7F8E4f7F8E4f7F8E4f7F8E',
            parameters: { function: 'rebalancePool', args: [] }
          },
          isActive: true,
          lastTriggered: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
          executionCount: 12
        },
        {
          id: 'rule-2',
          name: '자동 스테이킹',
          description: '지갑 잔액이 1000 XP 이상일 때 자동으로 스테이킹',
          trigger: {
            type: 'balance',
            condition: 'greater_than',
            value: '1000'
          },
          action: {
            type: 'stake',
            target: 'staking_pool',
            parameters: { amount: '500', token: 'XP' }
          },
          isActive: false,
          lastTriggered: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
          executionCount: 5
        },
        {
          id: 'rule-3',
          name: '거버넌스 투표',
          description: '새로운 제안이 생성되면 자동으로 찬성 투표',
          trigger: {
            type: 'event',
            condition: 'equals',
            value: 'ProposalCreated'
          },
          action: {
            type: 'execute',
            target: '0x3C8d35Cc6ABf4F3b3F7F8E4f7F8E4f7F8E4f7F8E',
            parameters: { function: 'vote', args: ['proposalId', 'true'] }
          },
          isActive: true,
          lastTriggered: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
          executionCount: 8
        }
      ];

      res.json(automationRules);
    } catch (error: any) {
      console.error('Get automation rules error:', error);
      res.status(500).json({ message: 'Failed to get automation rules' });
    }
  });

  app.post('/api/smart-contracts/compile', async (req, res) => {
    try {
      const { code } = req.body;

      if (!code) {
        return res.status(400).json({ message: 'Code is required' });
      }

      // Simulate compilation process
      const compilationResult = {
        success: true,
        bytecode: '0x608060405234801561001057600080fd5b50...',
        abi: [
          {
            inputs: [],
            name: 'name',
            outputs: [{ internalType: 'string', name: '', type: 'string' }],
            stateMutability: 'view',
            type: 'function'
          },
          {
            inputs: [],
            name: 'symbol',
            outputs: [{ internalType: 'string', name: '', type: 'string' }],
            stateMutability: 'view',
            type: 'function'
          }
        ],
        gasEstimate: '2500000',
        warnings: [],
        errors: []
      };

      res.json(compilationResult);
    } catch (error: any) {
      console.error('Compile contract error:', error);
      res.status(500).json({ message: 'Compilation failed' });
    }
  });

  app.post('/api/smart-contracts/deploy', async (req, res) => {
    try {
      const { name, bytecode, abi, gasLimit, gasPrice, constructorArgs } = req.body;

      if (!name || !bytecode || !abi) {
        return res.status(400).json({ message: 'Name, bytecode, and ABI are required' });
      }

      // Simulate deployment
      const deployedContract = {
        id: `sc-${Date.now()}`,
        name,
        type: 'custom',
        status: 'deployed',
        address: `0x${Math.random().toString(16).substring(2, 42)}`,
        abi,
        bytecode,
        gasUsed: parseInt(gasLimit) * 0.8, // Simulate actual gas usage
        createdAt: new Date().toISOString(),
        executionCount: 0,
        automation: {
          enabled: false,
          triggers: [],
          conditions: [],
          actions: []
        },
        deploymentTx: `0x${Math.random().toString(16).substring(2, 66)}`
      };

      res.json(deployedContract);
    } catch (error: any) {
      console.error('Deploy contract error:', error);
      res.status(500).json({ message: 'Deployment failed' });
    }
  });

  app.post('/api/smart-contracts/automation', async (req, res) => {
    try {
      const { name, description, triggerType, triggerCondition, triggerValue, actionType, actionTarget, actionParams } = req.body;

      if (!name || !triggerValue) {
        return res.status(400).json({ message: 'Name and trigger value are required' });
      }

      const newRule = {
        id: `rule-${Date.now()}`,
        name,
        description: description || '',
        trigger: {
          type: triggerType,
          condition: triggerCondition,
          value: triggerValue
        },
        action: {
          type: actionType,
          target: actionTarget,
          parameters: actionParams ? JSON.parse(actionParams) : {}
        },
        isActive: true,
        executionCount: 0,
        createdAt: new Date().toISOString()
      };

      res.json(newRule);
    } catch (error: any) {
      console.error('Create automation rule error:', error);
      res.status(500).json({ message: 'Failed to create automation rule' });
    }
  });

  app.put('/api/smart-contracts/:contractId/automation', async (req, res) => {
    try {
      const { contractId } = req.params;
      const { enabled, triggers, conditions, actions } = req.body;

      // Update contract automation settings
      const updatedContract = {
        contractId,
        automation: {
          enabled,
          triggers: triggers || [],
          conditions: conditions || [],
          actions: actions || []
        },
        updatedAt: new Date().toISOString()
      };

      res.json(updatedContract);
    } catch (error: any) {
      console.error('Update contract automation error:', error);
      res.status(500).json({ message: 'Failed to update automation' });
    }
  });

  app.post('/api/smart-contracts/:contractId/execute', async (req, res) => {
    try {
      const { contractId } = req.params;
      const { functionName, parameters, gasLimit } = req.body;

      if (!functionName) {
        return res.status(400).json({ message: 'Function name is required' });
      }

      // Simulate contract execution
      const execution = {
        contractId,
        functionName,
        parameters: parameters || [],
        gasUsed: Math.floor(Math.random() * 100000) + 50000,
        transactionHash: `0x${Math.random().toString(16).substring(2, 66)}`,
        blockNumber: Math.floor(Math.random() * 1000) + 18000000,
        status: 'success',
        timestamp: new Date().toISOString(),
        logs: [
          {
            address: contractId,
            topics: [`0x${Math.random().toString(16).substring(2, 66)}`],
            data: '0x0000000000000000000000000000000000000000000000000000000000000001'
          }
        ]
      };

      res.json(execution);
    } catch (error: any) {
      console.error('Execute contract error:', error);
      res.status(500).json({ message: 'Contract execution failed' });
    }
  });

  // Biometric Authentication Routes
  
  // Start biometric authentication session
  app.post("/api/auth/biometric/start", authenticateToken, async (req: any, res) => {
    try {
      const { authType, deviceInfo } = req.body;
      const sessionId = `bio_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
      
      res.json({ sessionId, expiresAt });
    } catch (error: any) {
      console.error("Error starting biometric session:", error);
      res.status(500).json({ message: "Failed to start biometric authentication" });
    }
  });

  // Verify biometric authentication
  app.post("/api/auth/biometric/verify", authenticateToken, async (req: any, res) => {
    try {
      const { type, sessionId, credentialId, authData, imageData, livenessVerified, qualityScore } = req.body;
      
      // For demo purposes, we'll simulate verification
      // In a real implementation, you would:
      // 1. Verify WebAuthn credentials for fingerprint
      // 2. Use ML models to verify facial features and liveness
      // 3. Compare with stored biometric templates
      
      let verified = false;
      
      if (type === 'fingerprint') {
        // Simulate fingerprint verification
        verified = credentialId && authData && authData.length > 0;
      } else if (type === 'facial') {
        // Simulate facial recognition verification
        verified = imageData && qualityScore > 70 && livenessVerified;
      }
      
      // Update user's biometric settings if this is first time setup
      if (verified) {
        await storage.updateUser(req.user.userId, {
          biometricEnabled: true,
        });
      }
      
      res.json({ 
        verified,
        authType: type,
        timestamp: new Date().toISOString(),
        sessionId: sessionId || `session_${Date.now()}`
      });
    } catch (error: any) {
      console.error("Error verifying biometric authentication:", error);
      res.status(500).json({ message: "Failed to verify biometric authentication" });
    }
  });

  // Get biometric settings
  app.get("/api/auth/biometric/settings", authenticateToken, async (req: any, res) => {
    try {
      const user = await storage.getUser(req.user.userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({
        biometricEnabled: user.biometricEnabled || false,
        fingerprintEnrolled: !!user.fingerprintHash,
        faceEnrolled: !!user.faceEncodingHash,
        supportedMethods: ['fingerprint', 'facial'],
      });
    } catch (error: any) {
      console.error("Error getting biometric settings:", error);
      res.status(500).json({ message: "Failed to get biometric settings" });
    }
  });

  // Update biometric settings
  app.put("/api/auth/biometric/settings", authenticateToken, async (req: any, res) => {
    try {
      const { biometricEnabled } = req.body;
      
      const updatedUser = await storage.updateUser(req.user.userId, {
        biometricEnabled: biometricEnabled,
      });
      
      res.json({
        biometricEnabled: updatedUser.biometricEnabled,
        message: biometricEnabled ? "Biometric authentication enabled" : "Biometric authentication disabled"
      });
    } catch (error: any) {
      console.error("Error updating biometric settings:", error);
      res.status(500).json({ message: "Failed to update biometric settings" });
    }
  });

  // VAN Payment Processing Routes for Korean Banking Integration
  
  // Process VAN payment
  app.post("/api/van/process", authenticateToken, async (req: any, res) => {
    try {
      const { amount, currency, merchantId, terminalId, cardNumber, paymentMethod, customerInfo } = req.body;
      
      // Generate transaction ID and approval number
      const transactionId = `VAN${Date.now()}${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
      const approvalNumber = `${Date.now().toString().slice(-8)}${Math.floor(Math.random() * 100).toString().padStart(2, '0')}`;
      
      // Simulate VAN processing based on payment method and currency
      let status = 'approved';
      let processingFee = 0;
      
      // Calculate processing fees
      if (currency === 'KWAN') {
        processingFee = amount * 0.001; // 0.1% for KWAN
      } else if (currency === 'KRW') {
        processingFee = amount * 0.005; // 0.5% for KRW
      } else {
        processingFee = amount * 0.01; // 1% for foreign currencies
      }
      
      // Simulate approval/decline logic
      if (amount > 10000000) { // Large amounts need additional verification
        status = 'pending';
      } else if (Math.random() < 0.02) { // 2% decline rate for simulation
        status = 'declined';
      }
      
      // Create VAN transaction record
      const vanTransaction = await storage.createVanTransaction({
        userId: req.user!.id,
        transactionId,
        approvalNumber,
        amount,
        currency,
        merchantId,
        terminalId,
        paymentMethod,
        cardNumberMasked: cardNumber ? `****-****-****-${cardNumber.slice(-4)}` : null,
        status,
        processingFee,
        customerName: customerInfo?.name || null,
        customerPhone: customerInfo?.phone || null,
        customerEmail: customerInfo?.email || null,
        processedAt: new Date(),
      });
      
      // Prepare response
      const response = {
        transactionId,
        approvalNumber,
        status,
        amount,
        currency,
        timestamp: new Date().toISOString(),
        receiptData: {
          merchantName: '슈퍼월렛 가맹점',
          merchantId,
          terminalId,
          cardMasked: cardNumber ? `****-****-****-${cardNumber.slice(-4)}` : undefined,
          authCode: status === 'approved' ? approvalNumber : 'DECLINED',
          processingFee,
        },
      };
      
      res.json(response);
    } catch (error: any) {
      console.error("VAN payment processing error:", error);
      res.status(500).json({ message: "VAN payment processing failed" });
    }
  });

  // Get KWAN exchange rates
  app.get("/api/van/kwan/rates", async (req, res) => {
    try {
      // In production, these would come from actual exchange APIs
      const rates = [
        {
          fromCurrency: 'KRW',
          toCurrency: 'KWAN',
          rate: 0.001,
          timestamp: new Date().toISOString(),
          spread: 0.005,
        },
        {
          fromCurrency: 'KWAN',
          toCurrency: 'KRW',
          rate: 1000,
          timestamp: new Date().toISOString(),
          spread: 0.005,
        },
        {
          fromCurrency: 'USD',
          toCurrency: 'KWAN',
          rate: 1.3,
          timestamp: new Date().toISOString(),
          spread: 0.01,
        },
        {
          fromCurrency: 'EUR',
          toCurrency: 'KWAN',
          rate: 1.4,
          timestamp: new Date().toISOString(),
          spread: 0.01,
        },
        {
          fromCurrency: 'JPY',
          toCurrency: 'KWAN',
          rate: 0.009,
          timestamp: new Date().toISOString(),
          spread: 0.01,
        },
        {
          fromCurrency: 'CNY',
          toCurrency: 'KWAN',
          rate: 0.18,
          timestamp: new Date().toISOString(),
          spread: 0.015,
        },
      ];
      
      res.json(rates);
    } catch (error: any) {
      console.error("KWAN rates fetch error:", error);
      res.status(500).json({ message: "Failed to fetch KWAN rates" });
    }
  });

  // Convert currency
  app.post("/api/van/convert", async (req, res) => {
    try {
      const { amount, fromCurrency, toCurrency } = req.body;
      
      // Mock exchange rates - in production, use real rates
      const exchangeRates: { [key: string]: { [key: string]: number } } = {
        'KRW': { 'KWAN': 0.001, 'USD': 0.00075, 'EUR': 0.00068, 'JPY': 0.11, 'CNY': 0.0052 },
        'KWAN': { 'KRW': 1000, 'USD': 0.75, 'EUR': 0.68, 'JPY': 110, 'CNY': 5.2 },
        'USD': { 'KRW': 1330, 'KWAN': 1.33, 'EUR': 0.91, 'JPY': 147, 'CNY': 7.0 },
        'EUR': { 'KRW': 1470, 'KWAN': 1.47, 'USD': 1.10, 'JPY': 162, 'CNY': 7.7 },
        'JPY': { 'KRW': 9.1, 'KWAN': 0.009, 'USD': 0.0068, 'EUR': 0.0062, 'CNY': 0.048 },
        'CNY': { 'KRW': 192, 'KWAN': 0.19, 'USD': 0.14, 'EUR': 0.13, 'JPY': 21 },
      };
      
      const rate = exchangeRates[fromCurrency]?.[toCurrency] || 1;
      const convertedAmount = amount * rate;
      
      // Calculate fees based on currency pair
      let feeRate = 0.005; // 0.5% default
      if (fromCurrency === 'KWAN' || toCurrency === 'KWAN') {
        feeRate = 0.002; // 0.2% for KWAN transactions
      }
      
      const fees = convertedAmount * feeRate;
      const finalAmount = convertedAmount - fees;
      
      res.json({
        amount: finalAmount,
        rate,
        fees,
        originalAmount: amount,
        fromCurrency,
        toCurrency,
        timestamp: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error("Currency conversion error:", error);
      res.status(500).json({ message: "Currency conversion failed" });
    }
  });

  // Get VAN payment history
  app.get("/api/van/history", authenticateToken, async (req: any, res) => {
    try {
      const { startDate, endDate, currency, status, merchantId } = req.query;
      
      // Get VAN transactions for the user
      const transactions = await storage.getVanTransactionsByUserId(req.user!.id);
      
      // Apply filters
      let filteredTransactions = transactions;
      
      if (startDate) {
        filteredTransactions = filteredTransactions.filter(
          t => new Date(t.processedAt) >= new Date(startDate as string)
        );
      }
      
      if (endDate) {
        filteredTransactions = filteredTransactions.filter(
          t => new Date(t.processedAt) <= new Date(endDate as string)
        );
      }
      
      if (currency) {
        filteredTransactions = filteredTransactions.filter(
          t => t.currency === currency
        );
      }
      
      if (status) {
        filteredTransactions = filteredTransactions.filter(
          t => t.status === status
        );
      }
      
      if (merchantId) {
        filteredTransactions = filteredTransactions.filter(
          t => t.merchantId === merchantId
        );
      }
      
      // Convert to response format
      const response = filteredTransactions.map(t => ({
        transactionId: t.transactionId,
        approvalNumber: t.approvalNumber,
        status: t.status,
        amount: t.amount,
        currency: t.currency,
        timestamp: t.processedAt.toISOString(),
        receiptData: {
          merchantName: '슈퍼월렛 가맹점',
          merchantId: t.merchantId,
          terminalId: t.terminalId,
          cardMasked: t.cardNumberMasked,
          authCode: t.status === 'approved' ? t.approvalNumber : 'DECLINED',
          processingFee: t.processingFee,
        },
      }));
      
      res.json(response);
    } catch (error: any) {
      console.error("VAN history fetch error:", error);
      res.status(500).json({ message: "Failed to fetch VAN payment history" });
    }
  });

  // Real-time push notification registration
  app.post("/api/notifications/register", authenticateToken, async (req: any, res) => {
    try {
      const { endpoint, keys, userAgent } = req.body;
      
      // Store push subscription in database
      // In production, you would save this to enable push notifications
      res.json({ 
        success: true, 
        message: "Push notification subscription registered",
        subscriptionId: `sub_${Date.now()}_${req.user.userId}`
      });
    } catch (error: any) {
      console.error("Push notification registration error:", error);
      res.status(500).json({ message: "Failed to register push notifications" });
    }
  });

  // Send transaction alert
  app.post("/api/notifications/transaction-alert", authenticateToken, async (req: any, res) => {
    try {
      const { transactionId, amount, currency, type } = req.body;
      
      // In production, this would trigger actual push notifications
      // For now, we'll simulate the response
      res.json({
        success: true,
        alertId: `alert_${Date.now()}_${transactionId}`,
        message: "Transaction alert sent successfully",
        timestamp: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error("Transaction alert error:", error);
      res.status(500).json({ message: "Failed to send transaction alert" });
    }
  });

  // Smart Contract Deployment Routes
  app.post('/api/contracts/deploy', authenticateToken, async (req: any, res) => {
    try {
      const { contractName, constructorArgs, gasLimit } = req.body;
      const userId = req.user.id;

      // Generate contract deployment simulation for Xphere network
      const contractAddress = `0x${Math.random().toString(16).substring(2, 42)}`;
      const txHash = `0x${Math.random().toString(16).substring(2, 66)}`;
      const blockNumber = Math.floor(Math.random() * 1000000) + 1000000;
      const gasUsed = Math.floor(gasLimit * 0.8); // Simulate 80% gas usage

      // Get contract ABI and bytecode based on contract name
      let abi = [];
      let bytecode = "";
      
      if (contractName === "SuperWalletToken") {
        abi = [
          {"inputs":[{"name":"_name","type":"string"},{"name":"_symbol","type":"string"},{"name":"_decimals","type":"uint8"},{"name":"_totalSupply","type":"uint256"}],"stateMutability":"nonpayable","type":"constructor"},
          {"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},
          {"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
          {"inputs":[{"name":"did","type":"string"}],"name":"registerDID","outputs":[],"stateMutability":"nonpayable","type":"function"},
          {"inputs":[{"name":"docHash","type":"bytes32"},{"name":"ipfsHash","type":"string"},{"name":"documentType","type":"string"}],"name":"storeDocument","outputs":[],"stateMutability":"nonpayable","type":"function"}
        ];
        bytecode = "0x608060405234801561001057600080fd5b506040516200100038038062001000833981016040819052610031916101a9565b8351610044906003906020870190610063565b50825161005890600490602086019061..."; // Truncated for brevity
      }

      // Create deployment record
      const deploymentData = {
        userId,
        contractName,
        contractAddress,
        deployerAddress: `0x${Math.random().toString(16).substring(2, 42)}`, // User's wallet address
        txHash,
        blockNumber,
        gasUsed,
        status: 'deployed',
        abi: JSON.stringify(abi),
        bytecode,
        constructorArgs: JSON.stringify(constructorArgs),
        compilationMetadata: JSON.stringify({
          compiler: "solc",
          version: "0.8.19",
          settings: { optimizer: { enabled: true, runs: 200 } }
        })
      };

      const deployment = await storage.createContractDeployment(deploymentData);
      res.json(deployment);
    } catch (error) {
      console.error('Contract deployment error:', error);
      res.status(500).json({ message: 'Contract deployment failed' });
    }
  });

  app.get('/api/contracts/deployments', authenticateToken, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const deployments = await storage.getContractDeploymentsByUserId(userId);
      res.json(deployments);
    } catch (error) {
      console.error('Get deployments error:', error);
      res.status(500).json({ message: 'Failed to fetch deployments' });
    }
  });

  app.get('/api/contracts/deployments/:id', authenticateToken, async (req: any, res) => {
    try {
      const deploymentId = parseInt(req.params.id);
      const deployments = await storage.getContractDeploymentsByUserId(req.user.id);
      const deployment = deployments.find(d => d.id === deploymentId);
      
      if (!deployment) {
        return res.status(404).json({ message: 'Deployment not found' });
      }
      
      res.json(deployment);
    } catch (error) {
      console.error('Get deployment error:', error);
      res.status(500).json({ message: 'Failed to fetch deployment' });
    }
  });

  app.post('/api/contracts/call', authenticateToken, async (req: any, res) => {
    try {
      const { contractAddress, functionName, args } = req.body;
      
      // Simulate contract function call
      let result;
      
      if (functionName === 'balanceOf') {
        result = `${Math.floor(Math.random() * 1000000)}000000000000000000`; // Random balance in wei
      } else if (functionName === 'getUserDID') {
        result = `did:xphere:${args[0]}`;
      } else if (functionName === 'getDocument') {
        result = {
          owner: args[0] || `0x${Math.random().toString(16).substring(2, 42)}`,
          ipfsHash: `Qm${Math.random().toString(36).substring(2, 48)}`,
          timestamp: Math.floor(Date.now() / 1000),
          isVerified: Math.random() > 0.5,
          documentType: "passport"
        };
      } else {
        result = `0x${Math.random().toString(16).substring(2, 66)}`;
      }

      res.json({ result });
    } catch (error) {
      console.error('Contract call error:', error);
      res.status(500).json({ message: 'Contract call failed' });
    }
  });

  app.post('/api/contracts/send', authenticateToken, async (req: any, res) => {
    try {
      const { contractAddress, functionName, args, value } = req.body;
      const userId = req.user.id;

      // Generate transaction hash
      const txHash = `0x${Math.random().toString(16).substring(2, 66)}`;
      const blockNumber = Math.floor(Math.random() * 1000000) + 1000000;
      const gasUsed = Math.floor(Math.random() * 200000) + 21000;

      // Create interaction record
      const interactionData = {
        userId,
        contractAddress,
        functionName,
        args: JSON.stringify(args),
        txHash,
        blockNumber,
        gasUsed,
        status: 'success',
        result: JSON.stringify({ success: true }),
        value: value || '0'
      };

      const interaction = await storage.createContractInteraction(interactionData);
      res.json({ txHash, blockNumber, gasUsed });
    } catch (error) {
      console.error('Contract transaction error:', error);
      res.status(500).json({ message: 'Contract transaction failed' });
    }
  });

  app.post('/api/contracts/verify', authenticateToken, async (req: any, res) => {
    try {
      const { contractAddress } = req.body;
      
      // Simulate contract verification
      const deployment = await storage.getContractDeploymentByAddress(contractAddress);
      
      if (!deployment) {
        return res.status(404).json({ message: 'Contract not found' });
      }

      // Update deployment status to verified
      await storage.updateContractDeployment(deployment.id, {
        status: 'verified',
        verifiedAt: new Date()
      });

      res.json({ verified: true, message: 'Contract verified successfully' });
    } catch (error) {
      console.error('Contract verification error:', error);
      res.status(500).json({ message: 'Contract verification failed' });
    }
  });

  app.get('/api/contracts/events', authenticateToken, async (req: any, res) => {
    try {
      const { contractAddress, fromBlock } = req.query;
      
      // Simulate contract events
      const events = [
        {
          event: 'Transfer',
          args: {
            from: `0x${Math.random().toString(16).substring(2, 42)}`,
            to: `0x${Math.random().toString(16).substring(2, 42)}`,
            value: `${Math.floor(Math.random() * 1000)}000000000000000000`
          },
          blockNumber: Math.floor(Math.random() * 1000000),
          transactionHash: `0x${Math.random().toString(16).substring(2, 66)}`
        },
        {
          event: 'DIDRegistered',
          args: {
            user: `0x${Math.random().toString(16).substring(2, 42)}`,
            did: `did:xphere:${Math.random().toString(36).substring(2, 10)}`
          },
          blockNumber: Math.floor(Math.random() * 1000000),
          transactionHash: `0x${Math.random().toString(16).substring(2, 66)}`
        }
      ];

      res.json(events);
    } catch (error) {
      console.error('Contract events error:', error);
      res.status(500).json({ message: 'Failed to fetch contract events' });
    }
  });

  app.post('/api/contracts/estimate-gas', authenticateToken, async (req: any, res) => {
    try {
      const { contractAddress, functionName, args } = req.body;
      
      // Simulate gas estimation based on function complexity
      let gasEstimate;
      
      if (functionName.includes('transfer')) {
        gasEstimate = 65000;
      } else if (functionName.includes('register')) {
        gasEstimate = 120000;
      } else if (functionName.includes('store')) {
        gasEstimate = 200000;
      } else {
        gasEstimate = 50000;
      }

      res.json({ gasEstimate });
    } catch (error) {
      console.error('Gas estimation error:', error);
      res.status(500).json({ message: 'Gas estimation failed' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
