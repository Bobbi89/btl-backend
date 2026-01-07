require('dotenv').config();
const express = require('express');
const { ethers } = require('ethers');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ============ Configuration ============

const PORT = process.env.PORT || 3001;
const RPC_URL = process.env.WEB3_RPC_URL;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const ORACLE_PRIVATE_KEY = process.env.ORACLE_PRIVATE_KEY;
const GOPLUS_API = 'https://api.gopluslabs.io/api/v1/token_security';

// In-memory database (temporary - replace with PostgreSQL later)
const inMemoryDB = {
    scans: [],
    addScan: function (data) {
        this.scans.push(data);
        if (this.scans.length > 1000) this.scans.shift(); // Keep last 1000
    },
    getScan: function (address) {
        return this.scans.find(s => s.contract_address.toLowerCase() === address.toLowerCase());
    },
    getRecent: function (limit = 50) {
        return this.scans.slice(-limit).reverse();
    }
};

console.log('📝 Using in-memory database (PostgreSQL not installed)');
console.log('💡 Install PostgreSQL for persistent storage\n');

// ============ Blockchain Setup ============

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(ORACLE_PRIVATE_KEY, provider);

const CONTRACT_ABI = [
    "event AuditRequested(uint256 indexed requestId, address indexed target, address requester, uint256 fee)",
    "event SBTMinted(address indexed target, uint256 indexed tokenId, uint256 score)",
    "function fulfillAudit(uint256 requestId, uint256 score, bool isHoneypot, bool isMintable, bool ownerCanWithdraw)",
    "function tokenOf(address contractAddress) view returns (uint256)",
    "function getAuditData(uint256 tokenId) view returns (tuple(uint256 score, bool isHoneypot, bool isMintable, bool ownerCanWithdraw, uint256 timestamp, string metadataURI))",
    "function calculateFee(address target) view returns (uint256)"
];

const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, wallet);

// ============ GoPlus Security Scan ============

async function scanWithGoPlus(address, chainId = 11155111) {
    try {
        const url = `${GOPLUS_API}/${chainId}`;
        const response = await axios.get(url, {
            params: { contract_addresses: address },
            timeout: 10000
        });

        const result = response.data?.result?.[address.toLowerCase()];
        if (!result) {
            console.log(`⚠️  No GoPlus data for ${address}`);
            return null;
        }

        let score = 100;

        if (result.is_honeypot === "1") score -= 100;
        if (result.is_open_source === "0") score -= 20;
        if (result.is_proxy === "1") score -= 10;
        if (result.is_mintable === "1") score -= 15;
        if (result.can_take_back_ownership === "1") score -= 20;
        if (parseFloat(result.buy_tax || 0) > 0.1) score -= 15;
        if (parseFloat(result.sell_tax || 0) > 0.1) score -= 15;

        score = Math.max(0, Math.min(100, score));

        return {
            score,
            isHoneypot: result.is_honeypot === "1",
            isMintable: result.is_mintable === "1",
            ownerCanWithdraw: result.can_take_back_ownership === "1",
            rawData: result
        };
    } catch (error) {
        console.error(`❌ GoPlus scan error:`, error.message);
        return null;
    }
}

// ============ FLOW A: On-Demand Audit ============

contract.on('AuditRequested', async (requestId, target, requester, fee, event) => {
    console.log(`\n📝 NEW AUDIT REQUEST #${requestId}`);
    console.log(`   Target: ${target}`);
    console.log(`   Requester: ${requester}`);
    console.log(`   Fee: ${ethers.formatEther(fee)} ETH`);

    try {
        const scanResult = await scanWithGoPlus(target);

        if (!scanResult) {
            console.log(`⚠️  Using default safe values`);
            scanResult = { score: 50, isHoneypot: false, isMintable: false, ownerCanWithdraw: false };
        }

        console.log(`📊 Scan Result: Score ${scanResult.score}`);
        console.log(`   Honeypot: ${scanResult.isHoneypot}`);
        console.log(`   Mintable: ${scanResult.isMintable}`);
        console.log(`   Owner Can Withdraw: ${scanResult.ownerCanWithdraw}`);

        console.log(`📤 Fulfilling audit #${requestId}...`);
        const tx = await contract.fulfillAudit(
            requestId,
            scanResult.score,
            scanResult.isHoneypot,
            scanResult.isMintable,
            scanResult.ownerCanWithdraw,
            { gasLimit: 300000 }
        );

        console.log(`🔗 TX sent: ${tx.hash}`);
        const receipt = await tx.wait();

        if (receipt.status === 1) {
            console.log(`✅ Audit #${requestId} completed successfully!`);
            console.log(`🏆 SBT minted for ${target}\n`);

            inMemoryDB.addScan({
                contract_address: target,
                score: scanResult.score,
                is_honeypot: scanResult.isHoneypot,
                is_mintable: scanResult.isMintable,
                owner_can_withdraw: scanResult.ownerCanWithdraw,
                has_sbt: true,
                scanned_at: new Date().toISOString()
            });
        } else {
            console.error(`❌ Transaction reverted`);
        }

    } catch (error) {
        console.error(`❌ Error processing audit #${requestId}:`, error.message);
    }
});

// ============ FLOW B: Auto-Scanner ============

let lastProcessedBlock = 0;
let isScanning = false;

async function scanNewBlocks() {
    if (isScanning) return;
    isScanning = true;

    try {
        const currentBlock = await provider.getBlockNumber();

        if (lastProcessedBlock === 0) {
            lastProcessedBlock = currentBlock - 1;
        }

        if (currentBlock > lastProcessedBlock) {
            console.log(`🔍 Scanning blocks ${lastProcessedBlock + 1} to ${currentBlock}...`);

            for (let blockNum = lastProcessedBlock + 1; blockNum <= currentBlock; blockNum++) {
                await scanBlock(blockNum);
            }

            lastProcessedBlock = currentBlock;
        }
    } catch (error) {
        console.error('❌ Block scanning error:', error.message);
    } finally {
        isScanning = false;
    }
}

async function scanBlock(blockNumber) {
    try {
        const block = await provider.getBlock(blockNumber, true);
        if (!block || !block.transactions) return;

        for (const txHash of block.transactions) {
            const tx = await provider.getTransaction(txHash);
            const receipt = await provider.getTransactionReceipt(txHash);

            if (receipt && receipt.contractAddress) {
                const contractAddress = receipt.contractAddress;
                console.log(`\n🆕 New contract detected: ${contractAddress}`);
                console.log(`   Block: ${blockNumber}`);
                console.log(`   Deployer: ${tx.from}`);

                const scanResult = await scanWithGoPlus(contractAddress);

                if (scanResult) {
                    console.log(`   Score: ${scanResult.score}/100`);

                    inMemoryDB.addScan({
                        contract_address: contractAddress,
                        score: scanResult.score,
                        is_honeypot: scanResult.isHoneypot,
                        is_mintable: scanResult.isMintable,
                        owner_can_withdraw: scanResult.ownerCanWithdraw,
                        block_number: blockNumber,
                        deployer: tx.from,
                        has_sbt: false,
                        scanned_at: new Date().toISOString()
                    });
                }
            }
        }
    } catch (error) {
        // Silent fail for individual blocks
    }
}

setInterval(scanNewBlocks, 12000); // Every 12 seconds

// ============ API Endpoints ============

app.get('/api/recent-scans', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const scans = inMemoryDB.getRecent(limit);

        res.json({
            success: true,
            count: scans.length,
            contracts: scans
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/contract-status/:address', async (req, res) => {
    try {
        const { address } = req.params;

        const tokenId = await contract.tokenOf(address);
        const hasSBT = Number(tokenId) > 0;

        let auditData = null;

        if (hasSBT) {
            const onChainData = await contract.getAuditData(tokenId);
            auditData = {
                score: Number(onChainData.score),
                isHoneypot: onChainData.isHoneypot,
                isMintable: onChainData.isMintable,
                ownerCanWithdraw: onChainData.ownerCanWithdraw,
                timestamp: Number(onChainData.timestamp),
                metadataURI: onChainData.metadataURI,
                tokenId: Number(tokenId)
            };
        } else {
            const dbData = inMemoryDB.getScan(address);
            if (dbData) {
                auditData = {
                    score: dbData.score,
                    isHoneypot: dbData.is_honeypot,
                    isMintable: dbData.is_mintable,
                    ownerCanWithdraw: dbData.owner_can_withdraw,
                    scannedAt: dbData.scanned_at
                };
            }
        }

        res.json({ success: true, address, hasSBT, auditData });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/fee/:address', async (req, res) => {
    try {
        const { address } = req.params;
        const fee = await contract.calculateFee(address);

        res.json({
            success: true,
            address,
            fee: ethers.formatEther(fee),
            feeWei: fee.toString()
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const scans = inMemoryDB.scans;
        const totalScans = scans.length;
        const totalSBTs = scans.filter(s => s.has_sbt).length;
        const avgScore = scans.length > 0
            ? scans.reduce((sum, s) => sum + s.score, 0) / scans.length
            : 0;

        res.json({
            success: true,
            stats: {
                total_scans: totalScans,
                total_sbts: totalSBTs,
                avg_score: avgScore.toFixed(1)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: 'in-memory',
        scans_stored: inMemoryDB.scans.length
    });
});

// ============ Server Startup ============

async function start() {
    try {
        console.log('🚀 Starting Base Trust Layer Oracle...\n');

        app.listen(PORT, () => {
            console.log(`🌐 API server running on port ${PORT}`);
        });

        const network = await provider.getNetwork();
        console.log(`⛓️  Connected to chain ID: ${network.chainId}`);
        console.log(`📝 Contract: ${CONTRACT_ADDRESS}`);
        console.log(`🔑 Oracle: ${wallet.address}\n`);

        console.log('✅ System ready!');
        console.log('👂 Listening for AuditRequested events...');
        console.log('🔍 Auto-scanning new contracts...\n');

    } catch (error) {
        console.error('❌ Startup error:', error);
        process.exit(1);
    }
}

process.on('SIGTERM', async () => {
    console.log('\n⏹️  Shutting down gracefully...');
    process.exit(0);
});

start();
