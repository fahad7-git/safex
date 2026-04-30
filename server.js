const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Mock data for demonstration - In production, integrate with real APIs
function analyzeUrl(url) {
    // Simulate URL parsing
    let domain = url;
    try {
        const urlObj = new URL(url);
        domain = urlObj.hostname;
    } catch (e) {
        // If URL is just a domain
    }

    // Generate deterministic but random-looking results based on domain length
    const hash = domain.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
    const isRisky = hash % 3 === 0; // ~33% chance of being flagged
    
    return {
        target: {
            domain: domain,
            ipAddress: `192.168.${hash % 255}.${hash % 255}`,
            asn: `AS${10000 + (hash % 50000)}`,
            hosting: hash % 2 === 0 ? 'Cloudflare, Inc.' : 'Amazon AWS',
            geolocation: hash % 4 === 0 ? 'United States' : hash % 4 === 1 ? 'Germany' : hash % 4 === 2 ? 'Netherlands' : 'United Kingdom',
            registrar: hash % 2 === 0 ? 'GoDaddy.com, LLC' : 'Namecheap, Inc.'
        },
        metrics: {
            ssl: {
                status: isRisky ? 'Invalid' : 'Valid',
                description: isRisky ? 'Certificate expired or self-signed' : 'Certificate valid and trusted'
            },
            age: {
                status: isRisky ? '< 1 Month' : '2 Years',
                description: isRisky ? 'Recently registered domain' : 'Established domain'
            },
            scripts: {
                status: isRisky ? '3 Detected' : '0 Detected',
                description: isRisky ? 'Suspicious obfuscated scripts found' : 'No malicious scripts detected'
            },
            redirects: {
                status: isRisky ? '5 Hops' : '1 Hop',
                description: isRisky ? 'Multiple redirects detected' : 'Direct connection'
            }
        },
        vendors: [
            { name: 'Google Safe Browsing', verdict: isRisky ? 'Malicious' : 'Clean' },
            { name: 'VirusTotal', verdict: isRisky ? 'Malicious' : 'Clean' },
            { name: ' Norton ConnectSafe', verdict: isRisky ? 'Malicious' : 'Clean' },
            { name: 'McAfee', verdict: isRisky ? 'Malicious' : 'Clean' },
            { name: 'Kaspersky', verdict: isRisky ? 'Malicious' : 'Clean' },
            { name: 'Bitdefender', verdict: isRisky ? 'Malicious' : 'Clean' }
        ],
        technical: {
            dns: [
                { type: 'A', value: `192.168.${hash % 255}.${hash % 255}` },
                { type: 'AAAA', value: `2001:db8::${hash.toString(16).slice(0,4)}` },
                { type: 'MX', value: `mail.${domain}` },
                { type: 'NS', value: `ns1.${domain}` }
            ],
            headers: [
                { name: 'X-Frame-Options', value: isRisky ? 'ALLOWALL' : 'DENY' },
                { name: 'Content-Security-Policy', value: isRisky ? 'unsafe-inline' : 'default-src \'self\'' },
                { name: 'X-Content-Type-Options', value: 'nosniff' },
                { name: 'Strict-Transport-Policy', value: 'max-age=31536000' }
            ]
        },
        isSafe: !isRisky,
        score: isRisky ? 75 + (hash % 20) : 5 + (hash % 20)
    };
}

// API Endpoint for URL scanning
app.post('/api/scan', (req, res) => {
    const { url } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    // Simulate processing delay
    setTimeout(() => {
        const report = analyzeUrl(url);
        res.json(report);
    }, 1500);
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Safe-X Server running at http://localhost:${PORT}`);
});
