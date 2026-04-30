// Netlify Function for URL scanning API
exports.handler = async (event, context) => {
    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
    }

    try {
        const { url } = JSON.parse(event.body);
        
        if (!url) {
            return { statusCode: 400, body: JSON.stringify({ error: 'URL is required' }) };
        }

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

        const report = {
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
                { name: 'Norton ConnectSafe', verdict: isRisky ? 'Malicious' : 'Clean' },
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

        return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(report)
        };
    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};
