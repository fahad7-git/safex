// Tab Switching Logic
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(tabId).classList.add('active');
    const activeBtn = document.querySelector(`[data-target="${tabId}"]`);
    if(activeBtn) activeBtn.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        switchTab(e.target.closest('.tab-btn').dataset.target);
    });
});

// Scan Logic
const scanBtn = document.getElementById('scan-btn');
const urlInput = document.getElementById('url-input');
const loadingState = document.getElementById('loading-state');
const resultsDashboard = document.getElementById('results-dashboard');
const progressBar = document.getElementById('scan-progress');
const loadingMessage = document.getElementById('loading-message');
const loadingLogs = document.getElementById('loading-logs');

const logMessages = [
    "[INFO] Initializing sandbox environment...",
    "[NETWORK] Resolving DNS A/AAAA records...",
    "[SECURITY] Verifying TLS/SSL certificate chain...",
    "[SCAN] Querying Google Safe Browsing API...",
    "[SCAN] Querying VirusTotal hashes...",
    "[CRAWLER] Executing DOM in headless browser...",
    "[HEURISTICS] Analyzing visual similarity...",
    "[SYSTEM] Compiling threat intelligence report..."
];

scanBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (!url) {
        alert("Please enter a valid URL to analyze.");
        return;
    }

    // Reset UI
    resultsDashboard.classList.add('hidden');
    loadingState.classList.remove('hidden');
    progressBar.style.width = '0%';
    loadingLogs.innerHTML = '';
    
    // Simulate Loading UI while waiting for Backend
    let progress = 0;
    let logIndex = 0;

    const uiInterval = setInterval(() => {
        if (progress < 90) progress += Math.random() * 10;
        progressBar.style.width = `${progress}%`;

        if (Math.random() > 0.5 && logIndex < logMessages.length) {
            const logEl = document.createElement('div');
            logEl.textContent = `> ${logMessages[logIndex]}`;
            loadingLogs.appendChild(logEl);
            loadingLogs.scrollTop = loadingLogs.scrollHeight;
            loadingMessage.textContent = logMessages[logIndex].split('] ')[1];
            logIndex++;
        }
    }, 200);

    try {
// Fetch from Netlify Function (works both locally and on Netlify)
        const response = await fetch('/.netlify/functions/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) throw new Error('API Error');
        const report = await response.json();
        
        clearInterval(uiInterval);
        progressBar.style.width = '100%';
        loadingMessage.textContent = "Analysis Complete.";
        
        setTimeout(() => {
            populateDashboard(report);
            loadingState.classList.add('hidden');
            resultsDashboard.classList.remove('hidden');
        }, 500);

} catch (error) {
        clearInterval(uiInterval);
        console.error('Scan error:', error);
        alert("An error occurred during analysis. Please try again or check the console for details.");
        loadingState.classList.add('hidden');
    }
});

urlInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') scanBtn.click();
});

function populateDashboard(report) {
    // 1. Top Row
    document.getElementById('scanned-url-display').textContent = report.target.domain;
    
    const circle = document.querySelector('.circle');
    const riskLevelTxt = document.getElementById('risk-level');
    const scoreText = document.getElementById('score-text');

    circle.classList.remove('safe', 'warning', 'danger');
    riskLevelTxt.classList.remove('text-safe', 'text-warning', 'text-danger');

    if (report.isSafe) {
        circle.classList.add('safe');
        circle.setAttribute('stroke-dasharray', `${report.score}, 100`);
        riskLevelTxt.textContent = 'Clean';
        riskLevelTxt.classList.add('text-safe');
    } else {
        circle.classList.add('danger');
        circle.setAttribute('stroke-dasharray', `${report.score}, 100`);
        riskLevelTxt.textContent = 'High Risk';
        riskLevelTxt.classList.add('text-danger');
        // If risky, show glitchy placeholder image, if safe, maybe hide it or use generic
        document.querySelector('.evidence-card').style.display = 'block';
    }
    scoreText.textContent = `${report.score}/100`;

    // 2. Target Fingerprint
    document.getElementById('target-ip').textContent = report.target.ipAddress;
    document.getElementById('target-asn').textContent = report.target.asn;
    document.getElementById('target-hosting').textContent = report.target.hosting;
    document.getElementById('target-location').textContent = report.target.geolocation;
    document.getElementById('target-registrar').textContent = report.target.registrar;

    // 3. Metrics Grid
    const updateMetric = (id, data, isSafeCond) => {
        const el = document.getElementById(id);
        const sub = document.getElementById(id + '-sub');
        el.textContent = data.status;
        sub.textContent = data.description;
        el.className = 'metric-value ' + (isSafeCond ? 'val-safe' : 'val-danger');
    };

    updateMetric('res-ssl', report.metrics.ssl, report.metrics.ssl.status === 'Valid');
    updateMetric('res-age', report.metrics.age, report.metrics.age.status.includes('Years'));
    updateMetric('res-scripts', report.metrics.scripts, report.metrics.scripts.status === '0 Detected');
    updateMetric('res-redirects', report.metrics.redirects, report.metrics.redirects.status === '1 Hop');

    // 4. Vendors Table
    const tbody = document.querySelector('#vendor-table tbody');
    tbody.innerHTML = '';
    report.vendors.forEach(v => {
        const tr = document.createElement('tr');
        const isClean = v.verdict === 'Clean';
        tr.innerHTML = `
            <td>${v.name}</td>
            <td><span class="${isClean ? 'verdict-clean' : 'verdict-malicious'}">${v.verdict}</span></td>
        `;
        tbody.appendChild(tr);
    });

    // 5. DNS and Headers
    const dnsHtml = report.technical.dns.map(d => 
        `<div><span class="code-key">${d.type}</span>: <span class="code-value">${d.value}</span></div>`
    ).join('');
    
    const headersHtml = report.technical.headers.map(h => 
        `<div><span class="code-key">${h.name}</span>: <span class="code-value">${h.value}</span></div>`
    ).join('');

    document.getElementById('dns-headers-block').innerHTML = `
        <div class="code-comment">// DNS Records</div>
        ${dnsHtml}
        <br/>
        <div class="code-comment">// Security Headers</div>
        ${headersHtml}
    `;

    // 6. Accordions Population
    const originalUrl = document.getElementById('url-input').value;
    
    document.getElementById('acc-url-info').innerHTML = `
        <div class="fp-item"><strong>Analyzed URL:</strong> <span style="font-family: var(--font-mono); color: var(--accent-cyan); word-break: break-all;">${originalUrl}</span></div>
        <div class="fp-item" style="margin-top: 10px;"><strong>Base Domain:</strong> ${report.target.domain}</div>
    `;

    document.getElementById('acc-domain-info').innerHTML = `
        <div class="fingerprint-grid" style="grid-template-columns: 1fr;">
            <div class="fp-item"><strong>IP Address:</strong> ${report.target.ipAddress}</div>
            <div class="fp-item"><strong>ASN:</strong> ${report.target.asn}</div>
            <div class="fp-item"><strong>Hosting:</strong> ${report.target.hosting}</div>
            <div class="fp-item"><strong>Location:</strong> ${report.target.geolocation}</div>
            <div class="fp-item"><strong>Registrar:</strong> ${report.target.registrar}</div>
        </div>
    `;

    document.getElementById('acc-ssl-info').innerHTML = `
        <div class="fp-item"><strong>Status:</strong> <span class="${report.metrics.ssl.status === 'Valid' ? 'val-safe' : 'val-danger'}">${report.metrics.ssl.status}</span></div>
        <div class="fp-item" style="margin-top: 10px;"><strong>Description:</strong> ${report.metrics.ssl.description}</div>
    `;

    document.getElementById('acc-url-structure').innerHTML = `
        <div class="fp-item"><strong>Redirects:</strong> ${report.metrics.redirects.status} - ${report.metrics.redirects.description}</div>
        <div class="fp-item" style="margin-top: 10px;"><strong>Domain Age:</strong> ${report.metrics.age.status} - ${report.metrics.age.description}</div>
    `;

    const vendorsHtml = report.vendors.map(v => 
        `<div class="fp-item" style="margin-bottom: 10px; display: flex; justify-content: space-between;"><strong>${v.name}:</strong> <span class="${v.verdict === 'Clean' ? 'verdict-clean' : 'verdict-malicious'}">${v.verdict}</span></div>`
    ).join('');
    document.getElementById('acc-security-indicators').innerHTML = vendorsHtml;

    document.getElementById('acc-content-analysis').innerHTML = `
        <div class="fp-item"><strong>Malicious Scripts:</strong> <span class="${report.metrics.scripts.status === '0 Detected' ? 'val-safe' : 'val-danger'}">${report.metrics.scripts.status}</span></div>
        <div class="fp-item" style="margin-top: 10px;"><strong>Description:</strong> ${report.metrics.scripts.description}</div>
    `;

    document.getElementById('acc-ml-model').innerHTML = `
        <div class="fp-item"><strong>Heuristic Score:</strong> <span class="${report.isSafe ? 'val-safe' : 'val-danger'}">${report.score}/100</span></div>
        <div class="fp-item" style="margin-top: 10px;"><strong>Verdict:</strong> <span class="${report.isSafe ? 'val-safe' : 'val-danger'}">${report.isSafe ? 'Clean' : 'High Risk'}</span></div>
    `;
}

// Accordion Logic
document.addEventListener('click', function(e) {
    const header = e.target.closest('.accordion-header');
    if (header) {
        const item = header.parentElement;
        item.classList.toggle('active');
    }
});

// Mobile Menu Logic
const mobileMenuBtn = document.getElementById('mobile-menu-btn');
const navTabs = document.getElementById('nav-tabs');

if(mobileMenuBtn) {
    mobileMenuBtn.addEventListener('click', () => {
        navTabs.classList.toggle('active');
        const icon = mobileMenuBtn.querySelector('i');
        if(navTabs.classList.contains('active')) {
            icon.classList.remove('ph-list');
            icon.classList.add('ph-x');
        } else {
            icon.classList.remove('ph-x');
            icon.classList.add('ph-list');
        }
    });
    
    // Close menu when a tab is clicked
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            navTabs.classList.remove('active');
            const icon = mobileMenuBtn.querySelector('i');
            icon.classList.remove('ph-x');
            icon.classList.add('ph-list');
        });
    });
}
