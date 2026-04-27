document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const target = document.getElementById('targetInput').value.trim();
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
    const targetType = isIp ? 'ip' : 'domain';
    
    // Gather selected plugins
    const plugins = [];
    if (document.getElementById('shodanCheck').checked) plugins.push('shodan');
    if (document.getElementById('crtshCheck').checked) plugins.push('crtsh');
    if (document.getElementById('dorkCheck').checked) plugins.push('dork');
    
    // UI Elements
    const scanBtn = document.getElementById('scanBtn');
    const btnText = scanBtn.querySelector('.btn-text');
    const loader = scanBtn.querySelector('.loader');
    const errorMsg = document.getElementById('errorMsg');
    const resultsSection = document.getElementById('resultsSection');
    
    // Reset UI
    errorMsg.classList.add('hidden');
    resultsSection.classList.add('hidden');
    document.getElementById('pluginResults').innerHTML = '';
    
    // Validation
    if (plugins.length === 0) {
        errorMsg.textContent = 'Please select at least one plugin.';
        errorMsg.classList.remove('hidden');
        return;
    }
    
    // Set Loading State
    scanBtn.disabled = true;
    btnText.textContent = 'Scanning...';
    loader.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                target_type: targetType,
                plugins: plugins
            })
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.detail || 'An error occurred during the scan.');
        }
        
        renderResults(result.data);
        resultsSection.classList.remove('hidden');
        
    } catch (error) {
        errorMsg.textContent = error.message;
        errorMsg.classList.remove('hidden');
    } finally {
        // Reset Loading State
        scanBtn.disabled = false;
        btnText.textContent = 'Initiate Scan';
        loader.classList.add('hidden');
    }
});

function renderResults(data) {
    let critical = 0;
    let high = 0;
    let medium = 0;
    
    const pluginContainer = document.getElementById('pluginResults');
    pluginContainer.innerHTML = '';
    
    // Iterate over plugin results
    for (const [pluginName, pluginData] of Object.entries(data)) {
        // Calculate Risk Scores
        if (typeof pluginData === 'object' && pluginData !== null) {
            if (pluginData.vulns && Array.isArray(pluginData.vulns)) {
                critical += pluginData.vulns.length;
            }
            if (pluginData.details && Array.isArray(pluginData.details)) {
                pluginData.details.forEach(item => {
                    if (item.severity === 'Critical') critical++;
                    else if (item.severity === 'High') high++;
                    else if (item.severity === 'Medium') medium++;
                });
            }
        }
        
        // Create Result Card
        const card = document.createElement('div');
        card.className = 'result-card';
        
        // Check for errors in plugin
        let contentHtml = '';
        if (typeof pluginData === 'string' && pluginData.startsWith('Error')) {
            contentHtml = `<p style="color: var(--critical);">${pluginData}</p>`;
        } else {
            contentHtml = `<pre>${JSON.stringify(pluginData, null, 2)}</pre>`;
        }
        
        card.innerHTML = `
            <div class="result-header">
                <h3>${pluginName.replace('Plugin', '')} Findings</h3>
            </div>
            <div class="result-body">
                ${contentHtml}
            </div>
        `;
        
        pluginContainer.appendChild(card);
    }
    
    // Update Risk Dashboard
    document.getElementById('criticalCount').textContent = critical;
    document.getElementById('highCount').textContent = high;
    document.getElementById('mediumCount').textContent = medium;
}
