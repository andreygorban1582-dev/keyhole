const https = require('https');
const http = require('http');
const { URL } = require('url');

// Known key patterns to detect
const PATTERNS = [
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,99}/g, severity: 'critical' },
  { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24,99}/g, severity: 'low' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', regex: /[0-9a-zA-Z\/+]{40}/g, severity: 'critical' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'GitHub Classic Token', regex: /ghp_[A-Za-z0-9]{36,}/g, severity: 'critical' },
  { name: 'Shopify Storefront Token', regex: /[a-f0-9]{32}/g, severity: 'low' },
  { name: 'Shopify API Key', regex: /api_key["\s:=]+([a-f0-9]{32})/g, severity: 'high' },
  { name: 'Shopify Shared Secret', regex: /secret["\s:=]+([a-f0-9]{32})/g, severity: 'critical' },
  { name: 'Slack Bot Token', regex: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g, severity: 'critical' },
  { name: 'Slack Webhook', regex: /hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g, severity: 'high' },
  { name: 'Twilio Account SID', regex: /AC[a-f0-9]{32}/g, severity: 'high' },
  { name: 'Twilio Auth Token', regex: /[a-f0-9]{32}/g, severity: 'critical' },
  { name: 'Mailchimp API Key', regex: /[a-f0-9]{32}-us[0-9]{1,2}/g, severity: 'high' },
  { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}/g, severity: 'high' },
  { name: 'Generic API Key (hex)', regex: /[a-fA-F0-9]{40,64}/g, severity: 'medium' },
  { name: 'Generic API Key (base64)', regex: /[A-Za-z0-9+\/=]{40,}/g, severity: 'medium' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g, severity: 'medium' },
  { name: 'Private Key Header', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Bearer Token', regex: /["']?Bearer\s+([A-Za-z0-9\-._~+\/=]+)["']?/g, severity: 'high' },
  { name: 'Password in JS', regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi, severity: 'critical' },
  { name: 'Database URL', regex: /(?:mysql|postgres|postgresql|mongodb|redis):\/\/[^/\s"']+/g, severity: 'critical' },
  { name: 'IP2Location Key', regex: /[A-F0-9]{32}/g, severity: 'medium' },
];

function fetchUrl(targetUrl) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'KeyHole-Scanner/1.0 (security-research)',
        'Accept': 'text/html,application/javascript,text/css,*/*',
      },
      timeout: 15000,
    };

    const req = client.request(options, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve(fetchUrl(res.headers.location));
        return;
      }
      
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data.substring(0, 500000))); // Cap at 500KB
    });

    req.on('error', (e) => reject(e));
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function scanContent(content, url) {
  const findings = [];
  
  for (const pattern of PATTERNS) {
    const matches = content.match(pattern.regex);
    if (!matches) continue;
    
    // Deduplicate
    const unique = [...new Set(matches)];
    
    for (const match of unique) {
      // Find line context
      const idx = content.indexOf(match);
      const before = content.substring(Math.max(0, idx - 200), idx);
      const lineMatch = before.split('\n');
      const line = lineMatch[lineMatch.length - 1].trim().substring(0, 200);
      
      findings.push({
        type: pattern.name,
        severity: pattern.severity,
        match: match.length > 80 ? match.substring(0, 80) + '...' : match,
        preview: line,
        count: unique.length,
      });
    }
    
    // Only report first 5 of each type to avoid spam
    if (findings.filter(f => f.type === pattern.name).length > 5) break;
  }
  
  return findings;
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  try {
    const { url } = JSON.parse(event.body);
    
    if (!url || !url.match(/^https?:\/\/.+/)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid URL' }),
      };
    }

    const content = await fetchUrl(url);
    const findings = scanContent(content, url);
    
    // Also try to find linked JS files and scan them
    const jsUrls = content.match(/(?:src|href)=["']([^"']+\.js)["']/gi) || [];
    const uniqueJs = [...new Set(jsUrls.map(u => {
      const m = u.match(/["']([^"']+)["']/);
      return m ? m[1] : null;
    }).filter(Boolean))];

    let jsFindings = [];
    for (const jsUrl of uniqueJs.slice(0, 5)) {
      try {
        const fullUrl = jsUrl.startsWith('http') ? jsUrl : new URL(jsUrl, url).href;
        const jsContent = await fetchUrl(fullUrl);
        jsFindings.push(...scanContent(jsContent, fullUrl));
      } catch(e) {
        // Skip failed JS fetches
      }
    }

    const allFindings = [...findings, ...jsFindings];
    
    // Summary
    const critical = allFindings.filter(f => f.severity === 'critical').length;
    const high = allFindings.filter(f => f.severity === 'high').length;
    const medium = allFindings.filter(f => f.severity === 'medium').length;
    const low = allFindings.filter(f => f.severity === 'low').length;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        url,
        scanned: content.length,
        totalFindings: allFindings.length,
        summary: { critical, high, medium, low },
        findings: allFindings.slice(0, 30),
        jsScanned: uniqueJs.slice(0, 5),
      }),
    };
  } catch (e) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: e.message }),
    };
  }
};
