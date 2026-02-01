// Heuristics Engine - Phishing Detection
// Analyzes DOM, forms, links, and network requests for phishing patterns
// Focuses on detecting actual phishing attempts, not legitimate services

let lastResults = null;
let anomalyScore = 0;
let externalLinks = [];
let externalPosts = [];
let detectedIssues = [];
let confidenceScore = 0; // 0-100, higher = more confident it's phishing

// Legitimate payment processors and OAuth providers (whitelist)
const LEGITIMATE_EXTERNAL_SERVICES = [
  // Payment processors
  'stripe.com', 'js.stripe.com', 'checkout.stripe.com',
  'paypal.com', 'www.paypal.com', 'checkout.paypal.com',
  'checkout.shopify.com', 'shopify.com',
  'square.com', 'squareup.com',
  'braintreegateway.com', 'braintree.com',
  'authorize.net',
  'adyen.com',
  // OAuth providers
  'accounts.google.com', 'google.com',
  'login.microsoftonline.com', 'microsoft.com',
  'github.com', 'github.io',
  'facebook.com', 'www.facebook.com',
  'okta.com',
  'auth0.com',
  'login.salesforce.com',
  // Analytics/tracking (legitimate)
  'google-analytics.com', 'googletagmanager.com',
  'facebook.net', 'facebook.com',
  'doubleclick.net',
  'googlesyndication.com'
];

// Known good CDNs and domains to whitelist
const KNOWN_GOOD_DOMAINS = [
  'google.com', 'googleapis.com', 'gstatic.com',
  'facebook.com', 'fbcdn.net',
  'cloudflare.com', 'cloudflare.net',
  'amazonaws.com', 'amazon.com',
  'jsdelivr.net', 'cdnjs.com',
  'github.com', 'githubusercontent.com',
  'twitter.com', 'twimg.com',
  ...LEGITIMATE_EXTERNAL_SERVICES
];

// High-risk TLDs (known for abuse)
const HIGH_RISK_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];

// Check if domain is legitimate external service (false positives)
function isLegitimateExternalService(hostname) {
  return LEGITIMATE_EXTERNAL_SERVICES.some(domain => 
    hostname === domain || hostname.endsWith('.' + domain)
  );
}

// Check if form action contains only tracking parameters
// Only treat it as safe if it’s tracking AND not related to login/payment
function isTrackingForm(action) {
  const trackingParams = ['utm_', 'ga_', 'fbclid', 'gclid', '_ga', 'ref'];
  return trackingParams.some(param => action.includes(param)) && 
         !action.includes('password') && 
         !action.includes('login') &&
         !action.includes('checkout');
}

// Initialize heuristics on page load
async function initHeuristics() {  
  // Always run initial analysis - background will filter by active tab
  anomalyScore = 0;
  externalLinks = [];
  externalPosts = [];
  detectedIssues = [];
  
  // Run all heuristics
  checkFormSubmissions();
  checkExternalLinks();
  interceptNetworkRequests();
  
  // Collect results
  const results = compileResults();
  lastResults = results;
  
  
  return results;
}

// Check for forms submitting to external domains (with false positive reduction)
function checkFormSubmissions() {
  const forms = document.querySelectorAll('form');
  
  forms.forEach((form, index) => {
    const action = form.getAttribute('action') || '';
    
    try {
      const formUrl = new URL(action, location.origin);
      
      // Skip if same domain
      if (formUrl.origin === location.origin) return;
      
      // Skip legitimate services
      if (isLegitimateExternalService(formUrl.hostname)) {
        return;
      }
      
      // Skip tracking-only forms
      if (isTrackingForm(action)) {
        return;
      }
      
      const hasPassword = form.querySelector('input[type="password"]');
      const hasPaymentFields = form.querySelector('input[name*="card"], input[name*="cvv"], input[name*="cvc"]');
      const style = window.getComputedStyle(form);
      const isHidden = style.display === 'none' || style.visibility === 'hidden';
      
      // Only flag if form is hidden AND contains sensitive fields
      if (isHidden && (hasPassword || hasPaymentFields)) {
        console.warn(`⚠️ Hidden form with sensitive fields submits externally: ${formUrl.hostname}`);
        anomalyScore += 50;
        confidenceScore += 30;
        detectedIssues.push({
          type: 'hidden_sensitive_form',
          severity: 'warning',
          message: `Hidden form with ${hasPassword ? 'password' : 'payment'} fields submits to ${formUrl.hostname}`,
          confidence: 70
        });
      }
      // Flag password forms to non-legitimate external domains
      else if (hasPassword && !isLegitimateExternalService(formUrl.hostname)) {
        // Check if different TLD (potential typosquatting)
        const currentTld = location.hostname.split('.').slice(-2).join('.');
        const formTld = formUrl.hostname.split('.').slice(-2).join('.');
        
        if (currentTld !== formTld) {
          anomalyScore += 80;
          confidenceScore += 60;
          detectedIssues.push({
            type: 'password_external_different_tld',
            severity: 'critical',
            message: `Password form submits to ${formUrl.hostname} (different TLD than ${location.hostname})`,
            confidence: 85
          });
        } else {
          // Same TLD but external - could be legitimate subdomain, lower confidence
          anomalyScore += 20;
          confidenceScore += 15;
          detectedIssues.push({
            type: 'password_external_same_tld',
            severity: 'warning',
            message: `Password form submits to ${formUrl.hostname}`,
            confidence: 40
          });
        }
      }
      // else: External form without password - informational only
    } catch (e) {
      // Invalid URL, skip
    }
  });
}

// Extract all external links and analyze their domains (refined for link patterns)
function checkExternalLinks() {
  const links = document.querySelectorAll('a[href]');
  
  links.forEach(link => {
    const href = link.getAttribute('href');
    
    try {
      const linkUrl = new URL(href, location.origin);
      
      if (linkUrl.origin !== location.origin) {
        externalLinks.push({
          url: linkUrl.href,
          domain: linkUrl.hostname,
          text: link.textContent.trim().substring(0, 50),
          isVisible: isElementVisible(link)
        });
        
        // Only flag suspicious domains (URL shorteners, high-risk TLDs, typosquatting)
        if (isSuspiciousDomain(linkUrl.hostname)) {
          anomalyScore += 10;
          confidenceScore += 5;
          detectedIssues.push({
            type: 'suspicious_link',
            severity: 'warning',
            message: `Suspicious external link: ${linkUrl.hostname}`,
            confidence: 30
          });
        }
      }
    } catch (e) {
      // Invalid URL, skip
    }
  });
  
}

// Check for suspicious domain patterns (refined for link pattern analysis)
function isSuspiciousDomain(hostname) {
  // Skip legitimate services
  if (isLegitimateExternalService(hostname)) return false;
  
  // Check for high-risk TLDs (known for abuse)
  const hasHighRiskTld = HIGH_RISK_TLDS.some(tld => hostname.endsWith(tld));
  
  // Check for URL shorteners (potential obfuscation)
  const isUrlShortener = /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.link|tiny\.cc|is\.gd|buff\.ly/gi.test(hostname);
  
  // Check for typosquatting indicators:
  // - Very short domains with high-risk TLDs
  // - Homograph attacks (mixed scripts, lookalike characters)
  const isVeryShort = /^[a-z0-9-]{1,8}\.[a-z]{2,3}$/gi.test(hostname);
  const hasMixedScripts = /[а-яё]/gi.test(hostname) || /[α-ω]/gi.test(hostname);
  const hasLookalikeChars = /[0-9]/.test(hostname) && /[oOlI1]/.test(hostname); // 0/O, 1/l/I confusion
  
  // Flag if: high-risk TLD, URL shortener, or typosquatting indicators
  return hasHighRiskTld || isUrlShortener || (isVeryShort && hasHighRiskTld) || hasMixedScripts || hasLookalikeChars;
}

// Intercept network requests to detect POST exfiltration 
function interceptNetworkRequests() {
  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = function(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    
    if (method === 'POST') {
      try {
        const requestUrl = typeof url === 'string' ? url : url.href;
        const reqUrl = new URL(requestUrl, location.origin);
        
        // Skip legitimate services
        if (reqUrl.origin !== location.origin && !isLegitimateExternalService(reqUrl.hostname)) {
          externalPosts.push({
            url: reqUrl.href,
            domain: reqUrl.hostname,
            method: 'fetch',
            timestamp: Date.now()
          });
          
          // Only flag if sensitive data detected AND not legitimate service
          if (options.body) {
            const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
            if (containsSensitiveData(bodyStr)) {
              anomalyScore += 60;
              confidenceScore += 50;
              detectedIssues.push({
                type: 'sensitive_data_exfiltration',
                severity: 'critical',
                message: `POSTing sensitive data to ${reqUrl.hostname}`,
                confidence: 80
              });
            }
          }
        }
      } catch (e) {
        // Invalid URL, continue
      }
    }
    
    return originalFetch.apply(this, arguments);
  };
  
  // Intercept XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._method = method;
    this._url = url;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };
  
  XMLHttpRequest.prototype.send = function(data) {
    if (this._method && this._method.toUpperCase() === 'POST') {
      try {
        const reqUrl = new URL(this._url, location.origin);
        
        // Skip legitimate services
        if (reqUrl.origin !== location.origin && !isLegitimateExternalService(reqUrl.hostname)) {
          externalPosts.push({
            url: reqUrl.href,
            domain: reqUrl.hostname,
            method: 'xhr',
            timestamp: Date.now()
          });
          
          // Only flag if sensitive data detected
          if (data && containsSensitiveData(data.toString())) {
            anomalyScore += 60;
            confidenceScore += 50;
            detectedIssues.push({
              type: 'sensitive_data_exfiltration',
              severity: 'critical',
              message: `POSTing sensitive data via XHR to ${reqUrl.hostname}`,
              confidence: 80
            });
          }
        }
      } catch (e) {
        // Invalid URL, continue
      }
    }
    
    return originalXHRSend.apply(this, arguments);
  };
}

// Helper to check if body contains sensitive data
function containsSensitiveData(str) {
  const lower = str.toLowerCase();
  const sensitivePatterns = [
    'password',
    'credit',
    'ssn',
    'social',
    'pin',
    'cvv',
    'cvc',
    'expiration',
    'card',
    'account',
    'routing'
  ];
  
  return sensitivePatterns.some(pattern => lower.includes(pattern));
}

// Listen for custom trigger events (for manual re-analysis)
window.addEventListener('heuristics-trigger', () => {
  setTimeout(() => {
    anomalyScore = 0;
    confidenceScore = 0;
    detectedIssues = [];
    externalLinks = [];
    externalPosts = [];
    
    checkFormSubmissions();
    checkExternalLinks();
    interceptNetworkRequests();
    
    const results = compileResults();
  }, 100);
});

// Helper to check if element is visible
function isElementVisible(element) {
  const style = window.getComputedStyle(element);
  return style.display !== 'none' && 
         style.visibility !== 'hidden' &&
         parseFloat(style.opacity) > 0;
}

// Compile all results with detailed information
function compileResults() {
  const severity = determineSeverity(anomalyScore);
  
  // Get detailed form information
  const forms = Array.from(document.querySelectorAll('form')).map((form, idx) => {
    const action = form.getAttribute('action') || '';
    try {
      const formUrl = new URL(action, location.origin);
      const isExternal = formUrl.origin !== location.origin;
      const hasPassword = form.querySelector('input[type="password"]') !== null;
      const style = window.getComputedStyle(form);
      const isHidden = style.display === 'none' || style.visibility === 'hidden';
      
      return {
        index: idx,
        action: action,
        isExternal: isExternal,
        targetDomain: isExternal ? formUrl.hostname : null,
        hasPassword: hasPassword,
        isHidden: isHidden,
        inputCount: form.querySelectorAll('input').length,
        method: form.getAttribute('method') || 'GET'
      };
    } catch (e) {
      return {
        index: idx,
        action: action,
        isExternal: false,
        error: 'Invalid URL'
      };
    }
  });
  
  // Get detailed link information
  const linkDetails = externalLinks.map((link, idx) => ({
    index: idx,
    url: link.url,
    domain: link.domain,
    text: link.text,
    isVisible: link.isVisible,
    isSuspicious: isSuspiciousDomain(link.domain)
  }));
  
  // Get iframe information
  const iframes = Array.from(document.querySelectorAll('iframe')).map((iframe, idx) => {
    const style = window.getComputedStyle(iframe);
    const isHidden = style.display === 'none' || 
                     style.visibility === 'hidden' ||
                     parseFloat(style.opacity) === 0;
    try {
      if (iframe.src) {
        const iframeUrl = new URL(iframe.src, location.origin);
        return {
          index: idx,
          src: iframe.src,
          isExternal: iframeUrl.origin !== location.origin,
          targetDomain: iframeUrl.origin !== location.origin ? iframeUrl.hostname : null,
          isHidden: isHidden
        };
      }
    } catch (e) {}
    return {
      index: idx,
      src: iframe.src || 'none',
      isHidden: isHidden
    };
  });
  
  return {
    anomalyScore,
    confidenceScore,
    severity,
    externalPosts: externalPosts.length,
    externalLinks: externalLinks.length,
    linkDomains: [...new Set(externalLinks.map(l => l.domain))],
    detectedIssues,
    timestamp: Date.now(),
    // Detailed analysis data for academic purposes
    detailedAnalysis: {
      forms: forms,
      links: linkDetails,
      iframes: iframes,
      externalPosts: externalPosts,
      totalForms: forms.length,
      totalLinks: document.querySelectorAll('a[href]').length,
      totalIframes: iframes.length,
      pageUrl: window.location.href,
      pageTitle: document.title,
      domainCounts: (() => {
        const counts = {};
        externalLinks.forEach(link => {
          counts[link.domain] = (counts[link.domain] || 0) + 1;
        });
        return counts;
      })()
    }
  };
}

// Determine severity based on score and confidence
function determineSeverity(score) {
  // Use confidence-adjusted scoring
  const adjustedScore = score * (confidenceScore / 100);
  
  if (adjustedScore >= 80 || (score >= 100 && confidenceScore >= 60)) return 'critical';
  if (adjustedScore >= 40 || (score >= 50 && confidenceScore >= 40)) return 'warning';
  if (score >= 20) return 'warning';
  return 'secure';
}

// Export for content script use
if (typeof window !== 'undefined') {
  
  // Run heuristics initialization
  function runInit() {
    initHeuristics().then(results => {
      if (results) {
        lastResults = results;    
      } 
    }).catch(err => {
    });
  }
  
  // Run heuristics on DOMContentLoaded or immediately if already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(runInit, 500); // Wait for page to settle
    });
  } else {
    // Page already loaded, run immediately
    setTimeout(runInit, 500);
  }
}

function scanDomInjectionPatterns() {
  const issues = [];
  let score = 0;

  // 1) Any inline event handlers: onclick, onload, onerror, etc.
  const inlineHandlers = [];
  document.querySelectorAll("*").forEach(el => {
    for (const attr of el.getAttributeNames()) {
      if (attr.toLowerCase().startsWith("on")) {
        inlineHandlers.push({ el, attr });
        break;
      }
    }
  });
  if (inlineHandlers.length) {
    score += Math.min(35, 5 + inlineHandlers.length * 2);
    issues.push({
      type: "inline_event_handler",
      severity: "warning",
      message: `Found ${inlineHandlers.length} inline on* event handler(s) (e.g., onclick="...").`,
      confidence: 70
    });
  }

  // 2) javascript: URLs
  const jsHrefs = Array.from(document.querySelectorAll('a[href]'))
    .filter(a => /^javascript:/i.test(a.getAttribute("href") || ""));
  if (jsHrefs.length) {
    score += Math.min(30, 10 + jsHrefs.length * 3);
    issues.push({
      type: "javascript_url",
      severity: "warning",
      message: `Found ${jsHrefs.length} link(s) with javascript: in href.`,
      confidence: 75
    });
  }

  // 3) Iframes without sandbox
  const badIframes = Array.from(document.querySelectorAll("iframe"))
    .filter(f => !f.hasAttribute("sandbox"));
  if (badIframes.length) {
    score += Math.min(35, 15 + badIframes.length * 5);
    issues.push({
      type: "iframe_without_sandbox",
      severity: "warning",
      message: `Found ${badIframes.length} iframe(s) without sandbox attribute.`,
      confidence: 70
    });
  }

  // 4) style="...url(...)" patterns
  const styleUrl = Array.from(document.querySelectorAll("[style]"))
    .filter(el => /url\s*\(/i.test(el.getAttribute("style") || ""));
  if (styleUrl.length) {
    score += Math.min(25, 10 + styleUrl.length * 2);
    issues.push({
      type: "style_url",
      severity: "warning",
      message: `Found ${styleUrl.length} element(s) whose inline style contains url(...).`,
      confidence: 60
    });
  }

  // 5) Script tags (for demo: flag any script tags with text OR non-empty src)
  const suspiciousScripts = Array.from(document.scripts).filter(s => {
    const hasSrc = !!(s.getAttribute("src") || "").trim();
    const hasInline = !!(s.textContent || "").trim();
    return hasSrc || hasInline;
  });
  if (suspiciousScripts.length) {
    score += Math.min(40, 15 + suspiciousScripts.length * 4);
    issues.push({
      type: "script_present",
      severity: "warning",
      message: `Detected ${suspiciousScripts.length} script tag(s) (inline and/or external).`,
      confidence: 55
    });
  }

  return { score, issues };
}


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type !== "GET_DOM_AND_PERMISSIONS") return;

  (async () => {
    // Ensure we have results; if not, run analysis once
    // Do NOT re-run heuristics here.
    // Just wait until initial analysis is ready.
    if (!lastResults) {
      sendResponse({
        anomalyScore: clamp(lastResults.anomalyScore ?? 0, 0, 100),
      domIssues: lastResults.detectedIssues ?? [],
      sitePermissions
      });
      return;
    }


    const sitePermissions = await getSitePermissionsBestEffort();

    const domScan = scanDomInjectionPatterns();
    const phishingScore = clamp(lastResults?.anomalyScore ?? 0, 0, 100);
    const combinedScore = clamp(phishingScore + domScan.score, 0, 100);

    sendResponse({
      anomalyScore: combinedScore,
      domIssues: [
        ...(lastResults?.detectedIssues ?? []),
        ...domScan.issues
      ],
      sitePermissions
    });

  })();

  return true; // keep channel open
});

function clamp(n, min, max) {
  const x = Number(n);
  if (Number.isNaN(x)) return min;
  return Math.max(min, Math.min(max, x));
}


async function getSitePermissionsBestEffort() {
  const perms = [];

  // 1) Notifications (most reliable)
  try {
    perms.push({ name: "Notifications", state: Notification.permission }); 
    // granted | denied | default
  } catch {
    perms.push({ name: "Notifications", state: "unknown" });
  }

  // 2) Permissions API checks (best-effort)
  // Some permission names aren't supported in every browser
  const candidates = [
    { key: "geolocation", label: "Location" },
    { key: "camera", label: "Camera" },
    { key: "microphone", label: "Microphone" },
    { key: "clipboard-read", label: "Clipboard Read" },
    { key: "clipboard-write", label: "Clipboard Write" },
  ];

  if (!navigator.permissions || !navigator.permissions.query) {
    // Permissions API not available
    // Return what we have (Notifications)
    return perms;
  }

  for (const p of candidates) {
    try {
      const result = await navigator.permissions.query({ name: p.key });
      perms.push({ name: p.label, state: result.state }); 
      // granted | denied | prompt (sometimes)
    } catch {
      // Not supported in this browser/context -> show as Unknown
      perms.push({ name: p.label, state: "unknown" });
    }
  }

  return perms;
}



