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
  console.log('🔍 Initializing heuristics engine');
  
  // Always run initial analysis - background will filter by active tab
  anomalyScore = 0;
  externalLinks = [];
  externalPosts = [];
  detectedIssues = [];
  
  // Run all heuristics
  checkFormSubmissions();
  checkExternalLinks();
  interceptNetworkRequests();
  analyzeLinkPatterns();
  
  // Collect results
  const results = compileResults();
  lastResults = results;
  
  // Report to background (background will check if tab is active)
  reportToBackground(results);
  
  console.log('✅ Heuristics analysis complete:', {
    score: results.anomalyScore,
    severity: results.severity,
    issues: results.detectedIssues.length
  });
  
  return results;
}

// Check if current tab is active
async function checkIfActiveTab() {
  return new Promise((resolve) => {
    // First try to get tab ID from chrome.tabs
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        console.log('Error checking active tab:', chrome.runtime.lastError);
        // Fallback: assume active if we can't check
        resolve(true);
        return;
      }
      
      const currentTab = tabs[0];
      if (!currentTab) {
        resolve(false);
        return;
      }
      
      // Get this page's tab ID
      chrome.runtime.sendMessage({ action: 'getTabId' }, (response) => {
        if (chrome.runtime.lastError) {
          // If message fails, assume we're active (fallback)
          console.log('Could not verify tab ID, assuming active');
          resolve(true);
          return;
        }
        
        const thisTabId = response?.tabId;
        const isActive = thisTabId === currentTab.id;
        resolve(isActive);
      });
    });
  });
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
          console.warn(`🚨 Password form submits to different TLD: ${formUrl.hostname}`);
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
          console.log(`⚠️ Password form submits externally (same TLD): ${formUrl.hostname}`);
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
      // External form without password - informational only
      else {
        console.log(`ℹ️ External form submission (no sensitive fields): ${formUrl.hostname}`);
        // Don't add to score, just log
      }
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
          // Reduced score - link patterns are analyzed in analyzeLinkPatterns()
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
  
  // Analyze link patterns (clone detection, URL shortener chains, typosquatting)
  analyzeLinkPatterns();
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
            console.warn(`⚠️ Sensitive data XHR POST to external domain: ${reqUrl.hostname}`);
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

// Analyze link patterns for anomalies (refined for typosquatting and clone detection)
function analyzeLinkPatterns() {
  if (externalLinks.length === 0) return;
  
  // Filter out legitimate domains
  const suspiciousLinks = externalLinks.filter(link => 
    !isLegitimateExternalService(link.domain) && 
    !KNOWN_GOOD_DOMAINS.some(domain => link.domain.includes(domain))
  );
  
  if (suspiciousLinks.length === 0) return;
  
  const domainCounts = {};
  suspiciousLinks.forEach(link => {
    domainCounts[link.domain] = (domainCounts[link.domain] || 0) + 1;
  });
  
  const totalLinks = document.querySelectorAll('a[href]').length;
  
  // CRITICAL: Clone pattern detection - >70% of links point to single external domain
  // This indicates a full-site clone/phishing attempt
  Object.entries(domainCounts).forEach(([domain, count]) => {
    const percentage = (count / totalLinks) * 100;
    if (percentage > 70 && count > 5) {
      console.warn(`🚨 CRITICAL: ${percentage.toFixed(1)}% of links point to ${domain} (likely clone)`);
      anomalyScore += 100;
      confidenceScore += 80;
      detectedIssues.push({
        type: 'link_clone_pattern',
        severity: 'critical',
        message: `${count} links (${percentage.toFixed(1)}%) point to ${domain} - possible site clone`,
        confidence: 85
      });
    }
  });
  
  // WARNING: URL shortener chains - multiple different shortener services
  // Indicates potential obfuscation of malicious URLs
  const shortenedLinks = suspiciousLinks.filter(link => 
    /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.link|tiny\.cc|is\.gd|buff\.ly/gi.test(link.url)
  );
  
  const uniqueShorteners = new Set(shortenedLinks.map(l => l.domain));
  if (uniqueShorteners.size > 2) {
    console.warn(`⚠️ Multiple URL shorteners detected: ${uniqueShorteners.size} different services`);
    anomalyScore += 25;
    confidenceScore += 20;
    detectedIssues.push({
      type: 'url_shortener_chain',
      severity: 'warning',
      message: `Multiple URL shorteners detected (${uniqueShorteners.size} different services) - potential obfuscation`,
      confidence: 50
    });
  }
  
  // Check for typosquatting patterns
  // Look for domains that are very similar to the current domain
  const currentDomain = location.hostname.toLowerCase();
  const currentDomainParts = currentDomain.split('.');
  const currentBaseDomain = currentDomainParts.length > 1 
    ? currentDomainParts.slice(-2).join('.') 
    : currentDomain;
  
  suspiciousLinks.forEach(link => {
    const linkDomain = link.domain.toLowerCase();
    const linkDomainParts = linkDomain.split('.');
    const linkBaseDomain = linkDomainParts.length > 1 
      ? linkDomainParts.slice(-2).join('.') 
      : linkDomain;
    
    // Check for typosquatting: similar domain name but different TLD or slight variations
    if (linkBaseDomain !== currentBaseDomain && 
        linkBaseDomain.length > 0 && 
        currentBaseDomain.length > 0) {
      // Calculate similarity (simple Levenshtein-like check)
      const similarity = calculateDomainSimilarity(currentBaseDomain, linkBaseDomain);
      
      // Flag if domain is very similar (>80% similarity) but different
      if (similarity > 0.8 && similarity < 1.0) {
        console.warn(`⚠️ Possible typosquatting: ${linkBaseDomain} similar to ${currentBaseDomain} (${(similarity * 100).toFixed(0)}% similar)`);
        anomalyScore += 30;
        confidenceScore += 25;
        detectedIssues.push({
          type: 'typosquatting',
          severity: 'warning',
          message: `Suspicious domain similar to current site: ${linkBaseDomain}`,
          confidence: 60
        });
      }
    }
  });
}

// Calculate domain similarity (0-1 scale)
function calculateDomainSimilarity(domain1, domain2) {
  // Remove TLD for comparison
  const d1 = domain1.split('.').slice(0, -1).join('.');
  const d2 = domain2.split('.').slice(0, -1).join('.');
  
  if (d1 === d2) return 1.0;
  if (d1.length === 0 || d2.length === 0) return 0;
  
  // Simple character overlap check
  const longer = d1.length > d2.length ? d1 : d2;
  const shorter = d1.length > d2.length ? d2 : d1;
  
  let matches = 0;
  for (let i = 0; i < shorter.length; i++) {
    if (longer.includes(shorter[i])) matches++;
  }
  
  // Also check for common substrings
  let maxCommonSubstring = 0;
  for (let i = 0; i < shorter.length; i++) {
    for (let j = i + 1; j <= shorter.length; j++) {
      const substr = shorter.substring(i, j);
      if (longer.includes(substr) && substr.length > maxCommonSubstring) {
        maxCommonSubstring = substr.length;
      }
    }
  }
  
  // Combine character overlap and common substring
  const charSimilarity = matches / longer.length;
  const substringSimilarity = maxCommonSubstring / longer.length;
  
  return Math.max(charSimilarity, substringSimilarity);
}

// Listen for custom trigger events (for manual re-analysis)
window.addEventListener('heuristics-trigger', () => {
  console.log('🔄 Manual heuristics trigger received');
  setTimeout(() => {
    anomalyScore = 0;
    confidenceScore = 0;
    detectedIssues = [];
    externalLinks = [];
    externalPosts = [];
    
    checkFormSubmissions();
    checkExternalLinks();
    interceptNetworkRequests();
    analyzeLinkPatterns();
    
    const results = compileResults();
    reportToBackground(results);
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

// Report results to background script
function reportToBackground(results) {
  console.log('📤 Reporting heuristics results to background:', {
    score: results.anomalyScore,
    severity: results.severity,
    issues: results.detectedIssues.length
  });
  
  chrome.runtime.sendMessage({
    action: 'heuristicsResults',
    data: results
  }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('❌ Error sending heuristics results:', chrome.runtime.lastError.message);
    } else {
      console.log('✅ Heuristics results sent successfully');
    }
  });
}

// Export for content script use
if (typeof window !== 'undefined') {
  console.log('🔍 Heuristics engine loaded, initializing...');
  
  // Run heuristics initialization
  function runInit() {
    console.log('🚀 Starting heuristics initialization...');
    initHeuristics().then(results => {
      if (results) {
        lastResults = results;    
      } 
    }).catch(err => {
      console.error('❌ Error initializing heuristics:', err);
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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type !== "GET_DOM_AND_PERMISSIONS") return;

  (async () => {
    // Ensure we have results; if not, run analysis once
    // Do NOT re-run heuristics here.
    // Just wait until initial analysis is ready.
    if (!lastResults) {
      sendResponse({
        anomalyScore: 0,
        domIssues: [],
        sitePermissions: []
      });
      return;
    }


    const sitePermissions = await getSitePermissionsBestEffort();
    sendResponse({
      anomalyScore: clamp(lastResults.anomalyScore ?? 0, 0, 100),
      domIssues: lastResults.detectedIssues ?? [],
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

  // Helper: safe query wrapper
  async function tryQuery(name, label = null) {
    try {
      // Some browsers require exact permission names; if unsupported, it throws.
      const res = await navigator.permissions.query({ name });
      perms.push({ name: label || prettyLabel(name), state: res.state });
    } catch {
      // If query isn't supported, report "unknown" (or skip if you prefer)
      perms.push({ name: label || prettyLabel(name), state: "unknown" });
    }
  }

  // Notifications (special: doesn't use navigator.permissions consistently)
  try {
    perms.push({ name: "Notifications", state: Notification.permission }); // granted/denied/default
  } catch {
    perms.push({ name: "Notifications", state: "unknown" });
  }

  // Location (usually supported)
  await tryQuery("geolocation", "Location");

  // Optional best-effort (support varies)
  await tryQuery("camera", "Camera");
  await tryQuery("microphone", "Microphone");

  // Clipboard (often unsupported in permission query)
  await tryQuery("clipboard-read", "Clipboard Read");
  await tryQuery("clipboard-write", "Clipboard Write");

  // Some browsers support this (varies)
  await tryQuery("persistent-storage", "Persistent Storage");

  // Normalize Notification "default" -> "prompt" to match others (optional)
  perms.forEach(p => {
    if (p.name === "Notifications" && p.state === "default") p.state = "prompt";
  });

  return perms;
}

function prettyLabel(name) {
  // fallback: title case + spaces
  return name
    .split("-")
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

async function getSitePermissionsBestEffort() {
  const perms = [];

  // Notifications 
  try {
    perms.push({ name: "Notifications", state: Notification.permission }); // granted/denied/default
  } catch {
    perms.push({ name: "Notifications", state: "unknown" });
  }

  // Geolocation
  try {
    const geo = await navigator.permissions.query({ name: "geolocation" });
    perms.push({ name: "Location", state: geo.state }); // granted/denied/prompt
  } catch {
    perms.push({ name: "Location", state: "unknown" });
  }

  return perms;
}


