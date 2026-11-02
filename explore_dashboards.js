const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  const dashboards = [
    'https://dashboard.f1.hotgame.win',
    'https://dashboard.f2.hotgame.win',
    'https://dashboard.s1.hotgame.win',
    'https://dashboard.s2.hotgame.win'
  ];
  
  for (const baseUrl of dashboards) {
    console.log(`\n{'='.repeat(60)}`);
    console.log(`EXPLORING: ${baseUrl}`);
    console.log(`{'='.repeat(60)}`);
    
    try {
      await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 30000 });
      
      // Get all script src URLs
      const scripts = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
      });
      console.log('\n[SCRIPT TAGS]:', scripts);
      
      // Get all network requests
      const resources = [];
      page.on('response', response => {
        resources.push({ url: response.url(), status: response.status(), type: response.request().resourceType() });
      });
      
      await page.waitForTimeout(3000);
      
      // Filter for JS files
      const jsResources = resources.filter(r => r.type === 'script' || r.url.endsWith('.js'));
      console.log('\n[JS RESOURCES]:');
      jsResources.forEach(r => console.log(`  ${r.status} ${r.url}`));
      
      // Fetch and analyze main JS bundle
      for (const scriptUrl of scripts) {
        if (scriptUrl.includes('umi') || scriptUrl.includes('.js')) {
          console.log(`\n[FETCHING] ${scriptUrl}`);
          try {
            const content = await page.evaluate(async (url) => {
              const res = await fetch(url, { credentials: 'include' });
              return await res.text();
            }, scriptUrl);
            
            // Search for API endpoints, base URLs, secrets
            const apiMatches = content.match(/["'`](\/api\/[^"'`]+)["'`]/g) || [];
            const urlMatches = content.match(/["'`](https?:\/\/[^"'`]+\.hotgame\.win[^"'`]*)["'`]/g) || [];
            const baseUrlMatches = content.match(/(baseURL|apiBase|serverUrl|host)["'`]\s*:\s*["'`]([^"'`]+)["'`]/g) || [];
            const secretMatches = content.match(/(apiKey|secret|token|password|jwt)["'`]\s*:\s*["'`]([^"'`]+)["'`]/gi) || [];
            
            if (apiMatches.length) console.log('  [API ENDPOINTS]:', [...new Set(apiMatches)]);
            if (urlMatches.length) console.log('  [HOTGAME URLS]:', [...new Set(urlMatches)]);
            if (baseUrlMatches.length) console.log('  [BASE URL CONFIGS]:', baseUrlMatches);
            if (secretMatches.length) console.log('  [POSSIBLE SECRETS]:', secretMatches);
            
            // Check for upload logic
            if (content.includes('finishChunk') || content.includes('startChunk') || content.includes('upload')) {
              console.log('  [UPLOAD LOGIC FOUND]');
              // Extract relevant functions
              const uploadFuncs = content.match(/function\s+\w*[Uu]pload\w*\([^)]*\)\s*\{[^}]+\}/g) || 
                                 content.match(/\w*[Uu]pload\w*\s*:\s*function\([^)]*\)\s*\{[^}]+\}/g) ||
                                 content.match(/const\s+\w*[Uu]pload\w*\s*=\s*\([^)]*\)\s*=>\s*\{[^}]+\}/g) || [];
              if (uploadFuncs.length) console.log('  [UPLOAD FUNCTIONS]:', uploadFuncs.slice(0, 3));
            }
            
          } catch (e) {
            console.log(`  [ERROR] ${e.message}`);
          }
        }
      }
      
      // Check for any API calls made by the page
      const apiCalls = resources.filter(r => r.url.includes('/api/') && r.url.includes('hotgame.win'));
      if (apiCalls.length) {
        console.log('\n[API CALLS MADE BY PAGE]:');
        apiCalls.forEach(r => console.log(`  ${r.status} ${r.url}`));
      }
      
    } catch (e) {
      console.log(`[ERROR] ${baseUrl}: ${e.message}`);
    }
  }
  
  await browser.close();
})();