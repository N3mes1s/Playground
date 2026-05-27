const { chromium } = require('playwright');
const path = require('path');

const root = path.dirname(__filename);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

  const pages = [
    { html: 'landing.html', out: 'screenshots/landing.png', fullPage: true, width: 1280 },
    { html: 'app.html', out: 'screenshots/app.png', fullPage: true, width: 1440 },
    { html: 'email_weekly.html', out: 'screenshots/email_weekly.png', fullPage: true, width: 700 },
  ];

  for (const p of pages) {
    const page = await ctx.newPage();
    await page.setViewportSize({ width: p.width, height: 900 });
    await page.goto('file://' + path.join(root, p.html));
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(root, p.out), fullPage: p.fullPage });
    console.log('wrote', p.out);
    await page.close();
  }
  await browser.close();
})();
