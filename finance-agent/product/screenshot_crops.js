const { chromium } = require('playwright');
const path = require('path');

const root = path.dirname(__filename);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

  // App dashboard — render and capture focused regions
  const page = await ctx.newPage();
  await page.setViewportSize({ width: 1440, height: 1200 });
  await page.goto('file://' + path.join(root, 'app.html'));
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1500);

  // Get full page height to clip safely
  const fullPage = await page.screenshot({ fullPage: true });
  const dimensions = await page.evaluate(() => ({ w: document.body.scrollWidth, h: document.body.scrollHeight }));
  console.log('page dims:', dimensions);

  const crops = [
    { name: 'app_hero', y: 0, h: 880 },
    { name: 'app_chart_flow', y: 880, h: 900 },
    { name: 'app_positions_journal', y: 1780, h: 1000 },
  ];

  for (const c of crops) {
    const h = Math.min(c.h, dimensions.h - c.y);
    if (h <= 0) continue;
    await page.screenshot({
      path: path.join(root, `screenshots/${c.name}.png`),
      clip: { x: 0, y: c.y, width: 1440, height: h }
    });
    console.log('wrote', c.name + '.png', `(${h}px)`);
  }

  await browser.close();
})();
