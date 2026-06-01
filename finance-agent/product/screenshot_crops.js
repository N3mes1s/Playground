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

  // Crop 1: top stats + flow + kalshi (the new content)
  await page.screenshot({
    path: path.join(root, 'screenshots/app_top.png'),
    clip: { x: 0, y: 0, width: 1440, height: 1100 }
  });
  console.log('wrote app_top.png');

  // Crop 2: macro scan + positions/triggers (middle)
  await page.screenshot({
    path: path.join(root, 'screenshots/app_middle.png'),
    clip: { x: 0, y: 1100, width: 1440, height: 1100 }
  });
  console.log('wrote app_middle.png');

  // Crop 3: journal + playbook
  await page.screenshot({
    path: path.join(root, 'screenshots/app_journal.png'),
    clip: { x: 0, y: 2200, width: 1440, height: 1000 }
  });
  console.log('wrote app_journal.png');

  await browser.close();
})();
