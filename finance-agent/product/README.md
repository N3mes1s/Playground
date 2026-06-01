# Levee — product surface

Static site (marketing landing + dashboard preview + email template) generated from real backtest data.

## Files

| File | Purpose |
|---|---|
| `landing.template.html` | Marketing site template with `{{...}}` placeholders |
| `app.template.html` | Subscriber dashboard template |
| `email_weekly.template.html` | Friday-close email template |
| `generate.py` | Reads `data/backtests/*/summary.json` + live Kalshi/flow data, renders the three pages |
| `landing.html`, `app.html`, `email_weekly.html` | Generated output (gitignored — rebuilt every deploy) |
| `dist/` | What gets deployed (`index.html` = `landing.html`) |
| `launch_post.md` | Substack-ready launch post with the full backtest write-up |
| `vercel.json` | Vercel deploy config |
| `netlify.toml` | Netlify deploy config (alternative) |
| `screenshot.js` | Playwright render of all 3 pages → PNG |
| `screenshots/` | Hero images for marketing |

## Local preview

```bash
cd finance-agent
python product/generate.py
open product/landing.html
```

## Deploy to Vercel (~5 min, free tier)

1. Push the repo to GitHub.
2. Go to vercel.com → New Project → Import the repo.
3. Configure: **Root Directory** = `finance-agent/product`, leave everything else default.
4. Click Deploy. Vercel reads `vercel.json` and runs the build.
5. Your site is live at `https://<project>.vercel.app`. Add a custom domain in Settings → Domains.

> The build command runs `generate.py` which fetches live Kalshi + options flow data at deploy time. Re-deploy daily (Vercel cron or GitHub Action) to keep the dashboard preview fresh.

## Deploy to Netlify (alternative)

1. Push the repo to GitHub.
2. netlify.com → Add new site → Import from GitHub.
3. Base directory: `finance-agent/product`. Build command and publish dir are read from `netlify.toml`.
4. Deploy.

## Ship the Substack launch post

1. Open `launch_post.md` in any editor.
2. Copy contents into a new Substack post.
3. Set the headline: *"The AI agent that stayed in cash through 8.6% CPI"*.
4. Substack renders markdown including the tables. Add the screenshots from `product/screenshots/` as inline images.
5. Publish + share.

## Next steps to make it real

- [ ] Choose a domain (`levee.research`, `levee.market`, etc.)
- [ ] Buy domain → point at Vercel/Netlify
- [ ] Substack publication setup (free tier OK to start)
- [ ] Email capture: replace `<form>` placeholders in `landing.template.html` with a real provider (ConvertKit, Substack, Formspree)
- [ ] Securities lawyer review of marketing copy (~$500-1500, 1-hour consultation usually enough)
- [ ] First 10 Pro subscribers from your network
