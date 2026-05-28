---
name: video-account-monitor
description: Use when monitoring creator/video accounts on Bilibili, Douyin, Kuaishou, or Xiaohongshu, especially for account URLs, browser login sessions, follower counts, video counts, likes, views, comments, per-video metrics, HTML dashboards, JSON exports, or CSV tables.
---

# Video Account Monitor

Collect creator-account metrics into one schema and export `summary.json`, `videos.json`, `videos.csv`, and `report.html`. By default, each platform collects the latest 200 videos unless `--limit` is provided. The required per-video fields are `likes`, `views`, and `comments`.

## Install

Run from this skill directory:

```bash
npm install
```

Real collection for every platform opens a visible Playwright browser session. `npm install` installs the Playwright package declared by this skill, and the collector launches local Google Chrome by default. Install Chrome on the machine before real collection.

For Xiaohongshu signed API collection, install the Python signing dependency with the same interpreter that will be used by `XHS_PYTHON`:

```bash
/path/to/python -m pip install -r requirements.txt
```

Set `XHS_PYTHON` to an absolute local interpreter path before running Xiaohongshu signed API collection:

```bash
XHS_PYTHON="/path/to/python" node scripts/monitor.mjs --platform xiaohongshu --account "ACCOUNT_URL_OR_ID" --profile ./private/profiles/xiaohongshu --out ./outputs/account
```

## Quick Start

Run from this skill directory:

```bash
node scripts/monitor.mjs --platform bilibili --account "https://space.bilibili.com/470995011" --out ./outputs/caiyaqi
```

Demo without network:

```bash
npm run demo
```

With a user-controlled browser login session:

```bash
node scripts/monitor.mjs --platform kuaishou --account "ACCOUNT_URL_OR_ID" --profile ./private/profiles/kuaishou --out ./outputs/account
```

Real collection always opens a visible browser login session. The CLI reuses the chosen browser profile on later runs. If Chrome is not available, install Google Chrome first, or change the browser launch configuration in `scripts/monitor.mjs` to a locally installed Playwright browser.

## Platform Status

The skill accepts all four platforms through the same CLI and output schema. Native collection status is:

| Platform | Native Adapter | Notes |
|---|---:|---|
| Bilibili | implemented | Uses public web APIs plus optional cookies/browser auth. Risk-control can still interrupt large accounts. |
| Douyin | implemented | Uses a_bogus signing (douyin.js). Requires cookies with msToken or browser auth. |
| Kuaishou | implemented | GraphQL POST. Supports cookies/browser auth. Tries the profile video list first; if that endpoint is risk-controlled, falls back to creator-name search and exact author-id filtering. Fallback rows are partial and marked with `collectionStatus: "partial"`. |
| Xiaohongshu | implemented | Uses visible browser login plus xhshow Python signing. Creator-note list can collect 200 rows by default; detail metrics are fetched for up to 200 rows. Public web data does not reliably expose views. |

## Authentication

Use only user-controlled browser sessions for real collection. Never ask for passwords, SMS codes, raw cookies, or credentials. Do not commit cookies, browser profiles, exported reports containing private data, or `.env` files.

Real collection opens a visible Playwright Chrome profile, lets the user log in manually, and exports cookies from that profile for the native adapters. The required Node dependency is installed by `npm install` from this package.

`--profile` should point to a dedicated browser profile under `./private/`, not a daily-use browser profile. User-provided `--cookies`, `--auth cookie`, and `--auth none` are intentionally unsupported. If scan login, captcha, or risk-control appears, the user must complete it manually in the opened browser; do not automate or bypass verification. Do not route collection through MediaCrawler or another external crawler backend for this skill; implement platform behavior in the native adapter files under `scripts/adapters/`.

Do not share `private/`, `outputs/`, `node_modules/`, `__pycache__/`, `.env`, raw cookies, browser profiles, or generated reports containing private account data.

## Output Contract

Every adapter must return:

```json
{
  "account": {
    "platform": "bilibili",
    "id": "470995011",
    "url": "https://space.bilibili.com/470995011",
    "name": "Creator",
    "followers": 0,
    "videoCount": 0,
    "totalLikes": 0,
    "totalViews": 0,
    "totalComments": 0
  },
  "videos": [
    {
      "id": "VIDEO_ID",
      "title": "Title",
      "url": "https://...",
      "publishedAt": "2026-05-25T00:00:00+08:00",
      "duration": "03:21",
      "likes": 0,
      "views": 0,
      "comments": 0,
      "shares": 0,
      "favorites": 0,
      "coins": 0
    }
  ]
}
```

`comments` is mandatory in JSON, CSV, and HTML. If a platform cannot expose comments for a row, output `0` or leave the adapter blocked with a clear auth/risk-control error; do not silently omit the column.

## Common Failures

- `Bilibili risk-control response`: retry later, reduce `--limit`, or use browser login with the saved profile.
- Kuaishou `collectionStatus: "partial"`: the profile video-list GraphQL endpoint was unavailable or risk-controlled, so the adapter used creator-name search with exact author-id filtering. This can produce per-video rows, but it is not a complete account archive.
- CSV looks garbled in Excel: the script writes UTF-8 with BOM; reopen the generated `videos.csv`.

## Verification

Before claiming the skill works, run:

```bash
node scripts/monitor.test.mjs
node scripts/monitor.mjs --demo --out ./outputs/demo
```
