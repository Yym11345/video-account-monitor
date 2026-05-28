#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_DIR = path.dirname(__dirname);

const DEFAULT_VIDEO_LIMIT = 200;

const VIDEO_COLUMNS = [
  "platform",
  "accountId",
  "accountName",
  "id",
  "title",
  "url",
  "publishedAt",
  "duration",
  "likes",
  "views",
  "comments",
  "shares",
  "favorites",
  "coins",
];

const PLATFORM_ALIASES = {
  bilibili: "bilibili",
  bili: "bilibili",
  b: "bilibili",
  "b站": "bilibili",
  douyin: "douyin",
  dy: "douyin",
  "抖音": "douyin",
  kuaishou: "kuaishou",
  ks: "kuaishou",
  "快手": "kuaishou",
  xiaohongshu: "xiaohongshu",
  xhs: "xiaohongshu",
  "小红书": "xiaohongshu",
};

const SUPPORTED_PLATFORMS = new Set(Object.values(PLATFORM_ALIASES));

const BROWSER_AUTH = {
  bilibili: {
    startUrl: (account) => account.startsWith("http") ? account : `https://space.bilibili.com/${account}`,
    hosts: ["bilibili.com"],
    loginCookies: ["SESSDATA", "DedeUserID"],
  },
  douyin: {
    startUrl: (account) => account.startsWith("http") ? account : "https://www.douyin.com",
    hosts: ["douyin.com"],
    loginCookies: ["sessionid", "sid_guard", "uid_tt"],
  },
  kuaishou: {
    startUrl: (account) => account.startsWith("http") ? account : `https://www.kuaishou.com/profile/${account}`,
    hosts: ["kuaishou.com"],
    loginCookies: ["passToken"],
  },
  xiaohongshu: {
    startUrl: (account) => account.startsWith("http") ? account : "https://www.xiaohongshu.com",
    hosts: ["xiaohongshu.com", "xhslink.com"],
    loginCookies: ["web_session", "a1"],
  },
};

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      continue;
    }
    const equalsIndex = token.indexOf("=");
    if (equalsIndex > 2) {
      args[token.slice(2, equalsIndex)] = token.slice(equalsIndex + 1);
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[key] = true;
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

function usage() {
  return `Usage:
  node scripts/monitor.mjs --platform bilibili --account URL_OR_ID --out ./outputs/name
  node scripts/monitor.mjs --platform kuaishou --account URL_OR_ID --profile ./private/profiles/kuaishou --out ./outputs/name
  node scripts/monitor.mjs --demo --out ./outputs/demo

Options:
  --platform       bilibili | douyin | kuaishou | xiaohongshu
  --account        Account URL, profile URL, or platform account id
  --profile        Optional browser profile directory for authenticated browser collection.
  --auth           Optional; only browser is supported for real collection.
  --out            Output directory. Defaults to ./outputs/video-account-monitor-<timestamp>
  --limit          Max recent videos to collect (default 200)
  --delay          Request interval in ms (default 3000). Increase to avoid risk-control.
  --demo           Generate a deterministic demo report without network access`;
}

function asNumber(value, fallback = 0) {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  const n = Number(String(value).replace(/,/g, ""));
  return Number.isFinite(n) ? n : fallback;
}

function normalizeVideo(video, account) {
  return {
    platform: video.platform || account.platform || "",
    accountId: video.accountId || account.id || "",
    accountName: video.accountName || account.name || "",
    id: String(video.id || video.bvid || video.awemeId || video.noteId || ""),
    title: String(video.title || ""),
    url: redactSensitiveText(String(video.url || "")),
    publishedAt: String(video.publishedAt || video.createdAt || ""),
    duration: String(video.duration || ""),
    likes: asNumber(video.likes ?? video.like),
    views: asNumber(video.views ?? video.play ?? video.view),
    comments: asNumber(video.comments ?? video.comment ?? video.reply),
    shares: asNumber(video.shares ?? video.share),
    favorites: asNumber(video.favorites ?? video.favorite ?? video.collect),
    coins: asNumber(video.coins ?? video.coin),
  };
}

export function normalizeDataset(input) {
  const account = {
    platform: String(input.account?.platform || ""),
    id: String(input.account?.id || ""),
    url: redactSensitiveText(String(input.account?.url || "")),
    name: String(input.account?.name || ""),
    followers: asNumber(input.account?.followers),
    following: asNumber(input.account?.following),
    videoCount: asNumber(input.account?.videoCount ?? input.videos?.length),
    totalLikes: asNumber(input.account?.totalLikes),
    totalViews: asNumber(input.account?.totalViews),
    totalComments: asNumber(input.account?.totalComments),
    collectionStatus: String(input.account?.collectionStatus || "complete"),
    warnings: Array.isArray(input.account?.warnings) ? input.account.warnings.map((warning) => redactSensitiveText(warning)) : [],
    fetchedAt: input.account?.fetchedAt || new Date().toISOString(),
  };
  const videos = (input.videos || []).map((video) => normalizeVideo(video, account));
  account.videoCount = account.videoCount || videos.length;
  account.totalLikes = account.totalLikes || videos.reduce((sum, item) => sum + item.likes, 0);
  account.totalViews = account.totalViews || videos.reduce((sum, item) => sum + item.views, 0);
  account.totalComments = account.totalComments || videos.reduce((sum, item) => sum + item.comments, 0);
  return { account, videos };
}

function csvEscape(value) {
  const text = String(value ?? "");
  const safeText = /^(?:[=+\-@]|\t|\r|\n|\s+[=+\-@])/.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safeText) ? `"${safeText.replace(/"/g, '""')}"` : safeText;
}

function safeHref(value) {
  const text = String(value || "");
  try {
    const url = new URL(text);
    return url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(asNumber(value));
}

function redactSensitiveText(value) {
  return String(value || "")
    .replace(/([?&]xsec_token=)[^&\s)]+/gi, "$1REDACTED")
    .replace(/(%3[FfAa]|[?&,\s\{\[])(xsec_token)(%3[Dd]|=)([^&\s,\}\]]+)/gi, "$1$2$3REDACTED")
    .replace(/(["']xsec_token["']\s*:\s*["'])[^"']+/gi, "$1REDACTED")
    .replace(/(Cookie\s*:\s*)[^\r\n]+/gi, "$1REDACTED")
    .replace(/\b(a1|web_session|sessionid|sid_guard|uid_tt|msToken)=([^;,\s]+)/gi, "$1=REDACTED");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderHtml(dataset) {
  const { account, videos } = dataset;
  const warnings = account.warnings || [];
  const warningHtml = warnings.length > 0
    ? `<section class="warning"><strong>Partial data:</strong> ${escapeHtml(warnings.join(" "))}</section>`
    : "";
  const rows = videos.map((video) => `
          <tr>
            <td>${safeHref(video.url) ? `<a href="${escapeHtml(safeHref(video.url))}">${escapeHtml(video.id)}</a>` : escapeHtml(video.id)}</td>
            <td>${escapeHtml(video.title)}</td>
            <td>${escapeHtml(video.publishedAt)}</td>
            <td>${formatNumber(video.views)}</td>
            <td>${formatNumber(video.likes)}</td>
            <td>${formatNumber(video.comments)}</td>
            <td>${formatNumber(video.shares)}</td>
            <td>${formatNumber(video.favorites)}</td>
          </tr>`).join("");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(account.name || account.id)} Video Account Monitor</title>
    <style>
      :root { color-scheme: light; --bg: #f7f8fa; --fg: #1f2937; --muted: #64748b; --line: #d8dee9; --brand: #2563eb; --card: #ffffff; }
      * { box-sizing: border-box; }
      body { margin: 0; font-family: Inter, Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--fg); }
      header { padding: 28px 32px 18px; background: var(--card); border-bottom: 1px solid var(--line); }
      h1 { margin: 0 0 6px; font-size: 26px; font-weight: 720; letter-spacing: 0; }
      .meta { color: var(--muted); font-size: 14px; }
      main { padding: 24px 32px 40px; }
      .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 18px; }
      .stat { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; }
      .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
      .value { margin-top: 6px; font-size: 24px; font-weight: 720; }
      .toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 18px 0 10px; }
      .toolbar a { color: var(--brand); font-weight: 650; text-decoration: none; }
      .table-wrap { overflow: auto; background: var(--card); border: 1px solid var(--line); border-radius: 8px; }
      table { width: 100%; border-collapse: collapse; min-width: 960px; }
      th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
      th { position: sticky; top: 0; background: #eef2f7; color: #334155; font-weight: 700; }
      td:nth-child(4), td:nth-child(5), td:nth-child(6), td:nth-child(7), td:nth-child(8) { text-align: right; white-space: nowrap; }
      a { color: var(--brand); }
      .warning { margin: 0 0 18px; padding: 12px 14px; border: 1px solid #f59e0b; border-radius: 8px; background: #fffbeb; color: #92400e; font-size: 14px; }
    </style>
  </head>
  <body>
    <header>
      <h1>${escapeHtml(account.name || account.id || "Video Account")}</h1>
      <div class="meta">${escapeHtml(account.platform)} · ${escapeHtml(account.id)} · Fetched ${escapeHtml(account.fetchedAt)}</div>
    </header>
    <main>
      ${warningHtml}
      <section class="stats">
        <div class="stat"><div class="label">Followers</div><div class="value">${formatNumber(account.followers)}</div></div>
        <div class="stat"><div class="label">Videos</div><div class="value">${formatNumber(account.videoCount)}</div></div>
        <div class="stat"><div class="label">Likes</div><div class="value">${formatNumber(account.totalLikes)}</div></div>
        <div class="stat"><div class="label">Views</div><div class="value">${formatNumber(account.totalViews)}</div></div>
        <div class="stat"><div class="label">Comments</div><div class="value">${formatNumber(account.totalComments)}</div></div>
      </section>
      <div class="toolbar">
        <strong>Per-video metrics</strong>
        <a href="./videos.csv" download>Download CSV</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>ID</th><th>Title</th><th>Published</th><th>Views</th><th>Likes</th><th>Comments</th><th>Shares</th><th>Favorites</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </main>
  </body>
</html>
`;
}

export async function exportDataset(input, outDir) {
  const dataset = normalizeDataset(input);
  await mkdir(outDir, { recursive: true });
  const summary = {
    fetchedAt: dataset.account.fetchedAt,
    platform: dataset.account.platform,
    accountId: dataset.account.id,
    accountName: dataset.account.name,
    followers: dataset.account.followers,
    videoCount: dataset.account.videoCount,
    totalLikesCollected: dataset.account.totalLikes,
    totalViewsCollected: dataset.account.totalViews,
    totalCommentsCollected: dataset.account.totalComments,
    videosCollected: dataset.videos.length,
    collectionStatus: dataset.account.collectionStatus,
    warnings: dataset.account.warnings,
  };
  const csv = [
    VIDEO_COLUMNS.join(","),
    ...dataset.videos.map((video) => VIDEO_COLUMNS.map((column) => csvEscape(video[column])).join(",")),
  ].join("\r\n");
  const files = {
    summaryJson: path.join(outDir, "summary.json"),
    videosJson: path.join(outDir, "videos.json"),
    csv: path.join(outDir, "videos.csv"),
    html: path.join(outDir, "report.html"),
  };
  await writeFile(files.summaryJson, JSON.stringify(summary, null, 2), "utf8");
  await writeFile(files.videosJson, JSON.stringify({ summary, account: dataset.account, videos: dataset.videos }, null, 2), "utf8");
  await writeFile(files.csv, `\ufeff${csv}\r\n`, "utf8");
  await writeFile(files.html, renderHtml(dataset), "utf8");
  return files;
}

export async function loadCookieHeader(cookiePath) {
  if (!cookiePath) {
    return "";
  }
  throw new Error("--cookies is no longer supported. Use browser login; cookies are saved automatically after login.");
}

export function normalizeAuth(value, hasCookies = false) {
  if (hasCookies) {
    throw new Error("--cookies is no longer supported. Use browser login; cookies are saved automatically after login.");
  }
  const auth = value || "browser";
  if (auth !== "browser") {
    throw new Error(`Invalid --auth ${auth}. Only browser login is supported.`);
  }
  return auth;
}

export function parseVideoLimit(value) {
  return value ? Number(value) : DEFAULT_VIDEO_LIMIT;
}

function cookiesToHeader(cookies) {
  return (cookies || []).map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

export function buildBrowserLaunchOptions() {
  return {
    acceptDownloads: true,
    channel: "chrome",
    headless: false,
    viewport: { width: 1920, height: 1080 },
    locale: "zh-CN",
    timezoneId: "Asia/Shanghai",
  };
}

export function isPlatformHostname(hostname, hosts) {
  return hosts.some((host) => hostname === host || hostname.endsWith(`.${host}`));
}

function cookieBelongsToHost(cookie, hosts) {
  const domain = String(cookie.domain || "").replace(/^\./, "");
  return isPlatformHostname(domain, hosts);
}

export function filterPlatformCookies(cookies, hosts) {
  return (cookies || []).filter((cookie) => cookieBelongsToHost(cookie, hosts));
}

function hasLoginCookie(cookies, config) {
  const platformCookies = filterPlatformCookies(cookies, config.hosts);
  const names = new Set(platformCookies.map((cookie) => cookie.name));
  return config.loginCookies.some((name) => names.has(name));
}

function isLoginExpiredError(error) {
  return /登录已过期|请登录|扫码登录|验证码|安全验证|风险|频繁|login expired|session expired|browser login is incomplete|verification|risk-control|captcha/i.test(error?.message || String(error));
}

async function getCookiesWithTimeout(context, timeoutMs = 3000) {
  return await Promise.race([
    context.cookies(),
    new Promise((resolve) => setTimeout(() => resolve([]), timeoutMs)),
  ]);
}

async function waitForBrowserLogin({ context, page, config, platform, userDataDir }) {
  const deadline = Date.now() + 10 * 60 * 1000;
  const browserReadyAt = platform === "xiaohongshu" ? Date.now() + 15 * 1000 : 0;
  while (Date.now() < deadline) {
    const cookies = await getCookiesWithTimeout(context);
    const platformCookies = filterPlatformCookies(cookies, config.hosts);
    if (hasLoginCookie(platformCookies, config)) {
      return platformCookies;
    }
    if (browserReadyAt && Date.now() >= browserReadyAt) {
      console.log("Xiaohongshu login cookie was not detected; continuing with browser page collection.");
      return platformCookies;
    }
    await page.waitForTimeout(1000);
  }
  throw new Error(`Timed out waiting for ${platform} login. Finish scan/verification in the opened browser and retry. Profile: ${userDataDir}`);
}

export function resolveBrowserStartUrl(platform, account) {
  const config = BROWSER_AUTH[platform];
  if (!config) {
    throw new Error(`Browser auth is not configured for ${platform}.`);
  }
  const startUrl = config.startUrl(String(account));
  const url = new URL(startUrl);
  if (url.protocol !== "https:") {
    throw new Error(`--account URL must use https for ${platform}.`);
  }
  if (!isPlatformHostname(url.hostname, config.hosts)) {
    throw new Error(`--account URL host ${url.hostname} does not match ${platform}.`);
  }
  return url.href;
}

export function resolveBrowserProfile(profile, platform) {
  const privateRoot = path.resolve(SKILL_DIR, "private");
  const profileDir = path.resolve(profile || path.join(privateRoot, "profiles", platform));
  const relative = path.relative(privateRoot, profileDir);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("--profile must be inside the skill private directory.");
  }
  return profileDir;
}

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    throw new Error("Browser auth requires local Playwright. Run `npm install playwright` in the video-account-monitor skill directory, then retry.");
  }
}

async function withBrowserSession({ platform, account, profile }, callback) {
  const config = BROWSER_AUTH[platform];
  if (!config) {
    throw new Error(`Browser auth is not configured for ${platform}.`);
  }

  const { chromium } = await loadPlaywright();
  const userDataDir = resolveBrowserProfile(profile, platform);
  const startUrl = resolveBrowserStartUrl(platform, account);
  await mkdir(userDataDir, { recursive: true });

  const context = await chromium.launchPersistentContext(userDataDir, buildBrowserLaunchOptions(platform));

  try {
    const page = context.pages()[0] || await context.newPage();
    await page.goto(startUrl, { waitUntil: "domcontentloaded" });
    console.log(`Browser auth opened ${platform}. Please log in manually if needed. Profile: ${userDataDir}`);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const platformCookies = await waitForBrowserLogin({ context, page, config, platform, userDataDir });
      try {
        return await callback({ context, page, cookieHeader: cookiesToHeader(platformCookies), userDataDir });
      } catch (error) {
        if (!isLoginExpiredError(error) || attempt > 0) throw error;
        console.log(`${platform} login expired. Reopening login page; please scan/login in the browser, then collection will retry automatically.`);
        await context.clearCookies();
        await page.goto(startUrl, { waitUntil: "domcontentloaded" });
      }
    }
  } finally {
    await context.close();
  }
}

function demoDataset() {
  return normalizeDataset({
    account: {
      platform: "bilibili",
      id: "demo",
      name: "Demo Creator",
      followers: 123456,
      videoCount: 2,
    },
    videos: [
      {
        id: "BV1demoA",
        title: "Demo video with comments",
        url: "https://www.bilibili.com/video/BV1demoA",
        publishedAt: "2026-05-25T09:00:00+08:00",
        duration: "03:21",
        likes: 1200,
        views: 23000,
        comments: 321,
        shares: 45,
        favorites: 67,
        coins: 89,
      },
      {
        id: "BV1demoB",
        title: "Second demo video",
        url: "https://www.bilibili.com/video/BV1demoB",
        publishedAt: "2026-05-24T09:00:00+08:00",
        duration: "05:12",
        likes: 800,
        views: 18000,
        comments: 120,
        shares: 20,
        favorites: 30,
        coins: 40,
      },
    ],
  });
}

async function loadAdapter(platform) {
  const canonical = PLATFORM_ALIASES[String(platform || "").toLowerCase()];
  if (!canonical || !SUPPORTED_PLATFORMS.has(canonical)) {
    throw new Error("Missing or invalid --platform. Use bilibili, douyin, kuaishou, or xiaohongshu.");
  }
  const adapterPath = path.join(__dirname, "adapters", `${canonical}.mjs`);
  const adapter = await import(pathToFileURL(adapterPath).href);
  return { platform: canonical, collect: adapter.collect, collectWithBrowser: adapter.collectWithBrowser };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args.h) {
    console.log(usage());
    return;
  }
  const outDir = args.out || path.resolve(process.cwd(), "outputs", `video-account-monitor-${Date.now()}`);
  if (args.demo) {
    const files = await exportDataset(demoDataset(), outDir);
    console.log(JSON.stringify({ files }, null, 2));
    return;
  }
  if (!args.account) {
    throw new Error(`Missing --account.\n\n${usage()}`);
  }
  const { platform, collect, collectWithBrowser } = await loadAdapter(args.platform);
  const auth = normalizeAuth(args.auth, Boolean(args.cookies));
  const dataset = await withBrowserSession({ platform, account: args.account, profile: args.profile }, async ({ context, page, cookieHeader }) => {
    const collector = platform === "xiaohongshu" && collectWithBrowser ? collectWithBrowser : collect;
    return await collector({
      account: args.account,
      cookieHeader,
      auth,
      profile: args.profile,
      context,
      page,
      limit: parseVideoLimit(args.limit),
      delay: args.delay ? Number(args.delay) : 3000,
    });
  });
  dataset.account = { ...dataset.account, platform };
  const files = await exportDataset(dataset, outDir);
  console.log(JSON.stringify({ files }, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(redactSensitiveText(error.stack || error.message || String(error)));
    process.exit(1);
  });
}
