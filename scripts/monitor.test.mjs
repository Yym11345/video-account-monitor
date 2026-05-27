import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  exportDataset,
  filterPlatformCookies,
  isPlatformHostname,
  loadCookieHeader,
  normalizeAuth,
  normalizeDataset,
  parseArgs,
  parseVideoLimit,
  resolveBrowserProfile,
  resolveBrowserStartUrl,
} from "./monitor.mjs";
import {
  buildXhsNoteUrl,
  extractXhsInitialState,
  parseXhsMetric,
} from "./adapters/xiaohongshu.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const skillRoot = path.resolve(__dirname, "..");
const tmpRoot = await mkdtemp(path.join(os.tmpdir(), "video-account-monitor-test-"));

try {
  const dataset = normalizeDataset({
    account: {
      platform: "bilibili",
      id: "470995011",
      name: "Demo Creator",
      followers: 10,
      videoCount: 1,
      totalLikes: 20,
    },
    videos: [
      {
        id: "BV1demo",
        title: " =HYPERLINK(\"https://example.com\")",
        url: "https://www.bilibili.com/video/BV1demo",
        publishedAt: "2026-05-25T00:00:00+08:00",
        duration: "01:00",
        likes: 7,
        views: 100,
        comments: 3,
        shares: 2,
        favorites: 4,
        coins: 5,
      },
    ],
  });

  assert.equal(dataset.account.totalComments, 3);
  assert.equal(dataset.videos[0].comments, 3);

  const outDir = path.join(tmpRoot, "report");
  await mkdir(outDir, { recursive: true });
  const files = await exportDataset(dataset, outDir);

  const json = JSON.parse(await readFile(files.videosJson, "utf8"));
  assert.equal(json.videos[0].comments, 3);
  assert.equal(json.summary.totalCommentsCollected, 3);

  const csv = await readFile(files.csv, "utf8");
  assert.match(csv.split(/\r?\n/)[0], /comments/);
  assert.match(csv, /BV1demo/);
  assert.match(csv, /' =HYPERLINK/);
  assert.match(csv, /,3,/);

  const html = await readFile(files.html, "utf8");
  assert.match(html, /Comments/);
  assert.match(html, /Demo Creator/);
  assert.match(html, /BV1demo/);

  assert.equal(normalizeAuth(undefined, false), "browser");
  assert.equal(normalizeAuth("browser", false), "browser");
  assert.throws(() => normalizeAuth(undefined, true), /--cookies is no longer supported/);
  assert.throws(() => normalizeAuth("brower", false), /Only browser login is supported/);
  assert.throws(() => normalizeAuth("cookie", false), /Only browser login is supported/);
  assert.throws(() => normalizeAuth("none", false), /Only browser login is supported/);
  assert.equal(parseVideoLimit(undefined), 200);
  assert.equal(parseVideoLimit("50"), 50);

  assert.deepEqual(parseArgs(["--auth=cookie", "--cookies=./cookies.txt", "--limit", "50"]), {
    auth: "cookie",
    cookies: "./cookies.txt",
    limit: "50",
  });

  assert.equal(parseXhsMetric("1.2万"), 12000);
  assert.equal(parseXhsMetric("3k"), 3000);
  assert.equal(parseXhsMetric(""), 0);
  assert.equal(
    buildXhsNoteUrl("68fb60030000000007020630", "TOKEN", "pc_note"),
    "https://www.xiaohongshu.com/explore/68fb60030000000007020630?xsec_token=TOKEN&xsec_source=pc_note",
  );
  assert.deepEqual(
    extractXhsInitialState('<script>window.__INITIAL_STATE__={"user":{"userPageData":{"basicInfo":{"nickname":"奶黄包"}}}}</script>')?.user?.userPageData?.basicInfo,
    { nickname: "奶黄包" },
  );

  assert.equal(isPlatformHostname("www.kuaishou.com", ["kuaishou.com"]), true);
  assert.equal(isPlatformHostname("evilkuaishou.com", ["kuaishou.com"]), false);
  assert.equal(resolveBrowserStartUrl("kuaishou", "3xabc"), "https://www.kuaishou.com/profile/3xabc");
  assert.throws(() => resolveBrowserStartUrl("kuaishou", "http://www.kuaishou.com/profile/3xabc"), /must use https/);
  assert.throws(() => resolveBrowserStartUrl("kuaishou", "https://example.com/profile/3xabc"), /does not match/);

  const privateProfile = resolveBrowserProfile(path.join(skillRoot, "private", "profiles", "kuaishou"), "kuaishou");
  assert.match(privateProfile.replace(/\\/g, "/"), /video-account-monitor\/private\/profiles\/kuaishou$/);
  assert.throws(() => resolveBrowserProfile(path.join(skillRoot, "outputs", "profile"), "kuaishou"), /private directory/);

  const cookies = filterPlatformCookies([
    { name: "passToken", value: "ok", domain: ".kuaishou.com" },
    { name: "passToken", value: "bad", domain: "evilkuaishou.com" },
  ], ["kuaishou.com"]);
  assert.equal(cookies.length, 1);
  assert.equal(cookies[0].value, "ok");
  assert.equal(await loadCookieHeader(""), "");
  await assert.rejects(() => loadCookieHeader(path.join(tmpRoot, "cookies.json"), ["kuaishou.com"]), /--cookies is no longer supported/);
} finally {
  await rm(tmpRoot, { recursive: true, force: true });
}
