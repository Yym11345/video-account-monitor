import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Python executable ────────────────────────────────────────────────
function resolveXhsPython() {
  const candidate = process.env.XHS_PYTHON;
  if (!candidate) {
    throw new Error("Set XHS_PYTHON to an absolute Python interpreter path before Xiaohongshu signed API collection.");
  }
  const normalized = normalize(candidate).replace(/\\/g, "/");
  if (!isAbsolute(normalized)) {
    throw new Error("XHS_PYTHON must be an absolute local interpreter path.");
  }
  if (/^\/[a-zA-Z]\//.test(normalized)) {
    return `${normalized[1].toUpperCase()}:/${normalized.slice(3)}`;
  }
  return normalized;
}

const DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const XHS_RISK_CONTROL_PATTERN = /验证码|验证|安全验证|风险|频繁|登录已过期|请登录|扫码登录|captcha|verify|verification|risk|login expired|session expired/i;
const XHS_PAGE_VERIFICATION_PATTERN = /验证码|安全验证|风险|频繁|登录已过期|扫码登录|请登录|captcha|verification|risk/i;
const SIGNED_DETAIL_LIMIT = 200;

// ── Helpers ──────────────────────────────────────────────────────────

function jitter(base) {
  return Math.round(base * (0.7 + Math.random() * 0.6));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, jitter(ms)));
}

async function fetchWithTimeout(url, options, timeoutMs = 30000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function shortHash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

// ── Python signing bridge ────────────────────────────────────────────
function signRequest(uri, cookieHeader, method = "GET", params = null, payload = null) {
  if (!hasXhsSignedApiCookies(cookieHeader)) {
    throw new Error("XHS browser login is incomplete. Finish login/verification in the opened browser and retry.");
  }
  const input = JSON.stringify({ uri, cookies: cookieHeader, method, params, payload });
  const result = execFileSync(resolveXhsPython(), [join(__dirname, "xhs_sign_helper.py")], {
    input,
    encoding: "utf8",
    timeout: 30000,
    env: {
      ...process.env,
      PYTHONIOENCODING: "utf-8",
    },
    windowsHide: true,
  });
  return JSON.parse(result.trim());
}

function isXhsHostname(hostname) {
  return hostname === "xiaohongshu.com" || hostname.endsWith(".xiaohongshu.com");
}

function isXhsApiUrl(value, paths) {
  try {
    const url = new URL(value);
    return isXhsHostname(url.hostname) && paths.includes(url.pathname);
  } catch {
    return false;
  }
}

function publicXhsUrl(value) {
  try {
    const url = new URL(value);
    url.searchParams.delete("xsec_token");
    url.searchParams.delete("xsec_source");
    return url.href;
  } catch {
    return String(value || "");
  }
}

function redactXhsText(value) {
  return String(value || "")
    .replace(/([?&]xsec_token=)[^&\s)]+/gi, "$1REDACTED")
    .replace(/(%3[FfAa]|[?&,\s\{\[])(xsec_token)(%3[Dd]|=)([^&\s,\}\]]+)/gi, "$1$2$3REDACTED")
    .replace(/(["']xsec_token["']\s*:\s*["'])[^"']+/gi, "$1REDACTED")
    .replace(/(Cookie\s*:\s*)[^\r\n]+/gi, "$1REDACTED")
    .replace(/\b(a1|web_session|sessionid|sid_guard|uid_tt|msToken)=([^;,\s]+)/gi, "$1=REDACTED");
}

function redactXhsUrl(value) {
  return redactXhsText(value);
}

// ── URL parsing ──────────────────────────────────────────────────────
function extractUserId(account) {
  const text = String(account);
  try {
    const url = new URL(text);
    const match = url.pathname.match(/\/user\/profile\/([a-f0-9]+)/i);
    if (match && /(^|\.)xiaohongshu\.com$/i.test(url.hostname)) {
      return {
        userId: match[1],
        xsecToken: url.searchParams.get("xsec_token") || "",
        xsecSource: url.searchParams.get("xsec_source") || "pc_feed",
      };
    }
  } catch {
  }

  if (/^[a-f0-9]{24}$/i.test(text)) return { userId: text, xsecToken: "", xsecSource: "" };
  throw new Error("Could not find Xiaohongshu user ID in account URL or id.");
}

// ── Build browser-like headers ───────────────────────────────────────
function buildHeaders(ua, cookieHeader) {
  const isFirefox = ua.includes("Firefox");
  if (isFirefox) {
    return {
      "user-agent": ua,
      accept: "application/json, text/plain, */*",
      "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
      origin: "https://www.xiaohongshu.com",
      referer: "https://www.xiaohongshu.com/",
      ...(cookieHeader ? { cookie: cookieHeader } : {}),
    };
  }
  return {
    "user-agent": ua,
    accept: "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "accept-encoding": "gzip, deflate, br, zstd",
    "cache-control": "no-cache",
    origin: "https://www.xiaohongshu.com",
    referer: "https://www.xiaohongshu.com/",
    "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": ua.includes("Mac") ? '"macOS"' : '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    pragma: "no-cache",
    ...(cookieHeader ? { cookie: cookieHeader } : {}),
  };
}

function isRiskControlMessage(message) {
  return XHS_RISK_CONTROL_PATTERN.test(String(message || ""));
}

function isPageVerificationMessage(message) {
  return XHS_PAGE_VERIFICATION_PATTERN.test(String(message || ""));
}

function throwIfRiskControl(message) {
  if (isRiskControlMessage(message)) {
    throw new Error(`XHS verification/risk-control required. Complete verification in the browser and retry. Message: ${message}`);
  }
}

// ── Request with retry + exponential backoff ──────────────────────────
async function xhsGet(uri, params, cookieHeader, retries = 5) {
  let lastError;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      const ua = DEFAULT_USER_AGENT;
      const signHeaders = signRequest(uri, cookieHeader, "GET", params);
      const headers = {
        ...buildHeaders(ua, cookieHeader),
        "x-s": signHeaders["x-s"],
        "x-t": String(signHeaders["x-t"]),
        "x-s-common": signHeaders["x-s-common"],
        "x-b3-traceid": signHeaders["x-b3-traceid"],
        "x-xray-traceid": signHeaders["x-xray-traceid"],
      };

      // Build URL with query string
      const qs = params
        ? "?" + Object.entries(params)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v)).replace(/%2C/g, ",")}`)
            .join("&")
        : "";
      const url = `https://edith.xiaohongshu.com${uri}${qs}`;

      const response = await fetchWithTimeout(url, { headers });

      if (response.status === 471 || response.status === 461) {
        throw new Error(`HTTP ${response.status}: XHS verification/risk-control required. Complete verification in the browser and retry.`);
      }
      if (response.status === 403 || response.status === 412) {
        throw new Error(`HTTP ${response.status}: XHS risk-control ban. Stop collection and retry later with the visible browser session.`);
      }

      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`XHS returned non-JSON status=${response.status}: ${text.slice(0, 90)} (retryable)`);
      }

      if (data.code !== 0 && data.success !== true) {
        const msg = data.msg || data.message || JSON.stringify(data).slice(0, 100);
        throwIfRiskControl(msg);
        throw new Error(`XHS API error: ${msg} (retryable)`);
      }

      return data;
    } catch (error) {
      lastError = error;
      if (isRiskControlMessage(error.message)) throw error;
      if (attempt < retries - 1) {
        const base = 3000 * 2 ** attempt;
        await sleep(base);
      }
    }
  }
  throw lastError;
}

async function xhsPost(uri, payload, cookieHeader, retries = 5) {
  let lastError;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      const ua = DEFAULT_USER_AGENT;
      const signHeaders = signRequest(uri, cookieHeader, "POST", null, payload);
      const headers = {
        ...buildHeaders(ua, cookieHeader),
        "content-type": "application/json;charset=UTF-8",
        "x-s": signHeaders["x-s"],
        "x-t": String(signHeaders["x-t"]),
        "x-s-common": signHeaders["x-s-common"],
        "x-b3-traceid": signHeaders["x-b3-traceid"],
        "x-xray-traceid": signHeaders["x-xray-traceid"],
      };

      const url = `https://edith.xiaohongshu.com${uri}`;
      const body = JSON.stringify(payload);

      const response = await fetchWithTimeout(url, { method: "POST", headers, body });

      if (response.status === 471 || response.status === 461) {
        throw new Error(`HTTP ${response.status}: XHS verification/risk-control required. Complete verification in the browser and retry.`);
      }
      if (response.status === 403 || response.status === 412) {
        throw new Error(`HTTP ${response.status}: XHS risk-control ban. Stop collection and retry later with the visible browser session.`);
      }

      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`XHS returned non-JSON status=${response.status}: ${text.slice(0, 90)} (retryable)`);
      }

      if (data.code !== 0 && data.success !== true) {
        const msg = data.msg || data.message || JSON.stringify(data).slice(0, 100);
        throwIfRiskControl(msg);
        throw new Error(`XHS API error: ${msg} (retryable)`);
      }

      return data;
    } catch (error) {
      lastError = error;
      if (isRiskControlMessage(error.message)) throw error;
      if (attempt < retries - 1) {
        const base = 3000 * 2 ** attempt;
        await sleep(base);
      }
    }
  }
  throw lastError;
}

function toIso(ts) {
  if (!ts) return "";
  // XHS timestamps can be in seconds or milliseconds
  const num = Number(ts);
  const ms = String(ts).length <= 10 ? num * 1000 : num;
  return new Date(ms + 8 * 3600 * 1000).toISOString().replace(".000Z", "+08:00");
}

function noteKey(note, index) {
  const noteCard = note.note_card || note.noteCard || {};
  const user = note.user || noteCard.user || {};
  const cover = note.cover || noteCard.cover || {};
  const stableParts = [
    note.xsec_token || noteCard.xsecToken,
    note.display_title || noteCard.title,
    user.user_id || user.userId,
    cover.url_default || cover.urlDefault || cover.url_pre || cover.urlPre,
  ].filter(Boolean);
  return note.note_id || note.id || note.noteId || noteCard.noteId || noteCard.note_id || stableParts.join("|") || `xhs-card-${index + 1}`;
}

function noteId(note, index) {
  const noteCard = note.note_card || note.noteCard || {};
  const key = noteKey(note, index);
  return note.note_id || note.id || note.noteId || noteCard.noteId || noteCard.note_id || `xhs-card-${shortHash(key)}`;
}

function noteXsecToken(note, fallback = "") {
  const noteCard = note.note_card || note.noteCard || {};
  return note.xsec_token || note.xsecToken || noteCard.xsec_token || noteCard.xsecToken || fallback || "";
}

function noteXsecSource(note, fallback = "pc_feed") {
  const noteCard = note.note_card || note.noteCard || {};
  return note.xsec_source || note.xsecSource || noteCard.xsec_source || noteCard.xsecSource || fallback || "pc_feed";
}

function buildXhsRequestNoteUrl(noteIdValue, xsecToken = "", xsecSource = "pc_feed") {
  if (!noteIdValue || String(noteIdValue).startsWith("xhs-card-")) return "";
  const url = new URL(`https://www.xiaohongshu.com/explore/${noteIdValue}`);
  if (xsecToken) url.searchParams.set("xsec_token", xsecToken);
  if (xsecSource) url.searchParams.set("xsec_source", xsecSource);
  return url.href;
}

export function buildXhsNoteUrl(noteIdValue) {
  if (!noteIdValue || String(noteIdValue).startsWith("xhs-card-")) return "";
  return `https://www.xiaohongshu.com/explore/${noteIdValue}`;
}

function localCookiesToHeader(cookies) {
  return (cookies || []).map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

export function hasXhsSignedApiCookies(cookieHeader = "") {
  return /(?:^|;\s*)a1=/.test(cookieHeader) && /(?:^|;\s*)web_session=/.test(cookieHeader);
}

async function getActiveBrowserCookieHeader(context) {
  const cookies = await Promise.race([
    context.cookies(["https://www.xiaohongshu.com"]),
    new Promise((resolve) => setTimeout(() => resolve([]), 3000)),
  ]);
  return localCookiesToHeader(cookies);
}

export function parseXhsMetric(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === "") continue;
    const text = String(value).replace(/[, ]/g, "");
    const exact = text.match(/^(\d+(?:\.\d+)?)(万|w|W|k|K)?$/);
    const loose = exact || text.match(/(\d+(?:\.\d+)?)(万|w|W|k|K)?/);
    if (!loose) continue;
    const number = Number(loose[1]);
    if (!Number.isFinite(number)) continue;
    const unit = loose[2];
    if (unit === "万" || unit === "w" || unit === "W") return Math.round(number * 10000);
    if (unit === "k" || unit === "K") return Math.round(number * 1000);
    return number;
  }
  return 0;
}

function browserVideoKey(video) {
  return video.id || video.url || video.title;
}

export function mergeXhsBrowserVideo(existing, incoming) {
  if (!existing) return incoming;
  return {
    ...existing,
    id: existing.id?.startsWith("xhs-card-") && !incoming.id?.startsWith("xhs-card-") ? incoming.id : existing.id,
    title: existing.title || incoming.title,
    url: existing.url || incoming.url,
    publishedAt: existing.publishedAt || incoming.publishedAt,
    likes: existing.likes || incoming.likes,
    views: existing.views || incoming.views,
    comments: existing.comments || incoming.comments,
    shares: existing.shares || incoming.shares,
    favorites: existing.favorites || incoming.favorites,
    coins: existing.coins || incoming.coins,
  };
}

export function normalizeBrowserVideo(video) {
  const idFromUrl = (video.url || "").match(/\/explore\/([^/?#]+)/)?.[1] || "";
  const id = String(video.id || idFromUrl || `xhs-card-${shortHash(video.title || video.url || "browser")}`);
  const url = id.startsWith("xhs-card-") ? publicXhsUrl(video.url) : buildXhsNoteUrl(id);
  return {
    id,
    title: String(video.title || ""),
    url: String(url),
    publishedAt: String(video.publishedAt || ""),
    duration: "",
    likes: parseXhsMetric(video.likes),
    views: parseXhsMetric(video.views),
    comments: parseXhsMetric(video.comments),
    shares: parseXhsMetric(video.shares),
    favorites: parseXhsMetric(video.favorites),
    coins: 0,
  };
}

function notesToBrowserVideos(notes) {
  return notes.map((note, index) => {
    const currentNoteId = noteId(note, index);
    const noteCard = note.note_card || note.noteCard || {};
    const interactInfo = note.interact_info || note.interactInfo || noteCard.interact_info || noteCard.interactInfo || {};
    return normalizeBrowserVideo({
      id: currentNoteId,
      title: noteCard.title || note.title || note.display_title || "",
      url: buildXhsNoteUrl(currentNoteId),
      publishedAt: toIso(note.time || noteCard.time),
      likes: parseXhsMetric(interactInfo.liked_count, interactInfo.likedCount, note.liked_count, note.likedCount, noteCard.liked_count, noteCard.likedCount),
      comments: parseXhsMetric(interactInfo.comment_count, interactInfo.commentCount, note.comment_count, note.commentCount, noteCard.comment_count, noteCard.commentCount),
      shares: parseXhsMetric(interactInfo.share_count, interactInfo.shareCount, note.share_count, note.shareCount, noteCard.share_count, noteCard.shareCount),
      favorites: parseXhsMetric(interactInfo.collected_count, interactInfo.collect_count, interactInfo.collectedCount, interactInfo.collectCount, note.collected_count, note.collect_count, noteCard.collected_count, noteCard.collect_count),
    });
  });
}

async function extractBrowserVideos(page) {
  return await page.evaluate(() => {
    const anchors = Array.from(document.querySelectorAll("a[href*='/explore/']"));
    const rows = [];
    for (const anchor of anchors) {
      const href = anchor.href || "";
      const id = href.match(/\/explore\/([^/?#]+)/)?.[1] || "";
      if (!id) continue;
      const card = anchor.closest("section, .note-item, [class*='note'], [class*='card']") || anchor;
      const titleNode = card.querySelector?.(".title, .footer .title, .note-title, [class*='title']") || anchor;
      const text = (card.innerText || "").trim();
      const title = (titleNode?.textContent || "").trim() || text.split("\n").find((line) => line.trim() && !/^\d/.test(line.trim())) || "";
      const likes = Array.from(card.querySelectorAll?.(".like-wrapper, .count, [class*='like'], [class*='count']") || [])
        .map((node) => (node.textContent || "").trim())
        .find((value) => /\d/.test(value)) || "";
      rows.push({ id, title, url: href, likes });
    }
    return rows;
  });
}

async function waitForUserVerification(page, delay) {
  const verificationText = await page.evaluate(() => document.body?.innerText || "").catch(() => "");
  if (!isPageVerificationMessage(verificationText)) return;
  console.log("Xiaohongshu verification/login may be required. Please finish it in the opened browser; collection will continue automatically.");
  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    await page.waitForTimeout(delay);
    const text = await page.evaluate(() => document.body?.innerText || "").catch(() => "");
    if (!isPageVerificationMessage(text)) return;
  }
  throw new Error("Timed out waiting for Xiaohongshu verification. Finish it in the browser and retry.");
}

export function extractXhsInitialState(text) {
  const match = String(text || "").match(/window\.__INITIAL_STATE__\s*=\s*({[\s\S]*?})<\/script>/);
  if (!match) return null;
  try {
    return JSON.parse(match[1].replace(/:undefined/g, ":null").replace(/undefined/g, "null"));
  } catch {
    return null;
  }
}

function getXhsDetailNoteId(detail) {
  const note = detail?.note || detail?.note_card || detail?.noteCard || detail || {};
  return note.note_id || note.noteId || note.id || detail?.note_id || detail?.noteId || detail?.id || "";
}

function findXhsNoteDetail(state, noteIdValue) {
  const noteMap = state?.note?.noteDetailMap || state?.note?.note_detail_map || findFirstObjectByKeys(state, ["noteDetailMap", "note_detail_map"]);
  const detail = noteMap?.noteDetailMap || noteMap?.note_detail_map || noteMap;
  const entry = detail?.[noteIdValue];
  if (!entry) return null;
  const note = entry?.note || entry?.note_card || entry?.noteCard || entry || null;
  if (note && getXhsDetailNoteId(note) && getXhsDetailNoteId(note) !== noteIdValue) return null;
  return note;
}

export function extractXhsNoteDetailFromHtml(noteIdValue, html) {
  if (!String(html || "").includes("noteDetailMap") && !String(html || "").includes("note_detail_map")) return null;
  const state = extractXhsInitialState(html);
  return findXhsNoteDetail(state, noteIdValue);
}

function findFirstObjectByKeys(value, keys) {
  if (!value || typeof value !== "object") return null;
  if (keys.some((key) => Object.prototype.hasOwnProperty.call(value, key))) return value;
  for (const child of Object.values(value)) {
    const found = findFirstObjectByKeys(child, keys);
    if (found) return found;
  }
  return null;
}

async function extractCreatorInfoFromPage(page) {
  const html = await page.content().catch(() => "");
  const state = extractXhsInitialState(html);
  const userPageData = state?.user?.userPageData || state?.user?.user_page_data || findFirstObjectByKeys(state?.user, ["basicInfo", "basic_info"]);
  const basicInfo = userPageData?.basicInfo || userPageData?.basic_info || userPageData || {};
  const interactions = userPageData?.interactions || userPageData?.interactInfo || userPageData?.interact_info || {};
  return {
    name: basicInfo.nickname || basicInfo.nickName || basicInfo.nick_name || basicInfo.name || "",
    followers: parseXhsMetric(interactions.fans, interactions.followers, interactions.follower_count, interactions.followerCount, basicInfo.followers),
    videoCount: parseXhsMetric(userPageData?.noteCount, userPageData?.note_count, userPageData?.notesCount, userPageData?.notes_count),
  };
}

function buildBrowserDataset({ userId, profileUrl, creatorInfo = {}, videos, warnings }) {
  return {
    account: {
      platform: "xiaohongshu",
      id: userId,
      url: profileUrl,
      name: creatorInfo.name || "",
      followers: parseXhsMetric(creatorInfo.followers),
      videoCount: parseXhsMetric(creatorInfo.videoCount) || videos.length,
      totalLikes: videos.reduce((sum, v) => sum + v.likes, 0),
      totalViews: videos.reduce((sum, v) => sum + v.views, 0),
      totalComments: videos.reduce((sum, v) => sum + v.comments, 0),
      collectionStatus: warnings.length > 0 ? "partial" : "complete",
      warnings,
      fetchedAt: new Date().toISOString(),
    },
    videos,
  };
}

async function getCreatorNotes({ userId, xsecToken, xsecSource, cookieHeader, limit, delay }) {
  const rawNotes = [];
  let cursor = "";
  let hasMore = true;
  const seenCursors = new Set();
  const maxPages = limit ? Math.ceil(limit / 30) + 2 : 50;

  for (let pageCount = 0; hasMore && pageCount < maxPages; pageCount += 1) {
    if (cursor && seenCursors.has(cursor)) break;
    if (cursor) seenCursors.add(cursor);

    console.log(`Xiaohongshu signed API list page ${pageCount + 1}/${maxPages}; collected ${rawNotes.length} note(s).`);
    const pageData = await xhsGet("/api/sns/web/v1/user_posted", {
      num: "30",
      cursor,
      user_id: userId,
      image_formats: "jpg,webp,avif",
      xsec_token: xsecToken,
      xsec_source: xsecSource || "pc_feed",
    }, cookieHeader);
    const data = pageData.data || pageData;
    const notes = data.notes || data.items || [];
    rawNotes.push(...notes);
    hasMore = data.has_more === true;
    cursor = data.cursor || "";
    if (limit && rawNotes.length >= limit) break;
    await sleep(delay);
  }

  const seen = new Set();
  return rawNotes.filter((note, index) => {
    const key = noteKey(note, index);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, limit || undefined);
}

async function fetchNoteDetailFromHtml(noteIdValue, xsecToken, xsecSource, cookieHeader) {
  const url = buildXhsRequestNoteUrl(noteIdValue, xsecToken, xsecSource);
  if (!url) throw new Error("XHS HTML detail fallback could not build note URL.");
  const response = await fetchWithTimeout(url, {
    headers: buildHeaders(DEFAULT_USER_AGENT, cookieHeader),
  });
  const html = await response.text();
  throwIfRiskControl(html.slice(0, 2000));
  if (!response.ok) {
    throw new Error(`XHS HTML detail fallback returned HTTP ${response.status}.`);
  }
  const detail = extractXhsNoteDetailFromHtml(noteIdValue, html);
  if (!detail) {
    throw new Error("XHS HTML detail fallback did not expose the requested note.");
  }
  return detail;
}

async function fetchNoteDetail(note, index, fallback, cookieHeader) {
  const currentNoteId = noteId(note, index);
  if (currentNoteId.startsWith("xhs-card-")) return null;
  const xsecToken = noteXsecToken(note, fallback.xsecToken);
  const xsecSource = noteXsecSource(note, fallback.xsecSource || "pc_feed");
  try {
    const detail = await xhsPost("/api/sns/web/v1/feed", {
      source_note_id: currentNoteId,
      image_formats: ["jpg", "webp", "avif"],
      extra: { need_body_topic: 1 },
      xsec_token: xsecToken,
      xsec_source: xsecSource,
    }, cookieHeader, 3);
    const item = (detail.data?.items || detail.items || [])[0];
    const candidate = item?.note_card || item?.noteCard || item || null;
    if (!candidate) {
      throw new Error(`XHS feed detail returned no item for ${currentNoteId}.`);
    }
    const returnedId = getXhsDetailNoteId(candidate);
    if (returnedId && returnedId !== currentNoteId) {
      throw new Error(`XHS feed detail returned ${returnedId} for ${currentNoteId}.`);
    }
    return candidate;
  } catch (error) {
    if (isRiskControlMessage(error.message)) throw error;
    return await fetchNoteDetailFromHtml(currentNoteId, xsecToken, xsecSource, cookieHeader);
  }
}

function mapXhsVideo({ note, detail, index, fallback }) {
  const currentNoteId = noteId(note, index);
  const noteCard = detail || note.note_card || note.noteCard || {};
  const interactInfo = noteCard.interact_info || noteCard.interactInfo || note.interact_info || note.interactInfo || {};
  const xsecToken = noteXsecToken(note, fallback.xsecToken);
  const xsecSource = noteXsecSource(note, fallback.xsecSource || "pc_feed");
  return {
    id: String(currentNoteId),
    title: noteCard.title || note.title || note.display_title || "",
    url: buildXhsNoteUrl(currentNoteId),
    publishedAt: toIso(noteCard.time || detail?.time || note.time),
    duration: "",
    likes: parseXhsMetric(interactInfo.liked_count, interactInfo.likedCount, note.liked_count, note.likedCount, noteCard.liked_count, noteCard.likedCount),
    views: parseXhsMetric(interactInfo.view_count, interactInfo.viewCount, noteCard.view_count, noteCard.viewCount),
    comments: parseXhsMetric(interactInfo.comment_count, interactInfo.commentCount, note.comment_count, note.commentCount, noteCard.comment_count, noteCard.commentCount),
    shares: parseXhsMetric(interactInfo.share_count, interactInfo.shareCount, note.share_count, note.shareCount, noteCard.share_count, noteCard.shareCount),
    favorites: parseXhsMetric(interactInfo.collected_count, interactInfo.collect_count, interactInfo.collectedCount, interactInfo.collectCount, note.collected_count, note.collect_count, noteCard.collected_count, noteCard.collect_count),
    coins: 0,
  };
}

async function collectWithSignedApi({ account, cookieHeader, limit, delay, creatorInfo = {} }) {
  const { userId, xsecToken, xsecSource } = extractUserId(account);
  const profileUrl = `https://www.xiaohongshu.com/user/profile/${userId}`;
  const uniqueNotes = await getCreatorNotes({ userId, xsecToken, xsecSource, cookieHeader, limit, delay });
  console.log(`Xiaohongshu signed API list collected ${uniqueNotes.length} unique note(s).`);
  const details = new Map();
  let detailFailures = 0;
  let firstDetailFailure = "";
  const detailNotes = uniqueNotes.slice(0, Math.min(uniqueNotes.length, SIGNED_DETAIL_LIMIT));
  if (detailNotes.length < uniqueNotes.length) {
    console.log(`Xiaohongshu detail fetch limited to first ${detailNotes.length}/${uniqueNotes.length} note(s) to keep collection bounded.`);
  }

  for (const [index, note] of detailNotes.entries()) {
    const currentNoteId = noteId(note, index);
    try {
      console.log(`Xiaohongshu signed API detail progress: ${index + 1}/${detailNotes.length}.`);
      const detail = await fetchNoteDetail(note, index, { xsecToken, xsecSource }, cookieHeader);
      if (detail) details.set(currentNoteId, detail);
    } catch (error) {
      if (isRiskControlMessage(error.message)) throw error;
      detailFailures += 1;
      firstDetailFailure ||= redactXhsText(error.message);
    }
    await sleep(Math.min(delay, 1000));
  }

  const videos = [];
  for (const [index, note] of uniqueNotes.entries()) {
    const currentNoteId = noteId(note, index);
    const video = mapXhsVideo({ note, detail: details.get(currentNoteId), index, fallback: { xsecToken, xsecSource } });
    videos.push(video);
  }

  const firstDetail = details.values().next().value || {};
  const firstCardUser = uniqueNotes[0]?.user || uniqueNotes[0]?.note_card?.user || uniqueNotes[0]?.noteCard?.user || {};
  const userInfo = firstDetail.user || firstCardUser;
  const warnings = [
    ...(uniqueNotes.some((note, index) => noteId(note, index).startsWith("xhs-card-")) ? ["Xiaohongshu did not expose note IDs for some creator-list cards; those rows may be partial."] : []),
    ...(detailFailures > 0 ? [`Xiaohongshu detail fetch failed for ${detailFailures} note(s); using creator-list card metrics for those rows. First failure: ${firstDetailFailure}`] : []),
    ...(videos.some((video) => video.views > 0) ? [] : ["Xiaohongshu web data did not expose reliable public view counts; views are reported as 0."]),
  ];

  return buildBrowserDataset({
    userId,
    profileUrl,
    creatorInfo: {
      name: creatorInfo.name || userInfo.nickname || userInfo.nick_name || "",
      followers: creatorInfo.followers,
      videoCount: creatorInfo.videoCount || videos.length,
    },
    videos,
    warnings,
  });
}

// ── Main collect function ────────────────────────────────────────────
export async function collect({ account, cookieHeader = "", limit, delay = 5000 }) {
  return await collectWithSignedApi({ account, cookieHeader, limit, delay });
}

export async function collectWithBrowser({ account, context, page, cookieHeader = "", limit = 200, delay = 3000 }) {
  let parsedAccount;
  try {
    parsedAccount = extractUserId(account);
  } catch {
    parsedAccount = null;
  }
  let userId = parsedAccount?.userId || "";
  let xsecToken = parsedAccount?.xsecToken || "";
  let xsecSource = parsedAccount?.xsecSource || "";
  let requestProfileUrl = userId
    ? (xsecToken
        ? `https://www.xiaohongshu.com/user/profile/${userId}?xsec_token=${encodeURIComponent(xsecToken)}&xsec_source=${encodeURIComponent(xsecSource || "pc_feed")}`
        : `https://www.xiaohongshu.com/user/profile/${userId}`)
    : String(account);
  let profileUrl = publicXhsUrl(requestProfileUrl);
  const collected = new Map();
  const warnings = ["Xiaohongshu used browser page auto-scroll collection; some metrics may still be unavailable if the page hides them."];

  page.on("response", async (response) => {
    try {
      const url = response.url();
      if (!isXhsApiUrl(url, ["/api/sns/web/v1/user_posted", "/api/sns/web/v1/feed"])) return;
      const data = await response.json();
      const notes = data.data?.notes || data.data?.items || [];
      for (const video of notesToBrowserVideos(notes)) {
        const key = browserVideoKey(video);
        if (key) collected.set(key, mergeXhsBrowserVideo(collected.get(key), video));
      }
    } catch {
    }
  });

  console.log(`Xiaohongshu adapter navigating profile: ${redactXhsUrl(requestProfileUrl)}`);
  await page.goto(requestProfileUrl, { waitUntil: "domcontentloaded", timeout: 45000 });
  console.log("Xiaohongshu profile page loaded; checking verification state.");
  await waitForUserVerification(page, delay);
  try {
    const resolved = extractUserId(page.url());
    userId = resolved.userId;
    xsecToken = resolved.xsecToken || xsecToken;
    xsecSource = resolved.xsecSource || xsecSource;
    requestProfileUrl = xsecToken
      ? `https://www.xiaohongshu.com/user/profile/${userId}?xsec_token=${encodeURIComponent(xsecToken)}&xsec_source=${encodeURIComponent(xsecSource || "pc_feed")}`
      : `https://www.xiaohongshu.com/user/profile/${userId}`;
    profileUrl = publicXhsUrl(requestProfileUrl);
  } catch {
    if (!userId) throw new Error("Could not resolve Xiaohongshu profile URL in the opened browser.");
  }
  const creatorInfo = await extractCreatorInfoFromPage(page);
  console.log("Xiaohongshu profile info extracted; checking signed API cookies.");
  const activeCookieHeader = context ? await getActiveBrowserCookieHeader(context) : cookieHeader;
  if (hasXhsSignedApiCookies(activeCookieHeader)) {
    try {
      console.log("Xiaohongshu signed API cookies detected; collecting through signed API.");
      const signedDataset = await collectWithSignedApi({ account: requestProfileUrl, cookieHeader: activeCookieHeader, limit, delay, creatorInfo });
      if (signedDataset.videos.length > 0) return signedDataset;
      warnings.push("Signed Xiaohongshu API returned no videos; falling back to browser page collection.");
    } catch (error) {
      if (isRiskControlMessage(error.message)) throw error;
      warnings.push(`Signed Xiaohongshu API collection failed; falling back to browser page collection: ${redactXhsText(error.message)}`);
    }
  } else {
    warnings.push("Active Xiaohongshu browser cookies are incomplete for signed API; using browser page collection fallback.");
  }

  console.log("Xiaohongshu browser fallback scrolling started.");
  let stableScrolls = 0;
  let lastCount = 0;
  const maxScrolls = Math.max(12, Math.ceil((limit || 200) / 10) + 8);
  for (let scroll = 0; scroll < maxScrolls && collected.size < limit; scroll += 1) {
    for (const video of (await extractBrowserVideos(page)).map(normalizeBrowserVideo)) {
      const key = browserVideoKey(video);
      if (key) collected.set(key, mergeXhsBrowserVideo(collected.get(key), video));
    }

    if (collected.size === lastCount) {
      stableScrolls += 1;
    } else {
      stableScrolls = 0;
      lastCount = collected.size;
    }
    if (stableScrolls >= 4) break;

    console.log(`Xiaohongshu browser fallback progress: ${collected.size} note(s), scroll ${scroll + 1}/${maxScrolls}.`);
    await page.evaluate(() => window.scrollBy(0, Math.max(window.innerHeight * 0.85, 600)));
    await page.waitForTimeout(delay);
    await waitForUserVerification(page, delay);
  }

  const videos = Array.from(collected.values()).slice(0, limit || undefined);
  if (videos.length > 0) {
    return buildBrowserDataset({ userId, profileUrl, creatorInfo, videos, warnings });
  }

  return buildBrowserDataset({
    userId,
    profileUrl,
    creatorInfo,
    videos: [],
    warnings: [
      ...warnings,
      "Browser page auto-scroll did not expose note cards. Finish login/verification in the opened browser and retry.",
    ],
  });
}
