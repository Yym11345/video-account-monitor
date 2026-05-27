import crypto from "node:crypto";

// ── UA rotation pool (bendi.monitor style) ──────────────────────────
const UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
];

// ── sec-ch-ua matching common Chrome versions ───────────────────────
const SEC_CH_UA_POOL = [
  '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
  '"Chromium";v="135", "Google Chrome";v="135", "Not.A/Brand";v="99"',
  '"Chromium";v="134", "Google Chrome";v="134", "Not.A/Brand";v="99"',
  '"Chromium";v="133", "Google Chrome";v="133", "Not.A/Brand";v="99"',
  '"Chromium";v="132", "Google Chrome";v="132", "Not.A/Brand";v="99"',
  '"Microsoft Edge";v="136", "Chromium";v="136", "Not.A/Brand";v="99"',
  '"Microsoft Edge";v="135", "Chromium";v="135", "Not.A/Brand";v="99"',
];

const MIXIN_KEY_ENC_TAB = [
  46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35,
  27, 43, 5, 49, 33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13,
  37, 48, 7, 16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30, 4,
  22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 44, 52,
];

function randItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Random jitter: base ± 30% variation
function jitter(base) {
  return Math.round(base * (0.7 + Math.random() * 0.6));
}

function extractMid(account) {
  const text = String(account);
  const match = text.match(/space\.bilibili\.com\/(\d+)/) || text.match(/^\d+$/);
  if (!match) {
    throw new Error("Could not find Bilibili mid in account URL or id.");
  }
  return match[1] || match[0];
}

function mixinKey(orig) {
  return MIXIN_KEY_ENC_TAB.map((index) => orig[index]).join("").slice(0, 32);
}

function sign(params, mixin) {
  const signed = { ...params, wts: Math.floor(Date.now() / 1000) };
  for (const key of Object.keys(signed)) {
    if (typeof signed[key] === "string") {
      signed[key] = signed[key].replace(/[!'()*]/g, "");
    }
  }
  const query = Object.keys(signed)
    .sort()
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(String(signed[key]))}`)
    .join("&");
  signed.w_rid = crypto.createHash("md5").update(query + mixin).digest("hex");
  return Object.keys(signed)
    .sort()
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(String(signed[key]))}`)
    .join("&");
}

// ── Build browser-like headers (bendi.monitor style) ────────────────
function buildHeaders(referer, cookieHeader) {
  const ua = randItem(UA_POOL);
  const secChUa = randItem(SEC_CH_UA_POOL);
  const isChrome = ua.includes("Chrome") && !ua.includes("Edg");
  const isEdge = ua.includes("Edg");
  const isFirefox = ua.includes("Firefox");

  if (isFirefox) {
    return {
      "user-agent": ua,
      accept: "application/json, text/plain, */*",
      "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
      referer,
      ...(cookieHeader ? { cookie: cookieHeader } : {}),
    };
  }

  return {
    "user-agent": ua,
    accept: "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "accept-encoding": "gzip, deflate, br, zstd",
    "cache-control": "no-cache",
    origin: "https://space.bilibili.com",
    referer,
    "sec-ch-ua": secChUa,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": isEdge ? '"Windows"' : ua.includes("Mac") ? '"macOS"' : '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    pragma: "no-cache",
    ...(cookieHeader ? { cookie: cookieHeader } : {}),
  };
}

// ── Request with retry + exponential backoff + jitter ────────────────
async function getJson(url, referer, cookieHeader = "", retries = 5) {
  let lastError;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      const headers = buildHeaders(referer, cookieHeader);
      const response = await fetch(url, { headers });

      // HTTP 412/403 → risk control ban
      if (response.status === 412 || response.status === 403) {
        throw new Error(`HTTP ${response.status}: Bilibili risk-control ban (retryable)`);
      }

      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(
          `Bilibili returned non-JSON status=${response.status}: ${text.slice(0, 90)} (retryable)`,
        );
      }
      if ([-352, -412, -799].includes(data.code)) {
        throw new Error(
          `Bilibili risk-control response code=${data.code}: ${data.message} (retryable)`,
        );
      }
      return data;
    } catch (error) {
      lastError = error;
      if (attempt < retries - 1) {
        // Exponential backoff with jitter: 3s, 6s, 12s, 24s, 48s ± 30%
        const base = 3000 * 2 ** attempt;
        await new Promise((resolve) => setTimeout(resolve, jitter(base)));
      }
    }
  }
  throw lastError;
}

async function getMixin(cookieHeader, referer) {
  const nav = await getJson("https://api.bilibili.com/x/web-interface/nav", referer, cookieHeader);
  const img = nav.data.wbi_img.img_url.split("/").pop().split(".")[0];
  const sub = nav.data.wbi_img.sub_url.split("/").pop().split(".")[0];
  return mixinKey(img + sub);
}

function arcUrl(mid, pn, ps, mixin) {
  const params = {
    pn: String(pn),
    ps: String(ps),
    tid: "0",
    special_type: "",
    order: "pubdate",
    mid,
    index: "0",
    keyword: "",
    order_avoided: "true",
    platform: "web",
    web_location: "333.1387",
    dm_img_list: "[]",
    dm_img_str: "V2ViR0wgMS4wIChPcGVuR0wgRVMgMi4wIENocm9taXVtKQ",
    dm_cover_img_str:
      "QU5HTEUgKEFNRCwgQU1EIFJhZGVvbihUTSkgR3JhcGhpY3MgKDB4MDAwMDE2ODEpIERpcmVjdDNEMTEgdnNfNV8wIHBzXzVfMCwgRDNEMTEpR29vZ2xlIEluYy4gKEFNRC",
    dm_img_inter: '{"ds":[],"wh":[4787,4649,85],"of":[439,878,439]}',
  };
  return `https://api.bilibili.com/x/space/wbi/arc/search?${sign(params, mixin)}`;
}

function toIso(ts) {
  return ts ? new Date(ts * 1000 + 8 * 3600 * 1000).toISOString().replace(".000Z", "+08:00") : "";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, jitter(ms)));
}

export async function collect({ account, cookieHeader = "", limit, delay = 5000 }) {
  const mid = extractMid(account);
  const spaceUrl = `https://space.bilibili.com/${mid}/upload/video`;

  // Sequential requests with jittered delay (bendi.monitor: MAX_CONCURRENCY_NUM = 1)
  const card = await getJson(
    `https://api.bilibili.com/x/web-interface/card?mid=${mid}`,
    `https://space.bilibili.com/${mid}`,
    cookieHeader,
  );
  await sleep(delay);
  const relation = await getJson(
    `https://api.bilibili.com/x/relation/stat?vmid=${mid}`,
    `https://space.bilibili.com/${mid}`,
    cookieHeader,
  );
  await sleep(delay);
  const navnum = await getJson(
    `https://api.bilibili.com/x/space/navnum?mid=${mid}&web_location=333.1387`,
    `https://space.bilibili.com/${mid}`,
    cookieHeader,
  );
  await sleep(delay);

  const mixin = await getMixin(cookieHeader, spaceUrl);
  await sleep(delay);
  const ps = 40;
  const first = await getJson(arcUrl(mid, 1, ps, mixin), spaceUrl, cookieHeader);
  await sleep(delay);
  const pageInfo = first.data.page || first.data.list?.page || {};
  const total = pageInfo.count || pageInfo.total || navnum.data?.video || 0;
  const pageCount = Math.ceil(total / ps);
  const rawVideos = [];
  const pages = limit ? Math.min(pageCount, Math.ceil(limit / ps)) : pageCount;
  for (let pn = 1; pn <= pages; pn += 1) {
    const page =
      pn === 1 ? first : await getJson(arcUrl(mid, pn, ps, mixin), spaceUrl, cookieHeader);
    rawVideos.push(...(page.data?.list?.vlist || []));
    if (limit && rawVideos.length >= limit) {
      break;
    }
    await sleep(delay);
  }
  const seen = new Set();
  const uniqueVideos = rawVideos
    .filter((video) => {
      const key = String(video.bvid || video.aid);
      if (!key || seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .slice(0, limit || undefined);
  const stats = new Map();
  for (const video of uniqueVideos) {
    const stat = await getJson(
      `https://api.bilibili.com/x/web-interface/view?bvid=${encodeURIComponent(video.bvid)}`,
      `https://www.bilibili.com/video/${video.bvid}`,
      cookieHeader,
      3,
    );
    stats.set(video.bvid, stat.data?.stat || {});
    await sleep(delay);
  }
  const videos = uniqueVideos.map((video) => {
    const stat = stats.get(video.bvid) || {};
    return {
      id: video.bvid,
      title: video.title,
      url: `https://www.bilibili.com/video/${video.bvid}`,
      publishedAt: toIso(video.created),
      duration: video.length,
      likes: stat.like ?? 0,
      views: stat.view ?? video.play ?? 0,
      comments: stat.reply ?? video.comment ?? 0,
      shares: stat.share ?? 0,
      favorites: stat.favorite ?? 0,
      coins: stat.coin ?? 0,
    };
  });
  return {
    account: {
      platform: "bilibili",
      id: mid,
      url: `https://space.bilibili.com/${mid}`,
      name: card.data?.card?.name || "",
      followers:
        relation.data?.follower ?? card.data?.follower ?? card.data?.card?.fans ?? 0,
      videoCount: navnum.data?.video ?? card.data?.archive_count ?? total,
      totalLikes: card.data?.like_num ?? 0,
      totalViews: videos.reduce((sum, video) => sum + video.views, 0),
      totalComments: videos.reduce((sum, video) => sum + video.comments, 0),
      fetchedAt: new Date().toISOString(),
    },
    videos,
  };
}
