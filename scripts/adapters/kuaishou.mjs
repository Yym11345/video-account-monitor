// ── UA rotation pool ─────────────────────────────────────────────────
const UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
];

// ── GraphQL queries (from bendi.monitor) ─────────────────────────────
const VISION_PROFILE_QUERY = `query visionProfile($userId: String) {
  visionProfile(userId: $userId) {
    result
    hostName
    userProfile {
      ownerCount { fan photo follow photo_public __typename }
      profile { gender user_name user_id headurl user_text user_profile_bg_url __typename }
      isFollowing
      __typename
    }
    __typename
  }
}`;

const PHOTO_FEED_FRAGMENT = `fragment photoContent on PhotoEntity {
  __typename
  id
  duration
  caption
  originCaption
  likeCount
  viewCount
  commentCount
  realLikeCount
  coverUrl
  photoUrl
  photoH265Url
  manifest
  manifestH265
  videoResource
  coverUrls { url __typename }
  timestamp
  expTag
  animatedCoverUrl
  distance
  videoRatio
  liked
  stereoType
  profileUserTopPhoto
  musicBlocked
  riskTagContent
  riskTagUrl
}
fragment recoPhotoFragment on recoPhotoEntity {
  __typename
  id
  duration
  caption
  originCaption
  likeCount
  viewCount
  commentCount
  realLikeCount
  coverUrl
  photoUrl
  photoH265Url
  manifest
  manifestH265
  videoResource
  coverUrls { url __typename }
  timestamp
  expTag
  animatedCoverUrl
  distance
  videoRatio
  liked
  stereoType
  profileUserTopPhoto
  musicBlocked
  riskTagContent
  riskTagUrl
}
fragment feedContent on Feed {
  type
  author {
    id
    name
    headerUrl
    following
    headerUrls { url __typename }
    __typename
  }
  photo {
    ...photoContent
    ...recoPhotoFragment
    __typename
  }
  canAddComment
  llsid
  status
  currentPcursor
  tags { type name __typename }
  __typename
}`;

const VISION_PROFILE_PHOTO_LIST_QUERY = `${PHOTO_FEED_FRAGMENT}
query visionProfilePhotoList($pcursor: String, $userId: String, $page: String, $webPageArea: String) {
  visionProfilePhotoList(pcursor: $pcursor, userId: $userId, page: $page, webPageArea: $webPageArea) {
    result
    llsid
    webPageArea
    feeds { ...feedContent __typename }
    hostName
    pcursor
    __typename
  }
}`;

const VISION_SEARCH_PHOTO_QUERY = `${PHOTO_FEED_FRAGMENT}
query visionSearchPhoto($keyword: String, $pcursor: String, $searchSessionId: String, $page: String, $webPageArea: String) {
  visionSearchPhoto(keyword: $keyword, pcursor: $pcursor, searchSessionId: $searchSessionId, page: $page, webPageArea: $webPageArea) {
    result
    feeds { ...feedContent __typename }
    searchSessionId
    pcursor
    __typename
  }
}`;

// ── Helpers ──────────────────────────────────────────────────────────
function randItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function jitter(base) {
  return Math.round(base * (0.7 + Math.random() * 0.6));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, jitter(ms)));
}

function extractUserId(account) {
  const text = String(account);
  // https://www.kuaishou.com/profile/3x4jtnbfter525a
  const match = text.match(/kuaishou\.com\/profile\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];
  // https://live.kuaishou.com/u/{userId}
  const liveMatch = text.match(/live\.kuaishou\.com\/u\/([a-zA-Z0-9_-]+)/);
  if (liveMatch) return liveMatch[1];
  // Pure ID
  if (/^[a-zA-Z0-9_-]+$/.test(text)) return text;
  throw new Error("Could not find Kuaishou user ID in account URL or id.");
}

function buildHeaders(cookieHeader) {
  const ua = randItem(UA_POOL);
  return {
    "user-agent": ua,
    accept: "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "content-type": "application/json;charset=UTF-8",
    origin: "https://www.kuaishou.com",
    referer: "https://www.kuaishou.com/profile/unknown",
    "sec-ch-ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": ua.includes("Mac") ? '"macOS"' : '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    ...(cookieHeader ? { cookie: cookieHeader } : {}),
  };
}

// ── Request with retry + exponential backoff ──────────────────────────
async function graphqlPost(operationName, variables, query, referer, cookieHeader = "", retries = 5) {
  let lastError;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      const headers = buildHeaders(cookieHeader);
      headers.referer = referer;
      const body = JSON.stringify({ operationName, variables, query });
      const response = await fetch("https://www.kuaishou.com/graphql", {
        method: "POST",
        headers,
        body,
      });

      if (response.status === 412 || response.status === 403 || response.status === 421) {
        throw new Error(`HTTP ${response.status}: Kuaishou risk-control ban (retryable)`);
      }

      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error(`Kuaishou returned non-JSON status=${response.status}: ${text.slice(0, 90)} (retryable)`);
      }
      if (data.errors) {
        throw new Error(`Kuaishou GraphQL error: ${JSON.stringify(data.errors)} (retryable)`);
      }
      return data.data || {};
    } catch (error) {
      lastError = error;
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
  // Kuaishou timestamps can be in seconds or milliseconds
  const ms = String(ts).length <= 10 ? ts * 1000 : ts;
  return new Date(ms + 8 * 3600 * 1000).toISOString().replace(".000Z", "+08:00");
}

function parseMetric(value) {
  if (value === null || value === undefined || value === "") return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;

  const text = String(value).trim().replace(/,/g, "");
  const match = text.match(/^([0-9]+(?:\.[0-9]+)?)(万|亿)?$/);
  if (!match) return 0;

  const number = Number(match[1]);
  const multiplier = match[2] === "亿" ? 100000000 : match[2] === "万" ? 10000 : 1;
  return Math.round(number * multiplier);
}

function formatDuration(ms) {
  if (!ms) return "";
  const totalSeconds = Math.floor(Number(ms) / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

async function searchVideosByCreator({ userId, keyword, cookieHeader, limit, delay }) {
  if (!keyword) return [];

  const rawVideos = [];
  let pcursor = "1";
  let searchSessionId = "";
  const maxPages = limit ? Math.ceil(limit / 20) : 2;

  for (let pageCount = 0; pageCount < maxPages && pcursor !== "no_more"; pageCount += 1) {
    const pageData = await graphqlPost(
      "visionSearchPhoto",
      { keyword, pcursor, page: "search", searchSessionId },
      VISION_SEARCH_PHOTO_QUERY,
      "https://www.kuaishou.com/search/video",
      cookieHeader,
    );
    await sleep(delay);

    const result = pageData.visionSearchPhoto || {};
    if (result.result !== 1) break;

    searchSessionId = result.searchSessionId || searchSessionId;
    pcursor = result.pcursor || "no_more";

    for (const feed of result.feeds || []) {
      if (feed.author?.id === userId && feed.photo) {
        rawVideos.push({ ...feed.photo, author: feed.author });
      }
    }

    if (limit && rawVideos.length >= limit) break;
  }

  return rawVideos;
}

// ── Main collect function ────────────────────────────────────────────
export async function collect({ account, cookieHeader = "", limit, delay = 5000 }) {
  const userId = extractUserId(account);
  const profileUrl = `https://www.kuaishou.com/profile/${userId}`;

  // 1. Fetch creator profile
  const profileData = await graphqlPost(
    "visionProfile",
    { userId },
    VISION_PROFILE_QUERY,
    profileUrl,
    cookieHeader,
  );
  await sleep(delay);

  const warnings = [];
  let collectionStatus = "complete";
  const visionProfile = profileData.visionProfile || {};
  if (visionProfile.result !== 1) {
    collectionStatus = "partial";
    warnings.push(`Kuaishou profile unavailable for ${userId}: result=${visionProfile.result ?? "missing"}.`);
  }

  const userProfile = visionProfile.userProfile || {};
  const profile = userProfile.profile || {};
  const ownerCount = userProfile.ownerCount || {};

  const expectedVideoCount = parseMetric(ownerCount.photo_public ?? ownerCount.photo);

  // 2. Fetch videos (paginated)
  const rawVideos = [];
  let profileListUnavailable = false;
  let pcursor = "";
  let pageCount = 0;
  const maxPages = limit ? Math.ceil(limit / 20) : 50;

  while (pcursor !== "no_more" && pageCount < maxPages) {
    let pageData;
    try {
      pageData = await graphqlPost(
        "visionProfilePhotoList",
        { pcursor, userId, page: "profile" },
        VISION_PROFILE_PHOTO_LIST_QUERY,
        profileUrl,
        cookieHeader,
      );
    } catch (error) {
      profileListUnavailable = true;
      warnings.push(
        `Kuaishou profile video list unavailable for ${userId}: ${error.message || String(error)}. Falling back to search.`,
      );
      break;
    }
    await sleep(delay);

    const result = pageData.visionProfilePhotoList || {};
    pcursor = result.pcursor || "no_more";
    const feeds = result.feeds || [];
    if (pageCount === 0 && expectedVideoCount > 0 && feeds.length === 0 && result.result !== 1) {
      profileListUnavailable = true;
      warnings.push(
        `Kuaishou profile video list unavailable for ${userId}: result=${result.result ?? "missing"}, pcursor=${result.pcursor ?? "missing"}. Falling back to search.`,
      );
      break;
    }

    for (const feed of feeds) {
      if (feed.photo) {
        rawVideos.push({ ...feed.photo, author: feed.author });
      }
    }

    pageCount += 1;
    if (limit && rawVideos.length >= limit) break;
  }

  if (rawVideos.length === 0) {
    try {
      rawVideos.push(...await searchVideosByCreator({
        userId,
        keyword: profile.user_name,
        cookieHeader,
        limit,
        delay,
      }));
    } catch (error) {
      warnings.push(`Kuaishou search fallback failed for ${userId}: ${error.message || String(error)}.`);
    }
  }

  if (profileListUnavailable) {
    collectionStatus = "partial";
  }

  if (rawVideos.length === 0 && expectedVideoCount > 0) {
    collectionStatus = "partial";
    warnings.push("Kuaishou collected account metrics, but no per-video rows were available.");
  }

  // 3. Deduplicate and limit
  const seen = new Set();
  const uniqueVideos = rawVideos
    .filter((video) => {
      const key = String(video.id);
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, limit || undefined);

  // 4. Map to output schema
  const videos = uniqueVideos.map((video) => ({
    id: String(video.id || ""),
    title: video.caption || "",
    url: `https://www.kuaishou.com/short-video/${video.id}`,
    publishedAt: toIso(video.timestamp),
    duration: formatDuration(video.duration),
    likes: parseMetric(video.realLikeCount ?? video.likeCount),
    views: parseMetric(video.viewCount),
    comments: parseMetric(video.commentCount),
    shares: 0,
    favorites: 0,
    coins: 0,
  }));

  return {
    account: {
      platform: "kuaishou",
      id: userId,
      url: profileUrl,
      name: profile.user_name || "",
      followers: parseMetric(ownerCount.fan),
      videoCount: expectedVideoCount || videos.length,
      totalLikes: videos.reduce((sum, v) => sum + v.likes, 0),
      totalViews: videos.reduce((sum, v) => sum + v.views, 0),
      totalComments: videos.reduce((sum, v) => sum + v.comments, 0),
      collectionStatus,
      warnings,
      fetchedAt: new Date().toISOString(),
    },
    videos,
  };
}
