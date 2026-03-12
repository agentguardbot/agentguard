// ═══════════════════════════════════════════════
// AgentGuard — API Routes
// All routes in one file for simplicity
// In production, split into separate route files
//
// Deploy as: Vercel Serverless Functions
// Or: Express.js server
// ═══════════════════════════════════════════════

// This file exports route handlers that can be used with
// any Node.js HTTP framework (Express, Fastify, Vercel, etc.)

const { scanContent, calculateTrustScore, determineTrustStatus } = require("../scripts/scanner");

// ─── Supabase Helper ───
function createSupabaseClient() {
  var url = process.env.SUPABASE_URL;
  var key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) throw new Error("Missing Supabase credentials");

  return {
    async query(path, options) {
      var fullUrl = url + "/rest/v1" + path;
      var headers = {
        "apikey": key,
        "Authorization": "Bearer " + key,
        "Content-Type": "application/json",
      };
      if (options && options.prefer) headers["Prefer"] = options.prefer;

      var resp = await fetch(fullUrl, {
        method: (options && options.method) || "GET",
        headers: headers,
        body: options && options.body ? JSON.stringify(options.body) : undefined,
      });

      if (!resp.ok) {
        var text = await resp.text();
        throw new Error("DB error " + resp.status + ": " + text);
      }

      var ct = resp.headers.get("content-type");
      if (ct && ct.includes("json")) return resp.json();
      return null;
    }
  };
}

// ═══════════════════════════════════════════════
// GET /api/skills — List skills with filters
// Query params: ?platform=openclaw&trust=verified&sort=score&limit=20&offset=0&q=gmail
// ═══════════════════════════════════════════════
async function handleGetSkills(params) {
  var db = createSupabaseClient();

  var path = "/skills?select=*";

  // Filters
  if (params.platform) path += "&platform_slug=eq." + params.platform;
  if (params.trust) path += "&trust_status=eq." + params.trust;
  if (params.safe === "true") path += "&trust_status=in.(verified,scanned)";
  if (params.threats === "true") path += "&trust_status=eq.flagged";

  // Search (simple ILIKE)
  if (params.q) path += "&or=(name.ilike.*" + params.q + "*,description.ilike.*" + params.q + "*)";

  // Sort
  var sort = params.sort || "score";
  if (sort === "score") path += "&order=trust_score.desc.nullslast";
  else if (sort === "downloads") path += "&order=downloads_week.desc";
  else if (sort === "newest") path += "&order=last_updated_at.desc";
  else if (sort === "reviews") path += "&order=review_count.desc";

  // Pagination
  var limit = Math.min(parseInt(params.limit) || 24, 100);
  var offset = parseInt(params.offset) || 0;
  path += "&limit=" + limit + "&offset=" + offset;

  var skills = await db.query(path);
  return { skills: skills, count: skills.length, limit: limit, offset: offset };
}

// ═══════════════════════════════════════════════
// GET /api/skills/search?q=<query>
// Full-text search
// ═══════════════════════════════════════════════
async function handleSearchSkills(params) {
  if (!params.q) return { skills: [], count: 0 };
  return handleGetSkills(params);
}

// ═══════════════════════════════════════════════
// GET /api/skills/:slug — Skill detail
// Includes permissions, scans, threats, tags
// ═══════════════════════════════════════════════
async function handleGetSkillDetail(slug) {
  var db = createSupabaseClient();

  // Get skill
  var skills = await db.query("/skills?slug=eq." + slug);
  if (!skills || skills.length === 0) return null;
  var skill = skills[0];

  // Get permissions
  var perms = await db.query("/skill_permissions?skill_id=eq." + skill.id + "&select=*");

  // Get scans
  var scans = await db.query("/security_scans?skill_id=eq." + skill.id + "&order=scanned_at.desc&limit=10");

  // Get threats
  var threats = await db.query("/skill_threats?skill_id=eq." + skill.id);

  // Get tags
  var tags = await db.query("/skill_tags?skill_id=eq." + skill.id + "&select=tag");

  // Get reviews
  var reviews = await db.query("/reviews?skill_id=eq." + skill.id + "&order=created_at.desc&limit=20");

  return {
    ...skill,
    permissions: perms || [],
    scans: scans || [],
    threats: (threats || []).map(function(t) { return t.description; }),
    tags: (tags || []).map(function(t) { return t.tag; }),
    reviews: reviews || [],
  };
}

// ═══════════════════════════════════════════════
// GET /api/platforms — All platforms with stats
// ═══════════════════════════════════════════════
async function handleGetPlatforms() {
  var db = createSupabaseClient();
  var platforms = await db.query("/platforms?select=*&order=skill_count.desc");
  return { platforms: platforms };
}

// ═══════════════════════════════════════════════
// GET /api/stats — Global statistics
// ═══════════════════════════════════════════════
async function handleGetStats() {
  var db = createSupabaseClient();

  var all = await db.query("/skills?select=trust_status");
  var platforms = await db.query("/platforms?select=slug");

  var total = all.length;
  var verified = all.filter(function(s) { return s.trust_status === "verified" || s.trust_status === "scanned"; }).length;
  var threats = all.filter(function(s) { return s.trust_status === "flagged"; }).length;

  return {
    total_skills: total,
    total_verified: verified,
    total_threats: threats,
    total_platforms: platforms.length,
    scan_cycle: "6h",
    last_updated: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════
// POST /api/scan — Scan a skill by name/URL
// Body: { "content": "...", "name": "skill-name" }
// ═══════════════════════════════════════════════
async function handleScanSkill(body) {
  if (!body || !body.content) {
    return { error: "content is required" };
  }

  var result = scanContent(body.content, body.name || "input");
  var trustScore = calculateTrustScore(result.safety_score, 5, 0, 0, null);
  var trustStatus = determineTrustStatus(trustScore, result.safety_score, false);

  return {
    name: body.name || "unknown",
    trust_score: trustScore,
    safety_score: result.safety_score,
    trust_status: trustStatus,
    findings_count: result.findings_count,
    threats: result.threats,
    permissions: result.permissions,
    scanned_at: new Date().toISOString(),
  };
}

module.exports = {
  handleGetSkills: handleGetSkills,
  handleSearchSkills: handleSearchSkills,
  handleGetSkillDetail: handleGetSkillDetail,
  handleGetPlatforms: handleGetPlatforms,
  handleGetStats: handleGetStats,
  handleScanSkill: handleScanSkill,
};
