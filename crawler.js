#!/usr/bin/env node

// ═══════════════════════════════════════════════
// AgentGuard — Skill Crawler
// Crawls GitHub for AI agent skills
// Run: node scripts/crawler.js
// Schedule: GitHub Actions cron every 6 hours
// ═══════════════════════════════════════════════

const { scanContent, calculateTrustScore, determineTrustStatus } = require("./scanner");

// ─── Config ───
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

// Topics to search on GitHub
const SEARCH_QUERIES = [
  { query: "topic:openclaw-skill", platform: "openclaw" },
  { query: "topic:agent-skill", platform: "openclaw" },
  { query: "topic:langchain-tool", platform: "langchain" },
  { query: "topic:crewai-tool", platform: "crewai" },
  { query: "topic:autogen-skill", platform: "autogen" },
  { query: "filename:SKILL.md openclaw", platform: "openclaw" },
  { query: "filename:SKILL.md agent", platform: "openclaw" },
  { query: "openclaw skill in:readme", platform: "openclaw" },
  { query: "langchain tool agent in:readme", platform: "langchain" },
];

// ─── GitHub API Helper ───
async function githubFetch(url) {
  var headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "AgentGuard-Crawler/0.1",
  };
  if (GITHUB_TOKEN) {
    headers["Authorization"] = "Bearer " + GITHUB_TOKEN;
  }

  var response = await fetch(url, { headers: headers });

  if (response.status === 403) {
    console.log("  ⚠ Rate limited. Waiting 60s...");
    await new Promise(r => setTimeout(r, 60000));
    response = await fetch(url, { headers: headers });
  }

  if (!response.ok) {
    throw new Error("GitHub API " + response.status + ": " + response.statusText);
  }

  return response.json();
}

// ─── Supabase Helper ───
async function supabaseFetch(path, options) {
  var url = SUPABASE_URL + "/rest/v1" + path;
  var headers = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": "Bearer " + SUPABASE_SERVICE_KEY,
    "Content-Type": "application/json",
    "Prefer": options && options.prefer ? options.prefer : "return=representation",
  };

  var response = await fetch(url, {
    method: options && options.method ? options.method : "GET",
    headers: headers,
    body: options && options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    var text = await response.text();
    throw new Error("Supabase " + response.status + ": " + text);
  }

  var contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("json")) {
    return response.json();
  }
  return null;
}

// ─── Fetch SKILL.md or README from repo ───
async function fetchSkillContent(repoFullName) {
  // Try SKILL.md first
  try {
    var data = await githubFetch(
      "https://api.github.com/repos/" + repoFullName + "/contents/SKILL.md"
    );
    if (data.content) {
      return Buffer.from(data.content, "base64").toString("utf-8");
    }
  } catch (e) { /* no SKILL.md */ }

  // Try README.md
  try {
    var data = await githubFetch(
      "https://api.github.com/repos/" + repoFullName + "/readme"
    );
    if (data.content) {
      return Buffer.from(data.content, "base64").toString("utf-8");
    }
  } catch (e) { /* no README */ }

  return null;
}

// ─── Process one repository ───
async function processRepo(repo, platformSlug) {
  var slug = repo.full_name.replace("/", "--").toLowerCase();
  var name = repo.name;

  console.log("  → " + name + " (" + platformSlug + ")");

  // Fetch content for scanning
  var content = await fetchSkillContent(repo.full_name);

  // Run security scan
  var scanResult = scanContent(content || "", "SKILL.md");

  // Calculate scores
  var qualityScore = 5;
  if (content && content.length > 500) qualityScore += 1;
  if (content && content.length > 2000) qualityScore += 1;
  if (repo.license) qualityScore += 1;
  if (repo.description && repo.description.length > 20) qualityScore += 1;
  if (qualityScore > 10) qualityScore = 10;

  var trustScore = calculateTrustScore(
    scanResult.safety_score,
    qualityScore,
    0, // no community rating yet
    repo.stargazers_count || 0,
    repo.pushed_at
  );

  var trustStatus = determineTrustStatus(trustScore, scanResult.safety_score, false);

  // Upsert skill to database
  var skillData = {
    slug: slug,
    name: name,
    description: repo.description || "",
    platform_slug: platformSlug,
    author_name: repo.owner ? repo.owner.login : "unknown",
    author_url: repo.owner ? repo.owner.html_url : "",
    source_url: repo.html_url,
    license: repo.license ? repo.license.spdx_id : "UNKNOWN",
    latest_version: "0.0.0",
    github_stars: repo.stargazers_count || 0,
    downloads_total: repo.stargazers_count || 0, // use stars as proxy
    downloads_week: Math.floor((repo.stargazers_count || 0) / 10),
    trust_score: trustScore,
    safety_score: scanResult.safety_score,
    quality_score: qualityScore,
    trust_status: trustStatus,
    last_updated_at: repo.pushed_at,
    last_scanned_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  try {
    // Upsert (insert or update on conflict)
    await supabaseFetch("/skills?on_conflict=slug", {
      method: "POST",
      body: skillData,
      prefer: "resolution=merge-duplicates,return=representation",
    });

    // Insert scan results
    for (var i = 0; i < scanResult.threats.length; i++) {
      await supabaseFetch("/skill_threats", {
        method: "POST",
        body: {
          skill_id: null, // will be linked later
          description: scanResult.threats[i].description + " (" + scanResult.threats[i].file + ")",
        },
        prefer: "return=minimal",
      });
    }

    // Insert permissions
    for (var i = 0; i < scanResult.permissions.length; i++) {
      var p = scanResult.permissions[i];
      await supabaseFetch("/skill_permissions", {
        method: "POST",
        body: {
          skill_id: null, // will be linked later  
          permission: p.permission,
          risk_level: p.risk_level,
          description: p.description,
        },
        prefer: "return=minimal",
      });
    }

    // Insert tags from repo topics
    if (repo.topics && repo.topics.length > 0) {
      // Get the skill ID first
      var skills = await supabaseFetch("/skills?slug=eq." + slug + "&select=id");
      if (skills && skills.length > 0) {
        for (var i = 0; i < Math.min(repo.topics.length, 10); i++) {
          try {
            await supabaseFetch("/skill_tags", {
              method: "POST",
              body: { skill_id: skills[0].id, tag: repo.topics[i] },
              prefer: "return=minimal",
            });
          } catch (e) { /* duplicate tag, ignore */ }
        }
      }
    }

    return { status: "ok", name: name, trust: trustStatus, score: trustScore };
  } catch (err) {
    console.log("  ✗ Error saving " + name + ": " + err.message);
    return { status: "error", name: name, error: err.message };
  }
}

// ─── Main Crawl Function ───
async function crawl() {
  console.log("");
  console.log("⛨ AgentGuard Crawler v0.1");
  console.log("─".repeat(50));
  console.log("");

  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.log("✗ Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
    console.log("  Set environment variables and try again.");
    process.exit(1);
  }

  var startTime = Date.now();
  var totalFound = 0;
  var totalNew = 0;
  var totalErrors = 0;
  var seenRepos = {};

  for (var q = 0; q < SEARCH_QUERIES.length; q++) {
    var search = SEARCH_QUERIES[q];
    console.log("Searching: " + search.query + " [" + search.platform + "]");

    try {
      // GitHub search API (max 100 per page, max 1000 total)
      for (var page = 1; page <= 3; page++) {
        var url = "https://api.github.com/search/repositories?q=" +
          encodeURIComponent(search.query) +
          "&sort=stars&order=desc&per_page=30&page=" + page;

        var data = await githubFetch(url);

        if (!data.items || data.items.length === 0) break;

        for (var i = 0; i < data.items.length; i++) {
          var repo = data.items[i];

          // Skip if already processed
          if (seenRepos[repo.full_name]) continue;
          seenRepos[repo.full_name] = true;

          // Skip forks and very small repos
          if (repo.fork) continue;
          if (repo.size < 1) continue;

          totalFound++;

          try {
            var result = await processRepo(repo, search.platform);
            if (result.status === "ok") totalNew++;
            else totalErrors++;
          } catch (err) {
            console.log("  ✗ " + repo.name + ": " + err.message);
            totalErrors++;
          }

          // Rate limit: wait 1 second between repos
          await new Promise(r => setTimeout(r, 1000));
        }

        // Wait between pages
        await new Promise(r => setTimeout(r, 2000));
      }
    } catch (err) {
      console.log("✗ Search error: " + err.message);
      totalErrors++;
    }

    console.log("");
  }

  // Update platform counts
  console.log("Updating platform stats...");
  try {
    var platforms = await supabaseFetch("/platforms?select=slug");
    for (var i = 0; i < platforms.length; i++) {
      var pSlug = platforms[i].slug;
      var skills = await supabaseFetch("/skills?platform_slug=eq." + pSlug + "&select=trust_status");
      var total = skills.length;
      var verified = skills.filter(function(s) { return s.trust_status === "verified" || s.trust_status === "scanned"; }).length;
      var threats = skills.filter(function(s) { return s.trust_status === "flagged"; }).length;

      await supabaseFetch("/platforms?slug=eq." + pSlug, {
        method: "PATCH",
        body: { skill_count: total, verified_count: verified, threat_count: threats },
      });
    }
  } catch (err) {
    console.log("  ⚠ Could not update platform stats: " + err.message);
  }

  // Log crawl results
  var duration = Date.now() - startTime;
  console.log("");
  console.log("─".repeat(50));
  console.log("✓ Crawl complete");
  console.log("  Found:   " + totalFound);
  console.log("  Saved:   " + totalNew);
  console.log("  Errors:  " + totalErrors);
  console.log("  Time:    " + (duration / 1000).toFixed(1) + "s");
  console.log("");

  // Log to crawl_log table
  try {
    await supabaseFetch("/crawl_log", {
      method: "POST",
      body: {
        source: "github",
        skills_found: totalFound,
        skills_new: totalNew,
        errors: totalErrors,
        duration_ms: duration,
        finished_at: new Date().toISOString(),
      },
      prefer: "return=minimal",
    });
  } catch (err) { /* non-critical */ }
}

// Run
crawl().catch(function(err) {
  console.error("Fatal: " + err.message);
  process.exit(1);
});
