// ═══════════════════════════════════════════════
// AgentGuard — Security Scanner
// Static analysis for AI agent skills
// ═══════════════════════════════════════════════

// Dangerous patterns to detect in SKILL.md and code files
const THREAT_PATTERNS = [
  { name: "base64_command", regex: /base64\s+(-d|--decode)|atob\(|Buffer\.from\(.+,\s*['"]base64['"]\)/gi, severity: "high", desc: "Base64-encoded command detected" },
  { name: "shell_exec", regex: /\b(exec|spawn|execSync|execFile|system)\s*\(|child_process/gi, severity: "critical", desc: "Shell execution pattern found" },
  { name: "eval_usage", regex: /\beval\s*\(|new\s+Function\s*\(/gi, severity: "high", desc: "Dynamic code evaluation detected" },
  { name: "curl_wget", regex: /\b(curl|wget|fetch)\s+https?:\/\/(?!github\.com|npmjs\.com|pypi\.org)/gi, severity: "medium", desc: "External download from unknown host" },
  { name: "env_read", regex: /process\.env|os\.environ|ENV\[|\.env\b|dotenv/gi, severity: "medium", desc: "Environment variable access" },
  { name: "keychain", regex: /keychain|keytar|credential|password\s*manager/gi, severity: "critical", desc: "Keychain/credential access" },
  { name: "crypto_wallet", regex: /private.?key|seed.?phrase|wallet.*secret|mnemonic/gi, severity: "critical", desc: "Crypto wallet key access pattern" },
  { name: "file_write", regex: /writeFile|writeFileSync|fs\.write|open\(.+['"]w['"]\)/gi, severity: "medium", desc: "Filesystem write operation" },
  { name: "network_exfil", regex: /webhook|ngrok|requestbin|pipedream|hookbin/gi, severity: "high", desc: "Potential data exfiltration endpoint" },
  { name: "obfuscation", regex: /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|String\.fromCharCode/gi, severity: "high", desc: "Code obfuscation detected" },
  { name: "paste_command", regex: /paste\s+(this|the\s+following)|copy\s+and\s+(run|paste|execute)/gi, severity: "high", desc: "Social engineering: paste command instruction" },
  { name: "hidden_binary", regex: /\.exe|\.bin|\.sh\b|chmod\s+\+x/gi, severity: "medium", desc: "Binary/executable reference" },
  { name: "startup_persist", regex: /LaunchAgent|launchd|systemd|crontab|startup|autorun/gi, severity: "critical", desc: "Persistence mechanism detected" },
  { name: "ssh_keys", regex: /\.ssh\/|id_rsa|id_ed25519|authorized_keys/gi, severity: "critical", desc: "SSH key access pattern" },
  { name: "browser_data", regex: /\.chrome|\.firefox|cookies\.sqlite|Login\s*Data|browser.*history/gi, severity: "critical", desc: "Browser data access pattern" },
];

// Permission patterns to extract from SKILL.md
const PERMISSION_PATTERNS = [
  { regex: /gmail|email|inbox|imap|smtp/gi, perm: "email", risk: "medium" },
  { regex: /calendar|schedule|event/gi, perm: "calendar", risk: "low" },
  { regex: /slack|discord|teams|chat/gi, perm: "messaging", risk: "medium" },
  { regex: /github|gitlab|bitbucket|repo/gi, perm: "git", risk: "medium" },
  { regex: /shopify|stripe|payment/gi, perm: "commerce", risk: "high" },
  { regex: /notion|confluence|docs/gi, perm: "documents", risk: "low" },
  { regex: /filesystem|fs\.|file.*read|file.*write/gi, perm: "filesystem", risk: "high" },
  { regex: /shell|exec|command|terminal|bash/gi, perm: "shell", risk: "critical" },
  { regex: /http|fetch|request|api.*call/gi, perm: "network", risk: "medium" },
  { regex: /database|sql|postgres|mongo|redis/gi, perm: "database", risk: "high" },
];

/**
 * Scan content for security threats
 * @param {string} content - SKILL.md or code file content
 * @param {string} filename - filename being scanned
 * @returns {{ threats: Array, permissions: Array, safety_score: number, findings_count: number }}
 */
function scanContent(content, filename) {
  if (!content) return { threats: [], permissions: [], safety_score: 10, findings_count: 0 };

  var threats = [];
  var permissions = [];
  var seenPerms = {};

  // Scan for threats
  for (var i = 0; i < THREAT_PATTERNS.length; i++) {
    var pattern = THREAT_PATTERNS[i];
    // Reset regex lastIndex
    pattern.regex.lastIndex = 0;
    var matches = content.match(pattern.regex);
    if (matches && matches.length > 0) {
      threats.push({
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.desc,
        matches: matches.length,
        file: filename,
      });
    }
  }

  // Extract permissions
  for (var i = 0; i < PERMISSION_PATTERNS.length; i++) {
    var pp = PERMISSION_PATTERNS[i];
    pp.regex.lastIndex = 0;
    if (pp.regex.test(content) && !seenPerms[pp.perm]) {
      seenPerms[pp.perm] = true;
      permissions.push({
        permission: pp.perm,
        risk_level: pp.risk,
        description: "Detected " + pp.perm + " related patterns",
      });
    }
  }

  // Calculate safety score (10 = safest, 0 = most dangerous)
  var score = 10;
  for (var i = 0; i < threats.length; i++) {
    var t = threats[i];
    if (t.severity === "critical") score -= 3;
    else if (t.severity === "high") score -= 2;
    else if (t.severity === "medium") score -= 1;
  }
  if (score < 0) score = 0;

  return {
    threats: threats,
    permissions: permissions,
    safety_score: Math.round(score * 10) / 10,
    findings_count: threats.length,
  };
}

/**
 * Calculate overall trust score
 */
function calculateTrustScore(safetyScore, qualityScore, communityRating, downloads, lastUpdated) {
  // Quality: based on README length, license, etc
  if (!qualityScore) qualityScore = 5;

  // Community: scale from 1-5 to 0-10
  var communityScore = communityRating ? communityRating * 2 : 5;

  // Popularity: log scale of downloads
  var popScore = downloads > 0 ? Math.min(10, Math.log10(downloads) * 2.5) : 0;

  // Maintenance: days since last update
  var mainScore = 5;
  if (lastUpdated) {
    var daysSince = (Date.now() - new Date(lastUpdated).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSince < 7) mainScore = 10;
    else if (daysSince < 30) mainScore = 8;
    else if (daysSince < 90) mainScore = 6;
    else if (daysSince < 365) mainScore = 4;
    else mainScore = 2;
  }

  var trustScore = (
    safetyScore * 0.35 +
    qualityScore * 0.25 +
    communityScore * 0.20 +
    popScore * 0.10 +
    mainScore * 0.10
  );

  return Math.round(trustScore * 10) / 10;
}

/**
 * Determine trust status from score
 */
function determineTrustStatus(trustScore, safetyScore, isManuallyReviewed) {
  if (safetyScore < 3) return "flagged";
  if (trustScore < 4) return "caution";
  if (isManuallyReviewed && trustScore >= 8) return "verified";
  if (trustScore >= 6) return "scanned";
  return "caution";
}

module.exports = { scanContent, calculateTrustScore, determineTrustStatus, THREAT_PATTERNS };
