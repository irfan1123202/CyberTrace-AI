// CyberTrace AI — Linux Tools Service
// =============================================================================
// Wraps Linux CLI tools (dig, whois, host, nslookup, traceroute, curl) using
// Node.js child_process for forensic network analysis.
//
// On Windows, automatically uses WSL (wsl <command>) if available, or falls
// back to native Windows equivalents (Resolve-DnsName, nslookup, etc.).
// =============================================================================

const { execFile, exec } = require('child_process');
const { promisify } = require('util');
const os = require('os');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const IS_WINDOWS = os.platform() === 'win32';

/**
 * Determine if WSL is available on Windows.
 */
let _wslAvailable = null;
async function isWslAvailable() {
  if (!IS_WINDOWS) return false;
  if (_wslAvailable !== null) return _wslAvailable;
  try {
    await execAsync('wsl echo ok', { timeout: 3000 });
    _wslAvailable = true;
  } catch {
    _wslAvailable = false;
  }
  return _wslAvailable;
}

/**
 * Run a Linux command — uses WSL on Windows if available.
 * @param {string} command - Full shell command string
 * @param {number} timeoutMs
 */
async function runLinux(command, timeoutMs = 10000) {
  const wsl = await isWslAvailable();
  const fullCmd = IS_WINDOWS && wsl ? `wsl ${command}` : command;

  try {
    const { stdout, stderr } = await execAsync(fullCmd, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 512, // 512 KB
    });
    return { success: true, stdout: stdout.trim(), stderr: stderr.trim(), command: fullCmd };
  } catch (err) {
    return {
      success: false,
      stdout: err.stdout?.trim() || '',
      stderr: err.stderr?.trim() || err.message,
      command: fullCmd,
      error: err.message,
    };
  }
}

// ─── DIG ──────────────────────────────────────────────────────────────────────

/**
 * Run `dig` for DNS lookups.
 * @param {string} domain
 * @param {'A'|'MX'|'TXT'|'NS'|'CNAME'|'PTR'|'SOA'|'AAAA'} type
 */
async function dig(domain, type = 'A') {
  if (IS_WINDOWS && !(await isWslAvailable())) {
    return digFallbackWindows(domain, type);
  }
  const result = await runLinux(`dig +short +time=4 +tries=2 ${domain} ${type}`);
  return {
    tool: 'dig',
    domain,
    type,
    raw: result.stdout,
    records: result.stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean),
    success: result.success,
    error: result.success ? null : result.stderr,
  };
}

/**
 * Windows fallback: use nslookup (no WSL)
 */
async function digFallbackWindows(domain, type) {
  try {
    const { stdout } = await execAsync(`nslookup -type=${type} ${domain}`, { timeout: 8000 });
    return {
      tool: 'nslookup (windows-fallback)',
      domain,
      type,
      raw: stdout.trim(),
      records: stdout
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('Server:') && !l.startsWith('Address:')),
      success: true,
      error: null,
    };
  } catch (err) {
    return { tool: 'nslookup', domain, type, raw: '', records: [], success: false, error: err.message };
  }
}

/**
 * Full SPF record lookup — parses `v=spf1` TXT record.
 */
async function lookupSpf(domain) {
  const txt = await dig(domain, 'TXT');
  const spfRecord = txt.records.find((r) => r.includes('v=spf1'));
  return {
    domain,
    spfRecord: spfRecord || null,
    hasSpf: !!spfRecord,
    mechanisms: spfRecord ? parseSpfMechanisms(spfRecord, domain) : [],
    raw: txt.raw,
  };
}

function parseSpfMechanisms(spfStr, domain = '') {
  const mechanisms = [];
  const parts = spfStr.replace(/^"?|"?$/g, '').split(/\s+/);
  for (const part of parts) {
    if (part.startsWith('ip4:')) mechanisms.push({ type: 'ip4', value: part.slice(4) });
    else if (part.startsWith('ip6:')) mechanisms.push({ type: 'ip6', value: part.slice(4) });
    else if (part.startsWith('include:')) mechanisms.push({ type: 'include', value: part.slice(8) });
    else if (part.startsWith('a:')) mechanisms.push({ type: 'a', value: part.slice(2) });
    else if (part.startsWith('mx')) mechanisms.push({ type: 'mx', value: domain || 'mx' });
    else if (part === '~all') mechanisms.push({ type: 'all', qualifier: 'softfail' });
    else if (part === '-all') mechanisms.push({ type: 'all', qualifier: 'hardfail' });
    else if (part === '+all') mechanisms.push({ type: 'all', qualifier: 'pass' });
  }
  return mechanisms;
}

/**
 * DMARC policy lookup — queries _dmarc.<domain> TXT record.
 */
async function lookupDmarc(domain) {
  const dmarcDomain = `_dmarc.${domain}`;
  const txt = await dig(dmarcDomain, 'TXT');
  const dmarcRecord = txt.records.find((r) => r.includes('v=DMARC1'));
  const policy = dmarcRecord?.match(/p=([a-z]+)/i)?.[1] || null;
  const rua = dmarcRecord?.match(/rua=mailto:([^\s;]+)/i)?.[1] || null;
  return {
    domain,
    dmarcDomain,
    dmarcRecord: dmarcRecord || null,
    hasDmarc: !!dmarcRecord,
    policy,
    reportingAddress: rua,
    raw: txt.raw,
  };
}

/**
 * MX record lookup — shows mail server infrastructure.
 */
async function lookupMx(domain) {
  const mx = await dig(domain, 'MX');
  return {
    domain,
    mxRecords: mx.records.map((r) => {
      const [priority, host] = r.split(/\s+/);
      return { priority: parseInt(priority) || 0, host: host || r };
    }),
    raw: mx.raw,
    success: mx.success,
  };
}

// ─── HOST (Reverse DNS / PTR) ─────────────────────────────────────────────────

/**
 * Reverse DNS lookup using `host` command.
 * @param {string} ip
 */
async function reverseDns(ip) {
  if (IS_WINDOWS && !(await isWslAvailable())) {
    return reverseDnsFallbackWindows(ip);
  }
  const result = await runLinux(`host -W 4 ${ip}`);
  const ptrMatch = result.stdout.match(/pointer\s+(.+?)\.?\s*$/im);
  const hostname = ptrMatch ? ptrMatch[1].trim() : null;
  return {
    tool: 'host',
    ip,
    hostname,
    hasPtr: !!hostname,
    raw: result.stdout,
    success: result.success,
  };
}

async function reverseDnsFallbackWindows(ip) {
  try {
    const { stdout } = await execAsync(`nslookup ${ip}`, { timeout: 8000 });
    const nameMatch = stdout.match(/Name:\s+(.+)/i);
    return {
      tool: 'nslookup (windows)',
      ip,
      hostname: nameMatch ? nameMatch[1].trim() : null,
      hasPtr: !!nameMatch,
      raw: stdout.trim(),
      success: true,
    };
  } catch (err) {
    return { tool: 'nslookup', ip, hostname: null, hasPtr: false, raw: '', success: false, error: err.message };
  }
}

// ─── WHOIS ────────────────────────────────────────────────────────────────────

/**
 * WHOIS lookup using system `whois` command.
 * Parses registration date, registrar, name servers, and status.
 */
async function whoisLookup(domain) {
  if (IS_WINDOWS && !(await isWslAvailable())) {
    return whoisFallbackApi(domain);
  }

  const result = await runLinux(`whois ${domain}`, 15000);
  if (!result.success || !result.stdout) {
    return whoisFallbackApi(domain);
  }

  return parseWhoisOutput(domain, result.stdout);
}

function parseWhoisOutput(domain, raw) {
  const get = (patterns) => {
    for (const p of patterns) {
      const m = raw.match(new RegExp(`^${p}:\\s*(.+)$`, 'im'));
      if (m) return m[1].trim();
    }
    return null;
  };

  const registrar = get(['Registrar', 'registrar']);
  const createdRaw = get(['Creation Date', 'Created On', 'created', 'Registered Date']);
  const updatedRaw = get(['Updated Date', 'Last Modified', 'modified']);
  const expiresRaw = get(['Registry Expiry Date', 'Expiration Date', 'expires']);
  const registrant = get(['Registrant Organization', 'Registrant Name', 'org']);
  const country = get(['Registrant Country', 'Country']);
  const statusRaw = raw.match(/^Status:\s*(.+)$/gim);

  const nameServers = [];
  const nsMatches = raw.matchAll(/^Name Server:\s*(.+)$/gim);
  for (const m of nsMatches) nameServers.push(m[1].trim().toLowerCase());

  const created = createdRaw ? new Date(createdRaw) : null;
  const domainAgeMs = created && !isNaN(created) ? Date.now() - created.getTime() : null;
  const domainAgeDays = domainAgeMs ? Math.floor(domainAgeMs / 86_400_000) : null;

  return {
    tool: 'whois',
    domain,
    registrar: registrar || 'Unknown',
    registrantOrg: registrant || 'Redacted / Privacy Protected',
    country: country || 'Unknown',
    created: createdRaw || null,
    updated: updatedRaw || null,
    expires: expiresRaw || null,
    domainAgeDays,
    ageCategory:
      domainAgeDays === null
        ? 'UNKNOWN'
        : domainAgeDays < 7
        ? 'NEWLY_REGISTERED (< 7 days)'
        : domainAgeDays < 30
        ? 'VERY_NEW (< 30 days)'
        : domainAgeDays < 180
        ? 'RECENT (< 6 months)'
        : 'ESTABLISHED',
    nameServers,
    statusFlags: statusRaw ? statusRaw.map((s) => s.replace(/^Status:\s*/i, '').trim()) : [],
    raw,
    success: true,
  };
}

/**
 * Fallback WHOIS via RDAP JSON API (no system command needed)
 */
async function whoisFallbackApi(domain) {
  const axios = require('axios');
  try {
    const tld = domain.split('.').slice(-1)[0];
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    const { data } = await axios.get(rdapUrl, { timeout: 10000 });

    const created = data.events?.find((e) => e.eventAction === 'registration')?.eventDate;
    const updated = data.events?.find((e) => e.eventAction === 'last changed')?.eventDate;
    const expires = data.events?.find((e) => e.eventAction === 'expiration')?.eventDate;
    const registrar = data.entities?.find((e) => e.roles?.includes('registrar'))?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3];
    const nameServers = data.nameservers?.map((ns) => ns.ldhName?.toLowerCase()) || [];
    const domainAgeDays = created ? Math.floor((Date.now() - new Date(created).getTime()) / 86_400_000) : null;

    return {
      tool: 'rdap-api (fallback)',
      domain,
      registrar: registrar || 'Unknown',
      registrantOrg: 'Privacy Protected (RDAP)',
      created: created || null,
      updated: updated || null,
      expires: expires || null,
      domainAgeDays,
      ageCategory:
        domainAgeDays === null
          ? 'UNKNOWN'
          : domainAgeDays < 7
          ? 'NEWLY_REGISTERED'
          : domainAgeDays < 30
          ? 'VERY_NEW'
          : domainAgeDays < 180
          ? 'RECENT'
          : 'ESTABLISHED',
      nameServers,
      statusFlags: data.status || [],
      raw: JSON.stringify(data, null, 2),
      success: true,
    };
  } catch (err) {
    return {
      tool: 'rdap-api',
      domain,
      registrar: 'Unknown',
      registrantOrg: 'Unknown',
      domainAgeDays: null,
      ageCategory: 'UNKNOWN',
      nameServers: [],
      statusFlags: [],
      success: false,
      error: err.message,
      raw: '',
    };
  }
}

// ─── TRACEROUTE ──────────────────────────────────────────────────────────────

/**
 * Limited traceroute (max 10 hops) — for network path reconstruction.
 * Returns hop-by-hop latency data.
 */
async function traceroute(target, maxHops = 10) {
  if (IS_WINDOWS && !(await isWslAvailable())) {
    return tracerouteFallbackWindows(target, maxHops);
  }
  const result = await runLinux(`traceroute -m ${maxHops} -n -w 2 ${target}`, 30000);
  const hops = parseTracerouteOutput(result.stdout);
  return { tool: 'traceroute', target, hops, raw: result.stdout, success: result.success };
}

async function tracerouteFallbackWindows(target, maxHops) {
  try {
    const { stdout } = await execAsync(`tracert -h ${maxHops} -d -w 2000 ${target}`, { timeout: 30000 });
    const hops = parseTracerouteOutput(stdout);
    return { tool: 'tracert (windows)', target, hops, raw: stdout.trim(), success: true };
  } catch (err) {
    return { tool: 'tracert', target, hops: [], raw: '', success: false, error: err.message };
  }
}

function parseTracerouteOutput(raw) {
  const hops = [];
  const lines = raw.split('\n').slice(1);
  for (const line of lines) {
    const m = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!m) continue;
    const hopNum = parseInt(m[1]);
    const rest = m[2].trim();
    if (rest.startsWith('*')) {
      hops.push({ hop: hopNum, ip: '*', hostname: '*', latencyMs: null, timeout: true });
    } else {
      const ipMatch = rest.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const latMatch = rest.match(/([\d.]+)\s*ms/);
      hops.push({
        hop: hopNum,
        ip: ipMatch ? ipMatch[1] : 'unknown',
        hostname: null,
        latencyMs: latMatch ? parseFloat(latMatch[1]) : null,
        timeout: false,
      });
    }
  }
  return hops;
}

// ─── PING ────────────────────────────────────────────────────────────────────

/**
 * Ping with 3 packets — measures RTT and packet loss.
 */
async function ping(target) {
  const cmd = IS_WINDOWS ? `ping -n 3 ${target}` : `ping -c 3 -W 3 ${target}`;
  const useWsl = IS_WINDOWS && (await isWslAvailable());
  const result = useWsl
    ? await runLinux(`ping -c 3 -W 3 ${target}`, 15000)
    : await execAsync(cmd, { timeout: 15000 }).then((r) => ({ success: true, stdout: r.stdout.trim() })).catch((e) => ({ success: false, stdout: e.stdout || '', error: e.message }));

  const rttMatch = result.stdout?.match(/(?:min\/avg\/max[^\d]*|Average\s*=\s*)([\d.]+)(?:\s*\/[\d.]+\/[\d.]+|ms)/);
  const lossMatch = result.stdout?.match(/(\d+)%\s*(?:packet\s*)?loss/i);

  return {
    tool: 'ping',
    target,
    avgRttMs: rttMatch ? parseFloat(rttMatch[1]) : null,
    packetLoss: lossMatch ? parseInt(lossMatch[1]) : null,
    reachable: result.success && (lossMatch ? parseInt(lossMatch[1]) < 100 : true),
    raw: result.stdout || '',
    success: result.success,
  };
}

module.exports = {
  dig,
  lookupSpf,
  lookupDmarc,
  lookupMx,
  reverseDns,
  whoisLookup,
  traceroute,
  ping,
  runLinux,
  isWslAvailable,
};
