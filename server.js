const express = require('express');
const cron = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');
require('dotenv').config();

const app = express();
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

/* ══════════════════════════════════════════════════════════
   IP HELPERS
══════════════════════════════════════════════════════════ */

/**
 * Extract the real client IP, handling proxies / Render / Railway / etc.
 * Never trust a single header blindly — fall back chain.
 */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // x-forwarded-for can be a comma-separated list; take the first (original client)
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return (
    req.headers['x-real-ip'] ||
    req.headers['cf-connecting-ip'] ||   // Cloudflare
    req.socket?.remoteAddress ||
    'unknown'
  );
}

/**
 * Convert an IPv4 string to a 32-bit unsigned integer for range comparisons.
 */
function ipToInt(ip) {
  // Strip IPv6-mapped IPv4 prefix (::ffff:)
  const clean = ip.replace(/^::ffff:/, '');
  const parts = clean.split('.');
  if (parts.length !== 4) return null;
  return parts.reduce((acc, octet) => {
    const n = parseInt(octet, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    return acc === null ? null : (acc * 256 + n);
  }, 0);
}

/**
 * Check whether `ip` falls within the CIDR block `cidr` (e.g. "175.176.0.0/16").
 * Returns true if blocked.
 */
function ipInCIDR(ip, cidr) {
  try {
    const [range, bits] = cidr.split('/');
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    const ipInt   = ipToInt(ip);
    const rangeInt = ipToInt(range);
    if (ipInt === null || rangeInt === null) return false;
    return (ipInt >>> 0 & mask) === (rangeInt >>> 0 & mask);
  } catch {
    return false;
  }
}

/* ══════════════════════════════════════════════════════════
   IN-MEMORY RATE-LIMIT STORE
   Key: /16 CIDR prefix (e.g. "175.176")   Value: { count, date }
   This is the fast path; DB is the persistent path.
══════════════════════════════════════════════════════════ */
const ipAttemptCache = new Map(); // "175.176.x.x" → { count, dateStr }

function todayStr() {
  return new Date().toISOString().slice(0, 10); // "2025-07-04"
}

/**
 * Returns the /16 prefix string used as the block key,
 * so that 175.176.1.5 and 175.176.200.9 share the same counter.
 */
function ipRangeKey(ip) {
  const clean = ip.replace(/^::ffff:/, '');
  const parts = clean.split('.');
  if (parts.length < 2) return clean;   // IPv6 — use as-is
  return parts[0] + '.' + parts[1];     // "175.176"
}

/**
 * Check whether this IP range is currently blocked.
 * First checks the in-memory cache, then falls back to the Supabase table.
 * Returns { blocked: bool, reason: string|null }
 */
async function checkIPBlocked(ip) {
  const rangeKey = ipRangeKey(ip);
  const today    = todayStr();

  // 1. Memory fast-path
  const cached = ipAttemptCache.get(rangeKey);
  if (cached && cached.dateStr === today && cached.count >= 3) {
    return { blocked: true, reason: 'Too many failed recovery attempts from your network today.' };
  }

  // 2. DB persistent check (survives restarts / incognito on different tab)
  try {
    const { data, error } = await supabase
      .from('ip_blocks')
      .select('attempt_count, block_date')
      .eq('ip_range', rangeKey)
      .eq('block_date', today)
      .maybeSingle();

    if (error) console.error('ip_blocks select error:', error.message);
    if (data && data.attempt_count >= 3) {
      // Warm the memory cache so subsequent checks don't hit DB
      ipAttemptCache.set(rangeKey, { count: data.attempt_count, dateStr: today });
      return { blocked: true, reason: 'Too many failed recovery attempts from your network today.' };
    }
  } catch (e) {
    console.error('checkIPBlocked DB error:', e.message);
  }

  return { blocked: false, reason: null };
}

/**
 * Record a failed attempt for this IP range.
 * Upserts into ip_blocks and updates the memory cache.
 */
async function recordFailedAttempt(ip) {
  const rangeKey = ipRangeKey(ip);
  const today    = todayStr();

  // Update memory cache
  const cached = ipAttemptCache.get(rangeKey);
  const newCount = (cached && cached.dateStr === today ? cached.count : 0) + 1;
  ipAttemptCache.set(rangeKey, { count: newCount, dateStr: today });

  // Upsert into DB (persist across restarts, visible in incognito, queryable)
  try {
    const { error } = await supabase.from('ip_blocks').upsert(
      {
        ip_range:      rangeKey,
        block_date:    today,
        attempt_count: newCount,
        last_attempt:  new Date().toISOString(),
      },
      { onConflict: 'ip_range,block_date' }
    );
    if (error) console.error('ip_blocks upsert error:', error.message);
    else console.log(`[RATE-LIMIT] ${rangeKey} — attempt ${newCount}/3 on ${today}`);
  } catch (e) {
    console.error('recordFailedAttempt DB error:', e.message);
  }
}

/* ══════════════════════════════════════════════════════════
   GMAIL AUTH
══════════════════════════════════════════════════════════ */
app.get('/auth/login', (req, res) => res.redirect(getAuthUrl()));

app.get('/auth/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Missing code parameter.');
    await saveToken(code);
    await registerWatch();
    res.send('Gmail connected! You can close this tab.');
  } catch (e) {
    console.error('Auth callback error:', e.message);
    res.status(500).send('Authentication failed.');
  }
});

/* ══════════════════════════════════════════════════════════
   GMAIL PUSH — Google calls this when new email arrives
══════════════════════════════════════════════════════════ */
app.post('/gmail/push', async (req, res) => {
  res.sendStatus(200); // ACK Google immediately — must be fast

  try {
    if (!req.body?.message?.data) return;
    console.log('[PUSH] Notification received — fetching new emails');

    const emails = await fetchEmails(10);
    if (!Array.isArray(emails) || !emails.length) return;

    // Validate rows before upserting — never send raw unverified data
    const sanitized = emails.filter(e => e && typeof e === 'object' && e.gmail_id);

    if (!sanitized.length) return;

    const { error } = await supabase
      .from('emails')
      .upsert(sanitized, { onConflict: 'gmail_id', ignoreDuplicates: true });

    if (error) console.error('[PUSH] Supabase error:', JSON.stringify(error));
    else console.log(`[PUSH] Synced ${sanitized.length} email(s)`);
  } catch (e) {
    console.error('[PUSH] Handler error:', e.message);
  }
});

/* ══════════════════════════════════════════════════════════
   RECOVERY EMAIL VALIDITY CHECK
   Called by the frontend before loading an inbox.
   Only returns valid=true if the alias has ≥1 email in DB.
══════════════════════════════════════════════════════════ */
app.post('/api/check-recovery-email', async (req, res) => {
  const ip = getClientIP(req);

  // 1. Check if this IP range is blocked first
  const blockStatus = await checkIPBlocked(ip);
  if (blockStatus.blocked) {
    return res.status(429).json({
      valid:   false,
      blocked: true,
      message: blockStatus.reason,
    });
  }

  // 2. Validate input
  const { email } = req.body || {};
  if (!email || typeof email !== 'string') {
    return res.status(400).json({ valid: false, message: 'Invalid request.' });
  }

  const normalized = email.trim().toLowerCase();

  // Basic email format check — no point hitting DB for garbage input
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    return res.status(400).json({ valid: false, message: 'Invalid email format.' });
  }

  // 3. Query Supabase — email is valid only if it has ≥1 row in the emails table
  try {
    const { count, error } = await supabase
      .from('emails')
      .select('id', { count: 'exact', head: true })
      .eq('alias', normalized);

    if (error) {
      console.error('[CHECK-EMAIL] Supabase error:', error.message);
      return res.status(500).json({ valid: false, message: 'Database error. Try again.' });
    }

    const isValid = typeof count === 'number' && count > 0;

    if (!isValid) {
      // Record the failed attempt — this IP tried a non-existent alias
      await recordFailedAttempt(ip);

      // Re-check block status after recording (might have just hit limit)
      const afterBlock = await checkIPBlocked(ip);
      if (afterBlock.blocked) {
        return res.status(429).json({
          valid:   false,
          blocked: true,
          message: afterBlock.reason,
        });
      }
    }

    return res.json({ valid: isValid });
  } catch (e) {
    console.error('[CHECK-EMAIL] Unexpected error:', e.message);
    return res.status(500).json({ valid: false, message: 'Server error.' });
  }
});

/* ══════════════════════════════════════════════════════════
   GMAIL WATCH RENEWAL — every 6 days (expires at 7)
══════════════════════════════════════════════════════════ */
cron.schedule('0 0 */6 * *', async () => {
  try {
    await registerWatch();
    console.log('[CRON] Gmail watch refreshed');
  } catch (e) {
    console.error('[CRON] Watch refresh error:', e.message);
  }
});

/* ══════════════════════════════════════════════════════════
   START
══════════════════════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  registerWatch().catch(e => console.error('[INIT] Watch error:', e.message));
});
