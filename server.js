const express = require('express');
const cron = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');
require('dotenv').config();
const app = express();
app.use(express.json());
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
 
app.get('/auth/login', (req, res) => res.redirect(getAuthUrl()));
app.get('/auth/callback', async (req, res) => {
  await saveToken(req.query.code);
  await registerWatch();
  res.send('Gmail connected! You can close this tab.');
});
 
// Instant push endpoint — Google calls this when email arrives
app.post('/gmail/push', async (req, res) => {
  res.sendStatus(200); // Acknowledge immediately
  try {
    if (!req.body?.message?.data) return;
    console.log('Gmail push received — fetching new emails immediately');
    const emails = await fetchEmails(10);
    if (!emails.length) return;
    const { error } = await supabase.from('emails')
      .upsert(emails, { onConflict: 'gmail_id', ignoreDuplicates: true });
    if (error) console.error('Supabase error:', JSON.stringify(error));
    else console.log(`[PUSH] Synced ${emails.length} email(s)`);
  } catch(e) { console.error('Push handler error:', e.message); }
});
 
// POLLING IS DISABLED — push notifications handle real-time delivery
// Enabling polling alongside push will exhaust Gmail API quota instantly
 
// Re-register Gmail watch every 6 days (it expires after 7 days)
cron.schedule('0 0 */6 * *', async () => {
  try { await registerWatch(); console.log('Gmail watch refreshed'); }
  catch(e) { console.error('Watch refresh error:', e.message); }
});
 
app.listen(process.env.PORT, () => {
  console.log(`Poller running on port ${process.env.PORT}`);
  registerWatch().catch(e => console.error('Initial watch error:', e.message));
});
