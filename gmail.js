const { google } = require('googleapis');
const fs = require('fs');
require('dotenv').config();
const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
let credentialsData;
if (process.env.CREDENTIALS_JSON) {
  credentialsData = JSON.parse(process.env.CREDENTIALS_JSON);
} else { credentialsData = JSON.parse(fs.readFileSync('credentials.json')); }
const { client_id, client_secret } = credentialsData.web;
const redirectUri = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/auth/callback`
  : 'http://localhost:3000/auth/callback';
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirectUri);
 
// Auto-refresh: merges new access tokens silently without losing refresh_token
oAuth2Client.on('tokens', (tokens) => {
  const current = oAuth2Client.credentials;
  oAuth2Client.setCredentials({ ...current, ...tokens });
  console.log('Token auto-refreshed by Google');
});
 
function loadToken() {
  if (process.env.TOKEN_JSON) {
    try {
      const token = JSON.parse(process.env.TOKEN_JSON);
      oAuth2Client.setCredentials(token);
      console.log('Token loaded, refresh_token present:', !!token.refresh_token);
      return true;
    } catch(e) { console.error('TOKEN_JSON parse error:', e.message); }
  }
  console.warn('No token — visit /auth/login');
  return false;
}
loadToken();
 
function getAuthUrl() {
  return oAuth2Client.generateAuthUrl({
    access_type: 'offline', prompt: 'consent', scope: SCOPES
  });
}
 
async function saveToken(code) {
  const { tokens } = await oAuth2Client.getToken(code);
  oAuth2Client.setCredentials(tokens);
  console.log('===== COPY THIS TO RAILWAY AS TOKEN_JSON =====');
  console.log(JSON.stringify(tokens));
  console.log('==============================================');
}
 
function normalizeGmail(address) {
  const [user, domain] = address.toLowerCase().split('@');
  return user.replace(/\./g, '') + '@' + domain;
}
 
async function fetchEmails(maxResults = 10) {
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const base = process.env.GMAIL_BASE + '@' + process.env.GMAIL_DOMAIN;
  const normalizedBase = normalizeGmail(base);
  console.log(`Fetching emails for base: ${normalizedBase}`);
  const list = await gmail.users.messages.list({ userId: 'me', maxResults });
  if (!list.data.messages) return [];
  const emails = [];
  for (const msg of list.data.messages) {
    const detail = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' });
    const headers = detail.data.payload.headers;
    const getHeader = n => headers.find(h => h.name.toLowerCase() === n)?.value || '';
    const toField = getHeader('to');
    if (normalizeGmail(toField) !== normalizedBase) continue;
    const from = getHeader('from');
    const subject = getHeader('subject');
    const date = getHeader('date');
    let body = '';
    const payload = detail.data.payload;
    if (payload.body?.data) body = Buffer.from(payload.body.data, 'base64').toString('utf8');
    const parts = payload.parts || [];
    const htmlPart = parts.find(p => p.mimeType === 'text/html');
    const textPart = parts.find(p => p.mimeType === 'text/plain');
    const preferred = htmlPart || textPart;
    if (preferred?.body?.data) body = Buffer.from(preferred.body.data, 'base64').toString('utf8');
    if (!body) {
      for (const part of parts) {
        if (part.parts) {
          const n = part.parts.find(p => p.mimeType === 'text/html')
                 || part.parts.find(p => p.mimeType === 'text/plain');
          if (n?.body?.data) { body = Buffer.from(n.body.data, 'base64').toString('utf8'); break; }
        }
      }
    }
    const m = from.match(/^(.*?)<(.+?)>$/);
    const senderName = m ? m[1].trim() : from;
    const senderEmail = m ? m[2].trim() : from;
    const aliasMatch = toField.match(/[\w.]+@[\w.]+/);
    const alias = aliasMatch ? aliasMatch[0].toLowerCase() : toField.toLowerCase();
    emails.push({ gmail_id: msg.id, alias, sender: senderName,
      sender_email: senderEmail, subject, body,
      received_at: new Date(date).toISOString() });
  }
  return emails;
}
 
async function registerWatch() {
  const projectId = process.env.GOOGLE_PROJECT_ID || 'maildot';
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  try {
    const res = await gmail.users.watch({
      userId: 'me',
      requestBody: { labelIds: ['INBOX'],
        topicName: `projects/${projectId}/topics/gmail-push` }
    });
    console.log('Gmail watch registered, expires:',
      new Date(parseInt(res.data.expiration)).toISOString());
  } catch(e) { console.error('registerWatch failed (non-fatal):', e.message); }
}
 
module.exports = { getAuthUrl, saveToken, fetchEmails, registerWatch };
