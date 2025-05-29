// services/login.js

const path = require('path');
const fs   = require('fs');
const { db } = require('../db/db');
const { hashPassword } = require('../utils/password');
const { getSecurityConfig } = require('../config/security');
const {
  WHITELIST,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const config        = getSecurityConfig();
const MAX_ATTEMPTS  = config.loginAttemptsLimit;
const LOCK_DURATION = 30 * 60 * 1000; // 30 minutes
const loginAttempts = {};             // in-memory tracking
const viewPath      = path.join(__dirname, '../public/index.html');

async function handleLogin(req, res) {
  const rawHtml = fs.readFileSync(viewPath, 'utf-8');
  const { username, password } = req.body;

  // Helper to repopulate form and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required fields
  if (!username || !password) {
    return res
      .status(400)
      .send(render(
        { username, password: '' },
        '<p style="color:red;">Both username and password are required.</p>'
      ));
  }

  // B) Whitelist & length validation
  if (
    username.length > 30   || !WHITELIST.test(username) ||
    password.length > 50   || !WHITELIST.test(password)
  ) {
    return res
      .status(400)
      .send(render(
        { username, password: '' },
        '<p style="color:red;">Login failed due to invalid input format.</p>'
      ));
  }

  // C) Lookup user
  const user = await db.user.findUnique({ where: { username } });
  if (!user) {
    return res
      .status(400)
      .send(render(
        { username, password: '' },
        '<p style="color:red;">Username or password is incorrect.</p>'
      ));
  }

  // D) Rate limiting
  const now    = Date.now();
  const record = loginAttempts[username] || { count: 0, lastFailed: 0 };
  if (record.count >= MAX_ATTEMPTS && now - record.lastFailed < LOCK_DURATION) {
    return res
      .status(403)
      .send(render(
        { username, password: '' },
        '<p style="color:red;">Your account is temporarily locked due to multiple failed attempts. Try again later.</p>'
      ));
  }

  // E) Verify password
  const [salt, storedHash] = user.password.split(':');
  if (hashPassword(password, salt) !== storedHash) {
    loginAttempts[username] = { count: record.count + 1, lastFailed: now };
    const attemptsLeft = MAX_ATTEMPTS - (record.count + 1);
    return res
      .status(400)
      .send(render(
        { username, password: '' },
        `<p style="color:red;">Username or password is incorrect. ${attemptsLeft} attempt(s) left.</p>`
      ));
  }

  // F) Reset failure count & success redirect
  loginAttempts[username] = { count: 0, lastFailed: 0 };
  return res.redirect('/dashboard');
}

module.exports = { handleLogin };
