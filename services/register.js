// services/register.js

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { db } = require('../db/db');
const { validatePassword, hashPassword } = require('../utils/password');
const {
  WHITELIST,
  escapeHtml,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const viewPath = path.join(__dirname, '../views/register.html');

async function handleRegister(req, res) {
  const rawHtml = fs.readFileSync(viewPath, 'utf-8');
  const { username, email, password } = req.body;

  // Helper to repopulate form and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required fields
  if (!username || !email || !password) {
    return res
      .status(400)
      .send(render(
        { username, email, password },
        '<p style="color:red;">All fields are required.</p>'
      ));
  }

  // B) Whitelist, length & basic email-format validation
  const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  if (
    username.length > 30   || !WHITELIST.test(username) ||
    email.length > 50      || !WHITELIST.test(email)    || !EMAIL_REGEX.test(email) ||
    password.length > 50   || !WHITELIST.test(password)
  ) {
    return res
      .status(400)
      .send(render(
        { username, email, password: '' },
        '<p style="color:red;">Registration failed due to invalid input format.</p>'
      ));
  }

  // C) Password policy
  const errors = validatePassword(password);
  if (errors.length > 0) {
    const list = `<ul style="color:red;">${
      errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')
    }</ul>`;
    return res
      .status(400)
      .send(render(
        { username, email, password: '' },
        list
      ));
  }

  // D) Uniqueness check
  const exists = await db.user.findFirst({
    where: { OR: [{ username }, { email }] }
  });
  if (exists) {
    return res
      .status(400)
      .send(render(
        { username, email, password: '' },
        '<p style="color:red;">Username or email already exists.</p>'
      ));
  }

  // E) Create user (salt + HMAC-SHA256)
  const salt = crypto.randomBytes(16).toString('hex');
  const hashed = hashPassword(password, salt);
  const saltedHash = `${salt}:${hashed}`;

  await db.user.create({
    data: { username, email, password: saltedHash }
  });

  // F) Success feedback
  return res
    .send(render(
      { username: '', email: '', password: '' },
      '<p style="color:green;">Registration successful!</p>'
    ));
}

module.exports = { handleRegister };
