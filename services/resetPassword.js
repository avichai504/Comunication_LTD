// services/resetPassword.js

const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');
const { db } = require('../db/db');
const { validatePassword, hashPassword } = require('../utils/password');
const {
  WHITELIST,
  escapeHtml,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const viewPath = path.join(__dirname, '../views/forgot-password.html');

async function handleResetPassword(req, res) {
  const rawHtml    = fs.readFileSync(viewPath, 'utf-8');
  const { email, code, newPassword } = req.body;

  // Helper to repopulate fields and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required fields
  if (!email || !code || !newPassword) {
    return res
      .status(400)
      .send(render(
        { email, code, newPassword },
        '<p style="color:red;">All fields are required.</p>'
      ));
  }

  // B) Whitelist, length & format validation
  const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  const CODE_REGEX  = /^[0-9a-fA-F]{6}$/;  // 6 hex digits
  if (
    email.length > 100     || !WHITELIST.test(email)    || !EMAIL_REGEX.test(email) ||
    code.length !== 6       || !CODE_REGEX.test(code)   ||
    newPassword.length > 50 || !WHITELIST.test(newPassword)
  ) {
    return res
      .status(400)
      .send(render(
        { email, code: '', newPassword: '' },
        '<p style="color:red;">Reset failed due to invalid input format.</p>'
      ));
  }

  // C) Lookup user
  const user = await db.user.findUnique({ where: { email } });
  if (!user) {
    return res
      .status(400)
      .send(render(
        { email, code: '', newPassword: '' },
        '<p style="color:red;">Invalid email or code.</p>'
      ));
  }

  // D) Verify reset code
  if (user.resetCode !== code) {
    return res
      .status(400)
      .send(render(
        { email, code: '', newPassword: '' },
        '<p style="color:red;">Invalid reset code.</p>'
      ));
  }

  // E) Validate new password policy
  const errors = validatePassword(newPassword);
  if (errors.length > 0) {
    const list = `<ul style="color:red;">${
      errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')
    }</ul>`;
    return res
      .status(400)
      .send(render(
        { email, code: '', newPassword: '' },
        list
      ));
  }

  // F) Hash new password, clear resetCode
  const salt       = crypto.randomBytes(16).toString('hex');
  const hashed     = hashPassword(newPassword, salt);
  const saltedHash = `${salt}:${hashed}`;

  await db.user.update({
    where: { email },
    data:  { password: saltedHash, resetCode: null }
  });

  // G) Success feedback
  return res
    .send(render(
      { email: '', code: '', newPassword: '' },
      '<p style="color:green;">Password reset successful.</p>'
    ));
}

module.exports = { handleResetPassword };
