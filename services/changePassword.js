// services/changePassword.js

const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');
const { db } = require('../db/db');
const { validatePassword, hashPassword } = require('../utils/password');
const { getSecurityConfig } = require('../config/security');
const {
  WHITELIST,
  escapeHtml,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const viewPath = path.join(__dirname, '../views/change-password.html');

async function handleChangePassword(req, res) {
  const rawHtml = fs.readFileSync(viewPath, 'utf-8');
  const { email, currentPassword, newPassword } = req.body;

  // Helper to repopulate form and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required fields
  if (!email || !currentPassword || !newPassword) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword, newPassword },
        '<p style="color:red;">All fields are required.</p>'
      ));
  }

  // B) Whitelist & length validation
  if (
    email.length > 100           || !WHITELIST.test(email) ||
    currentPassword.length > 50  || !WHITELIST.test(currentPassword) ||
    newPassword.length > 50      || !WHITELIST.test(newPassword)
  ) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        '<p style="color:red;">Change password failed due to invalid input format.</p>'
      ));
  }

  // C) Lookup user
  const user = await db.user.findUnique({ where: { email } });
  if (!user) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        '<p style="color:red;">User not found.</p>'
      ));
  }

  // D) Verify current password
  const [salt, storedHash] = user.password.split(':');
  if (!salt || !storedHash) {
    return res
      .status(500)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        '<p style="color:red;">Stored password format is invalid.</p>'
      ));
  }
  if (hashPassword(currentPassword, salt) !== storedHash) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        '<p style="color:red;">Current password is incorrect.</p>'
      ));
  }

  // E) Validate new password strength
  const errors = validatePassword(newPassword);
  if (errors.length > 0) {
    const list = `<ul style="color:red;">${errors
      .map(e => `<li>${escapeHtml(e)}</li>`)
      .join('')}</ul>`;
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        list
      ));
  }

  // F) Check password history reuse
  const config = getSecurityConfig();
  const limit = config.historyLimit || 3;
  const reused = (user.passwordHistory || []).some(old => {
    const [oldSalt] = old.split(':');
    return old === `${oldSalt}:${hashPassword(newPassword, oldSalt)}`;
  });
  if (reused) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        `<p style="color:red;">You cannot reuse your last ${limit} password(s).</p>`
      ));
  }

  // Prevent reusing current password
  if (`${salt}:${hashPassword(newPassword, salt)}` === user.password) {
    return res
      .status(400)
      .send(render(
        { email, currentPassword: '', newPassword: '' },
        '<p style="color:red;">You cannot use your current password.</p>'
      ));
  }

  // G) Hash new password & update history
  const newSalt = crypto.randomBytes(16).toString('hex');
  const newHash = hashPassword(newPassword, newSalt);
  const saltedHash = `${newSalt}:${newHash}`;
  const newHistory = [user.password, ...(user.passwordHistory || [])]
    .slice(0, limit);

  await db.user.update({
    where: { email },
    data: { password: saltedHash, passwordHistory: newHistory }
  });

  // H) Success feedback
  return res
    .send(render(
      { email: '', currentPassword: '', newPassword: '' },
      '<p style="color:green;">Password updated successfully.</p>'
    ));
}

module.exports = { handleChangePassword };
