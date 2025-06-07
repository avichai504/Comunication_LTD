// services/forgotPassword.js

const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');
const { db } = require('../db/db');
const { sendResetEmail } = require('../utils/email');
const {
  WHITELIST,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const viewPath = path.join(__dirname, '../views/forgot-password.html');

async function handleForgotPassword(req, res) {
  const rawHtml = fs.readFileSync(viewPath, 'utf-8');
  const { email } = req.body;

  // Helper to repopulate form and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required field
  if (!email) {
    return res
      .status(400)
      .send(render(
        { email },
        '<p style="color:red;">Email is required.</p>'
      ));
  }

  // B) Whitelist, length & basic email-format validation
  const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  if (
    email.length > 100 ||
    !WHITELIST.test(email) ||
    !EMAIL_REGEX.test(email)
  ) {
    return res
      .status(400)
      .send(render(
        { email },
        '<p style="color:red;">Reset request failed due to invalid input format.</p>'
      ));
  }

  // C) Lookup user (always return success message to prevent enumeration)
  const user = await db.user.findUnique({ where: { email } });
  if (!user) {
    return res
      .send(render(
        { email },
        '<p style="color:green;">If that email exists, a reset code has been sent.</p>'
      ));
  }

  // D) Generate secure random 6‐hex‐digit code (avoids “SHA-1”)
  const code = crypto.randomBytes(3).toString('hex');

  // E) Store and email the code
  await db.user.update({
    where: { email },
    data:  { resetCode: code }
  });
  await sendResetEmail(email, code);

  // F) Success feedback
  return res
    .send(render(
      { email },
      '<p style="color:green;">Reset code sent to your email.</p>'
    ));
}

module.exports = { handleForgotPassword };
