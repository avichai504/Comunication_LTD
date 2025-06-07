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

  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  if (!username || !email || !password) {
    return res
      .status(400)
      .send(render(
        { username, email, password },
        '<p style="color:red;">All fields are required.</p>'
      ));
  }

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

  try {
    const checkQuery = `SELECT * FROM "User" WHERE "username" = '${username}' OR "email" = '${email}'`;
    //console.log('Uniqueness check query:', checkQuery);
    const existingUsers = await db.$queryRawUnsafe(checkQuery);
    
    if (existingUsers.length > 0) {
      return res
        .status(400)
        .send(render(
          { username, email, password: '' },
          '<p style="color:red;">Username or email already exists.</p>'
        ));
    }

    const insertQuery = `INSERT INTO "User" ("username", "email", "password") VALUES ('${username}', '${email}', '${password}')`;
    console.log('Insert query:', insertQuery);
    await db.$executeRawUnsafe(insertQuery);

    return res
      .send(render(
        { username: '', email: '', password: '' },
        '<p style="color:green;">Registration successful!</p>'
      ));

  } catch (error) {
    console.error('Registration error:', error);
    return res
      .status(500)
      .send(render(
        { username, email, password: '' },
        '<p style="color:red;">Registration failed due to server error.</p>'
      ));
  }
}

module.exports = { handleRegister };