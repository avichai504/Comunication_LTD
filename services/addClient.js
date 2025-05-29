// services/addClient.js

const path = require('path');
const fs   = require('fs');
const { db } = require('../db/db');
const {
  WHITELIST,
  escapeHtml,
  injectValues,
  injectFeedback
} = require('../utils/htmlInject');

const viewPath = path.join(__dirname, '../views/dashboard.html');

async function handleAddClient(req, res) {
  const rawHtml = fs.readFileSync(viewPath, 'utf-8');
  const { name, email, phone, address } = req.body;

  // Helper to repopulate form and inject feedback
  function render(values, msgHtml) {
    const filled = injectValues(rawHtml, values);
    return injectFeedback(filled, msgHtml);
  }

  // A) Required fields
  if (!name || !email) {
    return res
      .status(400)
      .send(render(
        { name, email, phone, address },
        '<p style="color:red;">Name and email are required.</p>'
      ));
  }

  // B) Whitelist & length validation
  const EMAIL_REGEX = /^[^@\s]+@[^@\s]+$/;
  if (
    name.length > 50       || !WHITELIST.test(name) ||
    email.length > 100     || !WHITELIST.test(email) || !EMAIL_REGEX.test(email) ||
    (phone   && (phone.length > 20  || !WHITELIST.test(phone))) ||
    (address && (address.length > 100 || !WHITELIST.test(address)))
  ) {
    return res
      .status(400)
      .send(render(
        { name, email, phone, address },
        '<p style="color:red;">Add client failed due to invalid input format.</p>'
      ));
  }

  // C) Duplicate email check
  const existing = await db.client.findUnique({ where: { email } });
  if (existing) {
    return res
      .status(400)
      .send(render(
        { name, email, phone, address },
        '<p style="color:red;">That email is already in use.</p>'
      ));
  }

  // D) Create client
  await db.client.create({ data: { name, email, phone, address } });

  // E) Success message (escape once up-front)
  const safeName = escapeHtml(name);
  return res
    .send(render(
      { name: '', email: '', phone: '', address: '' },
      `<p style="color:green;">Client "${safeName}" added successfully!</p>`
    ));
}

module.exports = { handleAddClient };