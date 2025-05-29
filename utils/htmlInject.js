function injectFeedback(html, msg) {
  return html.replace('<div id="feedback"></div>', `<div id="feedback">${msg}</div>`)
}

function injectValues(html, {
  username = '',
  email = '',
  password = '',
  name = '',
  phone = '',
  address = '',
  currentPassword = '',
  newPassword = '',
  code = ''
} = {}) {
  return html
    .replace('name="username"',        `name="username"        value="${escapeHtml(username)}"`)
    .replace('name="email"',           `name="email"           value="${escapeHtml(email)}"`)
    .replace('name="password"',        `name="password"        value="${escapeHtml(password)}"`)
    .replace('name="name"',            `name="name"            value="${escapeHtml(name)}"`)
    .replace('name="phone"',           `name="phone"           value="${escapeHtml(phone)}"`)
    .replace('name="address"',         `name="address"         value="${escapeHtml(address)}"`)
    .replace('name="currentPassword"', `name="currentPassword" value="${escapeHtml(currentPassword)}"`)
    .replace('name="newPassword"',     `name="newPassword"     value="${escapeHtml(newPassword)}"`)
    .replace('name="code"',            `name="code"            value="${escapeHtml(code)}"`);
}

const WHITELIST = /^[A-Za-z0-9 _@.\-]+$/

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

module.exports = { injectFeedback, injectValues, escapeHtml, WHITELIST }
