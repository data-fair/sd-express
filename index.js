const util = require('util')
const assert = require('assert')
const URL = require('url').URL
const axios = require('axios')
const jwt = require('jsonwebtoken')
const jwksRsa = require('jwks-rsa')
const Cookies = require('cookies')
jwt.verifyAsync = util.promisify(jwt.verify)
const debug = require('debug')('session')

module.exports = ({ directoryUrl, privateDirectoryUrl, publicUrl, cookieName, cookieDomain, sameSite }) => {
  assert.ok(!!directoryUrl, 'directoryUrl parameter is required')
  assert.ok(!publicUrl, 'publicUrl parameter is deprecated')
  assert.ok(!cookieDomain, 'cookieDomain parameter is deprecated')
  assert.ok(!sameSite, 'sameSite parameter is deprecated')
  cookieName = cookieName || 'id_token'
  debug('Init with parameters', { directoryUrl, cookieName })
  privateDirectoryUrl = privateDirectoryUrl || directoryUrl

  const jwksClient = getJWKSClient(privateDirectoryUrl)

  // This middleware checks if a user has an active session with a valid token
  // it defines req.user and it can extend the session if necessary.
  const auth = asyncWrap(async (req, res, next) => {
    // JWT in a cookie = already active session
    const cookies = new Cookies(req, res)
    const token = getCookieToken(cookies, req, cookieName)
    if (token) {
      try {
        debug(`Verify JWT token from the ${cookieName} cookie`)
        req.user = await verifyToken(jwksClient, token)
        if (req.user.temporary) throw new Error('Temporary tokens should not be used in actual auth cookies')
        readOrganization(cookies, cookieName, req, req.user)
        debug('JWT token from cookie is ok', req.user)
      } catch (err) {
        // Token expired or bad in another way.. delete the cookie
        debug('JWT token from cookie is broken, clear it', err)
        cookies.set(cookieName, null)
        cookies.set(cookieName + '_sign', null)
        // case where the cookies were set before assigning domain
        if (cookies.get(cookieName)) {
          cookies.set(cookieName, null)
          cookies.set(cookieName + '_sign', null)
        }
      }
    }

    // We have a token from cookie
    // Does it need to be exchanged to prolongate the session ?
    if (req.user && req.user.exp) {
      debug('JWT token from cookie is set to expire on', new Date(req.user.exp * 1000))
      const timestamp = Date.now() / 1000
      const tooOld = timestamp > (req.user.iat + ((req.user.exp - req.user.iat) / 2))
      if (tooOld) {
        debug('The token has lived more than half its lifetime, renew it')
        // TODO: transmit set-cookie ?
        // const exchangedToken = await exchangeToken(privateDirectoryUrl, token)
      }
    }
    next()
  })

  const requiredAuth = (req, res, next) => {
    auth(req, res, err => {
      if (err) return next(err)
      if (!req.user) return res.status(401).send()
      next()
    })
  }

  return { auth, requiredAuth, verifyToken: (token) => verifyToken(jwksClient, token) }
}

// A cache of jwks clients, so that this module's main function can be called multiple times
const jwksClients = {}
function getJWKSClient (directoryUrl) {
  if (jwksClients[directoryUrl]) return jwksClients[directoryUrl]
  jwksClients[directoryUrl] = jwksRsa({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: directoryUrl + '/.well-known/jwks.json'
  })
  jwksClients[directoryUrl].getSigningKeyAsync = util.promisify(jwksClients[directoryUrl].getSigningKey)
  return jwksClients[directoryUrl]
}

// Fetch a session token from cookies if the same site policy is respected
function getCookieToken (cookies, req, cookieName) {
  let token = cookies.get(cookieName)
  if (!token) return null
  const signature = cookies.get(cookieName + '_sign')
  token += '.' + signature
  return token
}

// Fetch the public info of signing key from the directory that acts as jwks provider
async function verifyToken (jwksClient, token) {
  const decoded = jwt.decode(token, { complete: true })
  const signingKey = await jwksClient.getSigningKeyAsync(decoded.header.kid)
  return jwt.verifyAsync(token, signingKey.publicKey || signingKey.rsaPublicKey)
}

// Use complementary cookie id_token_org to set the current active organization of the user
// also set consumerFlag that is used by applications to decide if they should ask confirmation to the user
// of the right quotas or other organization related context to apply
// it is 'user' if id_token_org is an empty string or is equal to 'user'
// it is null if id_token_org is absent or if it does not match an organization of the current user
// it is the id of the orga in id_token_org
function readOrganization (cookies, cookieName, req, user) {
  if (!user) return
  // The order is important. The header can set explicitly on a query even if the cookie contradicts.
  const organizationId = req.headers['x-organizationid'] || cookies.get(cookieName + '_org')
  user.activeAccount = { type: 'user', id: user.id, name: user.name }
  if (organizationId) {
    user.organization = (user.organizations || []).find(o => o.id === organizationId)

    if (user.organization) {
      user.consumerFlag = user.organization.id
      user.activeAccount = { ...user.organization, type: 'organization' }
    } else if (organizationId === '' || organizationId.toLowerCase() === 'user') {
      user.consumerFlag = 'user'
    }
  }
}

// Exchange a token (because if was a temporary auth token of because it is too old)
/* async function _exchangeToken (privateDirectoryUrl, token, params) {
  const exchangeRes = await axios.post(privateDirectoryUrl + '/api/auth/exchange', null, { headers: { Authorization: 'Bearer ' + token }, params })
  return exchangeRes.data
} */

// small route wrapper for better use of async/await with express
function asyncWrap (route) {
  return (req, res, next) => route(req, res, next).catch(next)
}

// Adding a few things for testing purposes
module.exports.maildevAuth = async (email, sdUrl = 'http://localhost:8080', maildevUrl = 'http://localhost:1080', org) => {
  await axios.post(sdUrl + `/api/auth/passwordless`, { email }, { params: { redirect: sdUrl + `?id_token=`, org } })
  const emails = (await axios.get(maildevUrl + '/email')).data
  const host = new URL(sdUrl).host
  const emailObj = emails
    .reverse()
    .find(e => e.subject.indexOf(host) !== -1 && e.to[0].address.toLowerCase() === email.toLowerCase())
  if (!emailObj) throw new Error('Failed to find email sent to ' + email)
  const match = emailObj.text.split('\n').find(l => l.startsWith(sdUrl))
  if (!match) throw new Error('Failed to extract id_token from mail content')
  return match
}

module.exports.passwordAuth = async (email, password, sdUrl = 'http://localhost:8080', adminMode = false, org) => {
  const res = await axios.post(sdUrl + `/api/auth/password`, { email, password, adminMode, org }, { params: { redirect: sdUrl + `?id_token=` }, maxRedirects: 0 })
  return res.data
}

const _axiosInstances = {}
module.exports.axiosAuth = async (email, org, opts = {}, sdUrl = 'http://localhost:8080', maildevUrl = 'http://localhost:1080') => {
  if (!email) {
    _axiosInstances.anonymous = axios.create(opts)
    return _axiosInstances.anonymous
  }
  if (_axiosInstances[email]) return _axiosInstances[email]
  let callbackUrl
  if (email.indexOf(':') !== -1) {
    callbackUrl = await module.exports.passwordAuth(email.split(':')[0], email.split(':')[1], sdUrl, email.split(':').includes('adminMode'), org)
  } else {
    callbackUrl = await module.exports.maildevAuth(email, sdUrl, maildevUrl, org)
  }
  if (callbackUrl.startsWith('http://localhost:8080/simple-directory')) {
    callbackUrl = callbackUrl.replace('http://localhost:8080/simple-directory', 'http://localhost:8080')
  }
  try {
    await axios.get(callbackUrl, { maxRedirects: 0 })
  } catch (err) {
    if (!err.response || err.response.status !== 302) throw err
    opts.headers = opts.headers || {}
    opts.headers.Cookie = err.response.headers['set-cookie'].map(s => s.split(';')[0]).join(';')
  }

  _axiosInstances[email] = axios.create(opts)
  return _axiosInstances[email]
}
