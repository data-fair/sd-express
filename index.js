const util = require('util')
const assert = require('assert')
const URL = require('url').URL
const axios = require('axios')
const express = require('express')
const jwt = require('jsonwebtoken')
const jwksRsa = require('jwks-rsa')
const Cookies = require('cookies')
const corsBuilder = require('cors')
jwt.verifyAsync = util.promisify(jwt.verify)
const debug = require('debug')('session')

module.exports = ({ directoryUrl, publicUrl, cookieName, cookieDomain, privateDirectoryUrl }) => {
  assert.ok(!!directoryUrl, 'directoryUrl parameter is required')
  assert.ok(!!publicUrl, 'publicUrl parameter is required')
  cookieName = cookieName || 'id_token'
  debug('Init with parameters', { directoryUrl, publicUrl, cookieName })
  privateDirectoryUrl = privateDirectoryUrl || directoryUrl

  const jwksClient = _getJWKSClient(privateDirectoryUrl)
  const auth = _auth(privateDirectoryUrl, publicUrl, jwksClient, cookieName, cookieDomain)
  const requiredAuth = (req, res, next) => {
    auth(req, res, err => {
      if (err) return next(err)
      if (!req.user) return res.status(401).send()
      next()
    })
  }
  const decode = _decode(cookieName, cookieDomain, publicUrl)
  const loginCallback = _loginCallback(privateDirectoryUrl, publicUrl, jwksClient, cookieName, cookieDomain)
  const login = _login(directoryUrl, publicUrl)
  const logout = _logout(cookieName, cookieDomain)
  const cors = _cors(cookieDomain, publicUrl)
  const router = express.Router()
  router.get('/login', login)
  router.get('/me', auth, (req, res) => {
    if (!req.user) return res.status(404).send()
    else res.send(req.user)
  })
  router.post('/logout', logout)
  router.post('/keepalive', _auth(privateDirectoryUrl, publicUrl, jwksClient, cookieName, cookieDomain, true), (req, res) => res.status(204).send(req.user))

  return { auth, requiredAuth, decode, loginCallback, login, logout, cors, router }
}

// A cache of jwks clients, so that this module's main function can be called multiple times
const jwksClients = {}
function _getJWKSClient (directoryUrl) {
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

// Return a function that can build a CORS middleware
function _cors (cookieDomain, publicUrl) {
  return ({ acceptServers, acceptAllOrigins }) => {
    // accept server 2 server requests by default
    acceptServers = acceptServers === undefined ? true : acceptServers
    // do not accept call by outside origins by default
    acceptAllOrigins = acceptAllOrigins === undefined ? false : acceptAllOrigins
    return corsBuilder({
      credentials: true,
      origin (origin, callback) {
        // Case of server to server requests
        if (!origin) {
          if (acceptServers) return callback(null, true)
          return callback(new Error('No CORS allowed for server to server requests'))
        }

        // Case where we accept any domain as origin
        if (acceptAllOrigins) return callback(null, true)

        const originDomain = new URL(origin).host

        // Case of mono-domain acceptance
        if (!cookieDomain) {
          if (originDomain === new URL(publicUrl).host) return callback(null, true)
          return callback(new Error(`No CORS allowed from origin ${origin}`))
        }

        // Case of subdomains acceptance
        if (originDomain === cookieDomain || originDomain.endsWith('.' + cookieDomain)) {
          return callback(null, true)
        }
        callback(new Error(`No CORS allowed from origin ${origin}`))
      }
    })
  }
}

// Fetch a session token from cookies if the same site policy is respected
function _getCookieToken (cookies, req, cookieName, cookieDomain, publicUrl) {
  let token = cookies.get(cookieName)
  if (!token) return null
  const reqOrigin = req.headers['origin']
  const originDomain = reqOrigin && new URL(reqOrigin).host

  // check that the origin of the request is part of the accepted domain
  if (reqOrigin && cookieDomain && originDomain !== cookieDomain && !originDomain.endsWith('.' + cookieDomain)) {
    debug(`A cookie was sent from origin ${reqOrigin} while cookie domain is ${cookieDomain}, ignore it`)
    return null
  }
  // or simply that it is strictly equal to current target if domain is unspecified
  // in this case we are also protected by sameSite
  if (reqOrigin && !cookieDomain && reqOrigin !== new URL(publicUrl).origin) {
    debug(`A cookie was sent from origin ${reqOrigin} while public url is ${publicUrl}, ignore it`)
    return null
  }

  // Putting the signature in a second token is recommended but optional
  // and we accept full JWT in id_token cooke
  const signature = cookies.get(cookieName + '_sign')
  if (signature && (token.match(/\./g) || []).length === 1) {
    token += '.' + signature
  }
  return token
}

// Split JWT strategy, the signature is in a httpOnly cookie for XSS prevention
// the header and payload are not httpOnly to be readable by client
// all cookies use sameSite for CSRF prevention
function _setCookieToken (cookies, cookieName, cookieDomain, token, payload, org) {
  const parts = token.split('.')
  const opts = { sameSite: 'lax', expires: new Date(payload.exp * 1000) }
  if (cookieDomain) {
    opts.domain = cookieDomain
    // to support subdomains we can't use the sameSite opt
    // we rely on our manual check of the origin
    delete opts.sameSite
  }
  cookies.set(cookieName, parts[0] + '.' + parts[1], { ...opts, httpOnly: false })
  cookies.set(cookieName + '_sign', parts[2], { ...opts, httpOnly: true })
  if (org) {
    cookies.set(cookieName + '_org', org, { ...opts, httpOnly: false })
  }
}

// Use complementary cookie id_token_org to set the current active organization of the user
// also set consumerFlag that is used by applications to decide if they should ask confirmation to the user
// of the right quotas or other organization related context to apply
// it is 'user' if id_token_org is an empty string or is equal to 'user'
// it is null if id_token_org is absent or if it does not match an organization of the current user
// it is the id of the orga in id_token_org
function _setOrganization (cookies, cookieName, req, user) {
  if (!user) return
  // The order is important. The header can set explicitly on a query even if the cookie contradicts.
  const organizationId = req.headers['x-organizationid'] || cookies.get(cookieName + '_org')
  if (organizationId) {
    user.organization = (user.organizations || []).find(o => o.id === organizationId)

    if (user.organization) {
      user.consumerFlag = user.organization.id
    } else if (organizationId === '' || organizationId.toLowerCase() === 'user') {
      user.consumerFlag = 'user'
    }
  }
}

// Use complementary cookie id_token_admin to detect that the user is in activated admin mode
function _setAdminMode (cookies, cookieName, req, user) {
  if (!user) return
  user.adminMode = user.isAdmin && (cookies.get(cookieName + '_admin') === 'true')
}

// Fetch the public info of signing key from the directory that acts as jwks provider
async function _verifyToken (jwksClient, token) {
  const decoded = jwt.decode(token, { complete: true })
  const signingKey = await jwksClient.getSigningKeyAsync(decoded.header.kid)
  return jwt.verifyAsync(token, signingKey.publicKey || signingKey.rsaPublicKey)
}

// Exchange a token (because if was a temporary auth token of because it is too old)
async function _exchangeToken (privateDirectoryUrl, token) {
  const exchangeRes = await axios.post(privateDirectoryUrl + '/api/auth/exchange', null, { headers: { Authorization: 'Bearer ' + token } })
  return exchangeRes.data
}

// This middleware detects that we are coming from an authentication link (probably in an email)
// and creates a new session accordingly
function _loginCallback (privateDirectoryUrl, publicUrl, jwksClient, cookieName, cookieDomain) {
  return asyncWrap(async (req, res, next) => {
    // Get a JWT in a id_token query parameter = coming from a link in an email
    const linkToken = req.query.id_token
    if (linkToken) {
      const cookies = new Cookies(req, res)
      try {
        debug(`Verify JWT token from the query parameter`)
        await _verifyToken(jwksClient, linkToken)
        debug('JWT token from query parameter is ok, exchange it for a long term session token')
        const exchangedToken = await _exchangeToken(privateDirectoryUrl, linkToken)
        const payload = await _verifyToken(jwksClient, exchangedToken)
        debug('Exchanged token is ok, store it', payload)
        _setCookieToken(cookies, cookieName, cookieDomain, exchangedToken, payload, req.query.id_token_org)
      } catch (err) {
        // Token expired or bad in another way..
        // TODO: a way to display warning to user ? throw error ?
        debug('JWT token from query parameter is broken', err)
      }
      const reloadUrl = new URL(publicUrl + req.originalUrl)
      reloadUrl.searchParams.delete('id_token')
      debug('Reload current page without id_token query parameter', reloadUrl.toString())
      return res.redirect(reloadUrl.toString())
    }
    next()
  })
}

// This middleware checks if a user has an active session and defines req.user
// Contrary to auth it does not validate the token, only decode it..
// so it faster but it is limited to routes where req.user is informative
function _decode (cookieName, cookieDomain, publicUrl) {
  return (req, res, next) => {
    // JWT in a cookie = already active session
    const cookies = new Cookies(req, res)
    const token = _getCookieToken(cookies, req, cookieName, cookieDomain, publicUrl)
    if (token) {
      req.user = jwt.decode(token)
      _setOrganization(cookies, cookieName, req, req.user)
      _setAdminMode(cookies, cookieName, req, req.user)
    }
    next()
  }
}

// This middleware checks if a user has an active session with a valid token
// it defines req.user and it can extend the session if necessary.
function _auth (privateDirectoryUrl, publicUrl, jwksClient, cookieName, cookieDomain, forceExchange) {
  return asyncWrap(async (req, res, next) => {
    // JWT in a cookie = already active session
    const cookies = new Cookies(req, res)
    const token = _getCookieToken(cookies, req, cookieName, cookieDomain, publicUrl)
    if (token) {
      try {
        debug(`Verify JWT token from the ${cookieName} cookie`)
        req.user = await _verifyToken(jwksClient, token)
        _setOrganization(cookies, cookieName, req, req.user)
        _setAdminMode(cookies, cookieName, req, req.user)
        debug('JWT token from cookie is ok', req.user)
      } catch (err) {
        // Token expired or bad in another way.. delete the cookie
        debug('JWT token from cookie is broken, clear it', err)
        cookies.set(cookieName, null, { domain: cookieDomain })
        cookies.set(cookieName + '_sign', null, { domain: cookieDomain })
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
      // Token is more than 12 hours old or has less than half an hour left
      const tooOld = timestamp > (req.user.iat + 43200)
      const shortLife = timestamp > (req.user.exp - 1800)
      if (tooOld) debug('The token was issued more than 12 hours ago, exchange it for a new one')
      if (shortLife) debug('The token will expire in less than half an hour, exchange it for a new one')
      if (forceExchange) debug('The token was explicitly required to be exchanged (keepalive route), exchange it for a new one')
      if (tooOld || shortLife || forceExchange) {
        const exchangedToken = await _exchangeToken(privateDirectoryUrl, token)
        req.user = await _verifyToken(jwksClient, exchangedToken)
        _setOrganization(cookies, cookieName, req, req.user)
        _setAdminMode(cookies, cookieName, req, req.user)
        debug('Exchanged token is ok, store it', req.user)
        _setCookieToken(cookies, cookieName, cookieDomain, exchangedToken, req.user)
      }
    }
    next()
  })
}

// Login is simply a link to the right page of the directory.
// Going to the directory through a redirect, not throug a link in UI allows us
// to send along some optional client id or any kind of trust enhancing secret
function _login (directoryUrl, publicUrl) {
  return (req, res) => {
    res.redirect(directoryUrl + '/login?redirect=' + encodeURIComponent(req.query.redirect || publicUrl))
  }
}

// Sessions are only the persistence of the JWT token in cookies
// no need to call the directory
function _logout (cookieName, cookieDomain) {
  return (req, res) => {
    const cookies = new Cookies(req, res)
    cookies.set(cookieName, null, { domain: cookieDomain })
    cookies.set(cookieName + '_sign', null, { domain: cookieDomain })
    // case where the cookies were set before assigning domain
    if (cookies.get(cookieName)) {
      cookies.set(cookieName, null)
      cookies.set(cookieName + '_sign', null)
    }
    res.status(204).send()
  }
}

// small route wrapper for better use of async/await with express
function asyncWrap (route) {
  return (req, res, next) => route(req, res, next).catch(next)
}

// Adding a few things for testing purposes
module.exports.maildevAuth = async (email, sdUrl = 'http://localhost:8080', maildevUrl = 'http://localhost:1080') => {
  await axios.post(sdUrl + `/api/auth/passwordless`, { email }, { params: { redirect: sdUrl + `?id_token=` } })
  const emails = (await axios.get(maildevUrl + '/email')).data
  const host = new URL(sdUrl).host
  const emailObj = emails
    .reverse()
    .find(e => e.subject.indexOf(host) !== -1 && e.to[0].address === email)
  if (!emailObj) throw new Error('Failed to find email sent to ' + email)
  const match = emailObj.text.match(/id_token=(.*)\s/)
  if (!match) throw new Error('Failed to extract id_token from mail content')
  return match[1]
}

module.exports.passwordAuth = async (email, password, sdUrl = 'http://localhost:8080') => {
  const res = await axios.post(sdUrl + `/api/auth/password`, { email, password }, { params: { redirect: sdUrl + `?id_token=` }, maxRedirects: 0 })
  const match = res.data.match(/id_token=(.*)/)
  if (!match) throw new Error('Failed to extract id_token from response')
  return match[1]
}

const _axiosInstances = {}
module.exports.axiosAuth = async (email, org, opts = {}, sdUrl = 'http://localhost:8080', maildevUrl = 'http://localhost:1080') => {
  if (_axiosInstances[email]) return _axiosInstances[email]
  let token
  if (email.indexOf(':') !== -1) {
    token = await module.exports.passwordAuth(email.split(':')[0], email.split(':')[1], sdUrl)
  } else {
    token = await module.exports.maildevAuth(email, sdUrl, maildevUrl)
  }
  opts.headers = opts.headers || {}
  opts.headers.Cookie = `id_token=${token}`
  if (org) opts.headers.Cookie += `;id_token_org=${org};id_token_admin=true`
  _axiosInstances[email] = axios.create(opts)
  return _axiosInstances[email]
}
