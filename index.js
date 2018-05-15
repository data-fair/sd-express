const util = require('util')
const assert = require('assert')
const URL = require('url').URL
const axios = require('axios')
const express = require('express')
const jwt = require('jsonwebtoken')
const jwksRsa = require('jwks-rsa')
const Cookies = require('cookies')
jwt.verifyAsync = util.promisify(jwt.verify)
const debug = require('debug')('session')

module.exports = ({directoryUrl, publicUrl, cookieName}) => {
  assert.ok(!!directoryUrl, 'directoryUrl parameter is required')
  assert.ok(!!publicUrl, 'publicUrl parameter is required')
  cookieName = cookieName || 'id_token'
  debug('Init with parameters', {directoryUrl, publicUrl, cookieName})

  const jwksClient = _getJWKSClient(directoryUrl)
  const auth = _auth(directoryUrl, publicUrl, jwksClient, cookieName)
  const decode = _decode(cookieName)
  const loginCallback = _loginCallback(publicUrl, jwksClient, cookieName)
  const login = _login(directoryUrl, publicUrl)
  const logout = _logout(cookieName)
  const router = express.Router()
  router.get('/login', login)
  router.get('/me', auth, (req, res) => {
    if (!req.user) return res.status(404).send()
    else res.send(req.user)
  })
  router.post('/logout', logout)
  router.post('/keepalive', auth, (req, res) => res.status(204).send())

  return {auth, decode, loginCallback, login, logout, router}
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

// Fetch a session token from cookies if the same site policy is respected
function _getCookieToken (cookies, req, cookieName, publicUrl) {
  let token = cookies.get(cookieName)
  if (!token) return null
  const reqOrigin = req.header('origin')
  if (reqOrigin && reqOrigin !== new URL(publicUrl).origin) {
    debug(`A cookie was sent from origin ${reqOrigin} while public url is ${publicUrl}, ignore it`)
    return null
  }
  return token + '.' + cookies.get(cookieName + '_sign')
}

// Split JWT strategy, the signature is in a httpOnly cookie for XSS prevention
// the header and payload are not httpOnly to be readable by client
// all cookies use sameSite for CSRF prevention
function _setCookieToken (cookies, cookieName, token, payload) {
  const parts = token.split('.')
  const opts = {sameSite: true, expires: new Date(payload.exp * 1000)}
  cookies.set(cookieName, parts[0] + '.' + parts[1], {...opts, httpOnly: false})
  cookies.set(cookieName + '_sign', parts[2], {...opts, httpOnly: true})
}

// Fetch the public info of signing key from the directory that acts as jwks provider
async function _verifyToken (jwksClient, token) {
  const decoded = jwt.decode(token, {complete: true})
  const signingKey = await jwksClient.getSigningKeyAsync(decoded.header.kid)
  return jwt.verifyAsync(token, signingKey.publicKey || signingKey.rsaPublicKey)
}

// This middleware detects that we are coming from an authentication link (probably in an email)
// and creates a new session accordingly
function _loginCallback (publicUrl, jwksClient, cookieName, cookieOpts) {
  return asyncWrap(async (req, res, next) => {
    // Get a JWT in a id_token query parameter = coming from a link in an email
    const linkToken = req.query.id_token
    if (linkToken) {
      try {
        debug(`Verify JWT token from the query parameter`)
        const payload = await _verifyToken(jwksClient, linkToken)
        debug('JWT token from query parameter is ok, store it in cookie', payload)
        _setCookieToken(new Cookies(req, res), cookieName, linkToken, payload)
      } catch (err) {
        // Token expired or bad in another way..
        // TODO: a way to display warning to user ? throw error ?
        debug('JWT token from query parameter is broken', err)
      }
      const reloadUrl = publicUrl + req.path
      debug('Reload current page without query parameter', reloadUrl)
      return res.redirect(reloadUrl)
    }
    next()
  })
}

// This middleware checks if a user has an active session and defines req.user
// Contrary to auth it does not validate the token, only decode it..
// so it faster but it is limited to routes where req.user is informative
function _decode (cookieName) {
  return (req, res, next) => {
    // JWT in a cookie = already active session
    const cookies = new Cookies(req, res)
    let token = cookies.get(cookieName)
    if (token) {
      req.user = jwt.decode(token)
    }
    next()
  }
}

// This middleware checks if a user has an active session with a valid token
// it defines req.user and it can extend the session if necessary.
function _auth (directoryUrl, publicUrl, jwksClient, cookieName) {
  return asyncWrap(async (req, res, next) => {
    // JWT in a cookie = already active session
    const cookies = new Cookies(req, res)
    const token = _getCookieToken(cookies, req, cookieName, publicUrl)
    if (token) {
      try {
        debug(`Verify JWT token from the ${cookieName} cookie`)
        req.user = await _verifyToken(jwksClient, token)
        debug('JWT token from cookie is ok', req.user)
      } catch (err) {
        // Token expired or bad in another way.. delete the cookie
        debug('JWT token from cookie is broken, clear it', err)
        cookies.set(cookieName)
        cookies.set(cookieName + '_sign')
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
      if (tooOld || shortLife) {
        const exchangeRes = await axios.post(directoryUrl + '/api/auth/exchange', null, {headers: {Authorization: 'Bearer ' + token}})
        const exchangedToken = exchangeRes.data
        req.user = await _verifyToken(jwksClient, exchangedToken)
        debug('Exchanged token is ok, store it', req.user)
        _setCookieToken(cookies, cookieName, exchangedToken, req.user)
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
function _logout (cookieName) {
  return (req, res) => {
    const cookies = new Cookies(req, res)
    cookies.set(cookieName)
    cookies.set(cookieName + '_sign')
    res.status(204).send()
  }
}

// small route wrapper for better use of async/await with express
function asyncWrap (route) {
  return (req, res, next) => route(req, res, next).catch(next)
}
