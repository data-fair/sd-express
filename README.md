# simple-directory-express

[![Build Status](https://travis-ci.org/koumoul-dev/sd-express.svg?branch=master)](https://travis-ci.org/koumoul-dev/sd-express)
[![Coverage Status](https://coveralls.io/repos/github/koumoul-dev/sd-express/badge.svg?branch=master)](https://coveralls.io/github/koumoul-dev/sd-express?branch=master)

Middleware and router helpers to write expressjs applications that depend on [simple-directory](https://koumoul-dev.github.io/simple-directory/) for authentication.

    npm i @koumoul/sd-express

Initialization:

```
const app = require('express')()
const session = require('simple-directory-client-express')({directoryUrl: 'http://my-simple-directory', publicUrl: 'http://localhost:8080'})

// These routes are authenticated. In your router req.user will be defined with the content of the session.
app.use('/api', session.auth, apiRouter)

// These routes can all be used as callback redirections from authentication (thanks to session.loginCallback)
// Also they will have req.user but without the cost of crypto verification and session prolongation (thanks to session.decode)
app.use('/ui', session.loginCallback, session.decode, uiRouter)
// The router exposes login, logout and ping routes to manage auth and session.
app.use('/session', session.router)
```

**TODO**: Proper documentation of options and functionalities. For now [the code is the doc](https://github.com/koumoul-dev/sd-express/blob/master/index.js).
