const test = require('ava')

const sdClient = require('./index')

test('required parameters', t => {
  try {
    sdClient({})
    t.fail()
  } catch (err) {
    t.is(err.code, 'ERR_ASSERTION')
  }
})

test('proper exports', t => {
  const cl = sdClient({ directoryUrl: 'http://directory', publicUrl: 'http://my-app' })
  t.truthy(cl.auth)
})

// TODO: well everything basically :)
