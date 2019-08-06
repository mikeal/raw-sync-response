'use strict'
const assert = require('assert')
const { it } = require('mocha')
const rsr = require('../')
const rsl = require('raw-sha-links')
const digest = require('digestif')
const bytes = require('bytesish')

const test = it

test('basic encode/decode', async () => {
  const values = [bytes('v1'), bytes('v2'), bytes('v3')]
  const hashes = await Promise.all(values.map(v => digest(v)))
  const rslHash = await digest(rsl.encode(hashes))
  const block = rsr(rslHash)
  const [, v2] = values
  const [h1, , h3] = hashes
  block.addHash(h1)
  block.addPart(v2)
  block.addHash(h3)
  const buffer = block.encode()
  const resp = rsr.decode(buffer)
  assert.ok(bytes.compare(resp.rslHash, rslHash))
  for (let i = 0; i < resp.results.length; i++) {
    const [isPart, result] = resp.results[i]
    if (isPart) assert.ok(bytes.compare(result, values[i]))
    else assert.ok(bytes.compare(result, hashes[i]))
  }
})
