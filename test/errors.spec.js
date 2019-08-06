'use strict'
const assert = require('assert')
const tsame = require('tsame')
const { it } = require('mocha')
const rsr = require('../')
const rsl = require('raw-sha-links')
const digest = require('digestif')
const bytes = require('bytesish')

const test = it

const same = (x, y) => assert.ok(tsame(x, y))

test('invalid input', async () => {
  const values = [bytes('v1'), bytes('v2'), bytes('v3')]
  const hashes = await Promise.all(values.map(v => digest(v)))
  const rslHash = await digest(rsl.encode(hashes))

  try {
    rsr(bytes.typedArray('as'))
    throw new Error('Failed to throw')
  } catch (e) {
    same(e.message, 'Unsupported hash length')
  }

  const block = rsr(rslHash)
  try {
    block.addHash(bytes.typedArray('as'))
  } catch (e) {
    same(e.message, 'Hash lengths must all match')
  }
})
