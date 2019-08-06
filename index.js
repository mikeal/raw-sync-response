'use strict'
const rsl = require('raw-sha-links')
const varint = require('varint')
const bytes = require('bytesish')

const isHash = new Uint8Array(varint.encode(0))

class Block {
  constructor (rslhash) {
    this.rslhash = bytes.typedArray(rslhash)
    if (rsl.sizeTable[rslhash.byteLength] === undefined) {
      throw new Error('Unsupported hash length')
    }
    this.offsets = []
    this.hashes = []
    this.parts = []
  }

  addHash (hash) {
    hash = bytes.typedArray(hash)
    if (hash.byteLength !== this.rslhash.byteLength) throw new Error('Hash lengths must all match')
    this.hashes.push(hash)
    this.offsets.push(0)
  }

  addPart (part) {
    part = bytes.typedArray(part)
    const length = new Uint8Array(varint.encode(part.byteLength))
    this.parts.push([length, part])
    this.offsets.push(1)
  }

  size () {
    const shaType = 1
    const rslHashLength = this.rslhash.byteLength
    const hashesLength = this.hashes.length * rslHashLength
    const hashSignals = this.hashes.length * isHash.byteLength
    const partsLength = this.parts.reduce((x, y) => x + (y[0].byteLength + y[1].byteLength), 0)
    return shaType + rslHashLength + hashesLength + hashSignals + partsLength
  }

  encode () {
    const block = new Uint8Array(this.size())
    const hashes = this.hashes.slice()
    const parts = this.parts.slice()
    block[0] = rsl.sizeTable[this.rslhash.byteLength]
    block.set(this.rslhash, 1)
    let offset = this.rslhash.byteLength + 1
    for (const _map of this.offsets) {
      /* istanbul ignore else */
      if (_map === 0) {
        block.set(isHash, offset)
        offset += isHash.byteLength
        const hash = hashes.shift()
        block.set(hash, offset)
        offset += hash.byteLength
      } else if (_map === 1) {
        const [length, part] = parts.shift()
        block.set(length, offset)
        offset += length.byteLength
        block.set(part, offset)
        offset += part.byteLength
      } else {
        throw new Error('Invalid map encoding.')
      }
    }
    return block.buffer
  }
}

const decode = data => {
  const view = bytes.typedArray(data)
  const hashLength = rsl.tableSize[view[0]]
  const rslHash = bytes.slice(view, 1, hashLength + 1)
  const results = []
  let offset = hashLength + 1
  while (offset < data.byteLength) {
    const length = varint.decode(view, offset)
    offset += varint.decode.bytes
    if (length === 0) {
      results.push([0, bytes.slice(view, offset, offset + hashLength)])
      offset += hashLength
    } else {
      results.push([1, bytes.slice(view, offset, offset + length)])
      offset += length
    }
  }

  return { rslHash, hashLength, results }
}

module.exports = rslhash => new Block(rslhash)
module.exports.decode = decode
