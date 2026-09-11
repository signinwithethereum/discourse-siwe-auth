import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import test from 'node:test'
import { build } from 'vite'
import viteConfig from '../vite.config.ts'

// Follow the actual SDK dependency chain so this tests the patched installed
// parser, not a separately installed copy or an implementation mock.
let requireDependency = createRequire(import.meta.url)
for (const dependency of [
  '@metamask/connect-evm',
  '@metamask/chain-agnostic-permission',
  '@metamask/controller-utils',
  '@spruceid/siwe-parser',
]) {
  requireDependency = createRequire(requireDependency.resolve(dependency))
}
// Import library entrypoints only; the package root also loads its CLI.
const apgApi = requireDependency('apg-js/src/apg-api/api.js')
const apgLib = requireDependency('apg-js/src/apg-lib/node-exports.js')

test('MetaMask exposes the client factory required by wagmi', async () => {
  const { createEVMClient } = await import('@metamask/connect-evm')
  assert.equal(typeof createEVMClient, 'function')
})

test('parser and AST ignore inherited Ember array callbacks', () => {
  const previous = Object.getOwnPropertyDescriptor(Array.prototype, '_super')
  Object.defineProperty(Array.prototype, '_super', {
    configurable: true,
    enumerable: true,
    value() {},
  })
  try {
    const api = new apgApi('test = %s"ok"\n')
    api.generate()
    assert.deepEqual(api.errors, [])
    const grammar = api.toObject()
    const parser = new apgLib.parser()
    parser.ast = new apgLib.ast()
    parser.ast.callbacks.test = true
    const chars = apgLib.utils.stringToChars('ok')
    assert.equal(parser.parse(grammar, 'test', chars).success, true)
    assert.equal(parser.parse(grammar, 'test', apgLib.utils.stringToChars('bad')).success, false)
    // Unknown own callbacks must still be rejected.
    parser.callbacks.notARule = () => {}
    assert.throws(() => parser.parse(grammar, 'test', chars), /not a rule or udt name/)
    delete parser.callbacks.notARule
    parser.ast.callbacks.notARule = true
    assert.throws(() => parser.parse(grammar, 'test', chars), /not a rule or udt name/)
  } finally {
    if (previous) Object.defineProperty(Array.prototype, '_super', previous)
    else delete Array.prototype._super
  }
})

test('build rejects bundled missing optional peers, but permits tree-shaken ones', () => {
  const plugin = viteConfig.plugins.find(p => p.name === 'require-bundled-peers')
  const context = { error(message) { throw new Error(message) } }
  const bundle = renderedLength => ({
    'siwe.iife.js': {
      type: 'chunk',
      modules: {
        '__vite-optional-peer-dep:@metamask/connect-evm:@wagmi/connectors': { renderedLength },
      },
    },
  })
  assert.throws(() => plugin.generateBundle.call(context, {}, bundle(100)), /Missing wallet dependency/)
  assert.doesNotThrow(() => plugin.generateBundle.call(context, {}, bundle(0)))
})

test('Vite reports a retained missing-peer stub to the build guard', async () => {
  const id = '__vite-optional-peer-dep:test-sdk:test-connector'
  const entry = '/virtual-wallet-fixture.js'
  await assert.rejects(build({
    configFile: false,
    logLevel: 'silent',
    plugins: [
      viteConfig.plugins.find(p => p.name === 'require-bundled-peers'),
      {
        name: 'missing-peer-fixture',
        enforce: 'pre',
        resolveId(source) { if (source === entry || source === id) return source },
        load(source) {
          if (source === entry) return `import '${id}'`
          if (source === id) return 'throw new Error("missing SDK")'
        },
      },
    ],
    build: { write: false, lib: { entry, name: 'Fixture', formats: ['iife'] } },
  }), /Missing wallet dependency/)
})
