import { createApp, h } from 'vue'
import { VueQueryPlugin } from '@tanstack/vue-query'
import { WagmiPlugin } from '@wagmi/vue'
import globalStyles from '@1001-digital/styles?inline'
import {
  Globals,
  EvmConfigKey,
  defaultIconAliases,
  IconAliasesKey,
} from '@1001-digital/components'
import SiweAuth from './SiweAuth.vue'
import { createWagmiConfig } from './wagmi'
import { createShadowRoot, injectStyles, captureDevStyles, getHostCSSOverrides } from './shadow'

// In production, the cssToShadow Vite plugin prepends extracted component
// CSS as `var __siwe_css__` to the IIFE bundle. We reference it here.
declare var __siwe_css__: string | undefined

export interface SiweOptions {
  csrfToken: string
  callbackUrl: string
  messageUrl: string
  walletConnectProjectId?: string
  statement?: string
}

export function mountSiwe(el: string | HTMLElement, options: SiweOptions) {
  const element = typeof el === 'string' ? document.querySelector(el) : el
  if (!element) throw new Error(`Element not found: ${el}`)

  // Shadow DOM encapsulation
  const { shadow, root, teleportTarget } = createShadowRoot(element)

  // Inject base styles + Discourse theme overrides + component CSS
  const hostOverrides = getHostCSSOverrides()
  const allStyles = [
    globalStyles,
    hostOverrides,
    ':host { color-scheme: inherit; }',
    typeof __siwe_css__ !== 'undefined' ? __siwe_css__ : '',
  ].join('\n')
  injectStyles(shadow, allStyles)

  // In dev mode, capture Vite-injected SFC styles into shadow root
  let stopCapture: (() => void) | undefined
  if (import.meta.env.DEV) {
    stopCapture = captureDevStyles(shadow)
  }

  const wagmiConfig = createWagmiConfig({
    walletConnectProjectId: options.walletConnectProjectId,
  })

  const app = createApp({
    setup() {
      return () => [
        h(Globals),
        h(SiweAuth, {
          messageUrl: options.messageUrl,
          csrfToken: options.csrfToken,
        }),
      ]
    },
  })

  app.use(VueQueryPlugin)
  app.use(WagmiPlugin, { config: wagmiConfig })

  app.provide(EvmConfigKey, {
    title: 'Sign-in with Ethereum',
    defaultChain: 'mainnet',
    chains: { mainnet: { id: 1, blockExplorer: 'https://etherscan.io' } },
    walletConnectProjectId: options.walletConnectProjectId,
  })
  app.provide(IconAliasesKey, defaultIconAliases)

  // Provide shadow teleport target so Dialog renders inside shadow root
  app.provide('teleport-target', teleportTarget)

  app.mount(root)

  return {
    unmount: () => {
      stopCapture?.()
      app.unmount()
    },
  }
}

// Expose globally for Discourse's loadScript() usage
;(window as any).mountSiwe = mountSiwe
