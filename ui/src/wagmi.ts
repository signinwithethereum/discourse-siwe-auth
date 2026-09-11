import { http, createConfig, type CreateConnectorFn } from '@wagmi/core'
import { mainnet } from 'viem/chains'
import { injected, metaMask, safe, walletConnect } from '@wagmi/vue/connectors'

export interface WagmiOptions {
  walletConnectProjectId?: string
}

const configCache = new Map<string, ReturnType<typeof createConfig>>()

export function createWagmiConfig(options: WagmiOptions) {
  const key = options.walletConnectProjectId ?? ''
  const cached = configCache.get(key)
  if (cached) return cached

  const connectors: CreateConnectorFn[] = [
    injected(),
    safe({ allowedDomains: [/app\.safe\.global$/] }),
    metaMask({
      ui: { headless: true },
      dapp: {
        name: 'Sign in with Ethereum',
        url: window.location.origin,
      },
    }),
  ]

  if (options.walletConnectProjectId) {
    connectors.push(
      walletConnect({
        projectId: options.walletConnectProjectId,
        showQrModal: false,
      }),
    )
  }

  const config = createConfig({
    chains: [mainnet],
    batch: { multicall: true },
    connectors,
    transports: {
      [mainnet.id]: http(),
    },
  })

  configCache.set(key, config)
  return config
}
