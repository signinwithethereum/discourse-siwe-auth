import { http, createConfig, type CreateConnectorFn } from '@wagmi/core'
import { mainnet } from 'viem/chains'
import { injected, metaMask, safe, walletConnect } from '@wagmi/connectors'

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
    safe(),
    metaMask({
      headless: true,
      dappMetadata: { name: 'Sign-in with Ethereum', iconUrl: '', url: '' },
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
