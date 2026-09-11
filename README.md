# Sign in with Ethereum for Discourse

A Discourse plugin that lets users authenticate with their Ethereum wallet using
the [Sign in with Ethereum (SIWE)](https://login.xyz) standard. Injected wallets
(MetaMask, Safe, etc.) work out of the box. ENS names and avatars are resolved
server-side when an RPC endpoint is configured.

## Requirements

- A Discourse forum that is self-hosted or hosted with a provider that supports
  third-party plugins, like [Communiteq](https://www.communiteq.com/).

## Installation

Access your container's `app.yml` file:

```bash
cd /var/discourse
nano containers/app.yml
```

Add the plugin's repository URL to the `after_code` hook:

```yml
hooks:
  after_code:
    - exec:
        cd: $home/plugins
        cmd:
          - sudo -E -u discourse git clone https://github.com/discourse/docker_manager.git
          - sudo -E -u discourse git clone https://github.com/signinwithethereum/discourse-siwe-auth.git # <-- added
```

Rebuild the container:

```bash
cd /var/discourse
./launcher rebuild app
```

## Configuration

After installation, find the plugin under **Admin > Plugins** and make sure it
is enabled:

![Installed plugins](/installed-plugins.png 'Installed plugins')

Click **Settings** to configure the plugin:

![Plugin settings](/settings.png 'Plugin settings')

From here you can customize the sign-in statement and optionally add a
WalletConnect / Reown project ID. Without a project ID, only injected wallets
(MetaMask, Safe, etc.) are available.

### Settings

| Setting                    | Description                                                                                                                                                                                                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Discourse siwe enabled** | Enable or disable Sign in with Ethereum authentication.                                                                                                                                                                                                                     |
| **Siwe ethereum rpc url**  | _Optional._ An Ethereum JSON-RPC endpoint used for ENS name/avatar resolution and EIP-1271 signature verification (required for smart contract wallets like SAFE). A dedicated provider (Alchemy, Infura) is recommended. Example: `https://mainnet.infura.io/v3/YOUR_KEY`. |
| **Siwe project ID**        | _Optional._ A WalletConnect / Reown project ID. Without it, only injected wallets (MetaMask, Safe, etc.) are available. To enable WalletConnect, create a free project ID at [dashboard.reown.com](https://dashboard.reown.com).                                            |
| **Siwe statement**         | The human-readable statement shown in the SIWE message. Defaults to "Sign in with Ethereum".                                                                                                                                                                                |

## Tests

The plugin includes unit tests for ENS resolution and SIWE signature
verification, plus an ENS integration test.

### Frontend dependencies and bundle

The widget uses the Vue packages from Layers (`components`, `components.evm`,
and `styles`), with wallet dependencies aligned to `layers.evm` 4.0.3. Discourse
is not a Nuxt app, so the Nuxt layer itself is not installed. Wallet selection
and connection stay in the shared `EvmConnect` component; the local adapter
supplies Discourse's message endpoint and authentication callback.

Use Node.js 24 and pnpm to install the pinned dependencies, apply the Discourse
compatibility patch, run regression tests, and rebuild the checked-in bundle:

```bash
cd ui
pnpm install --frozen-lockfile
pnpm test
pnpm build
```

The build rejects missing optional wallet SDK dependencies. The parser patch
and its rationale are documented in `ui/patches/README.md`.

### Unit tests (no network needed)

```bash
ruby test/ens_unit_test.rb
ruby test/siwe_unit_test.rb
```

### Integration tests (require an Ethereum RPC endpoint)

```bash
ruby test/ens_integration_test.rb
```

By default, integration tests use a public RPC. Set `RPC_URL` for a dedicated
provider:

```bash
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY ruby test/ens_integration_test.rb
```

### Run all tests

```bash
for f in test/*_test.rb; do ruby "$f"; done
```

## How it works

When a user clicks the Ethereum login button, the plugin opens a dedicated
authentication. The user connects their wallet, signs a SIWE message,
and is authenticated via an OmniAuth strategy on the server side.

After first sign-in, users are asked to associate an email address with their
account. If an RPC URL is configured and the connected address has an ENS name,
the name is resolved and verified server-side and suggested as the default
username. ENS avatars are fetched via the ENS metadata service and used as the
profile photo.

Alternatively, existing users can connect their Ethereum accounts via
their profile settings.
