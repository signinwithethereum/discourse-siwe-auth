# Sign-In with Ethereum for Discourse

A Discourse plugin that lets users authenticate with their Ethereum wallet using
the [Sign-In with Ethereum (SIWE)](https://login.xyz) standard. Injected wallets
(MetaMask, Safe, etc.) work out of the box. ENS names and avatars are resolved
automatically.

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

Follow the existing format of the `docker_manager.git` line; if it does not
contain `sudo -E -u discourse` then use
`git clone https://github.com/signinwithethereum/discourse-siwe-auth.git` instead.

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

### Settings

| Setting | Description |
| --- | --- |
| **Discourse siwe enabled** | Enable or disable Sign-In with Ethereum authentication. |
| **Siwe project ID** | _Optional._ A WalletConnect / Reown project ID. Without it, only injected wallets (MetaMask, Safe, etc.) are available. To enable WalletConnect, create a free project ID at [cloud.walletconnect.com](https://cloud.walletconnect.com). |
| **Siwe statement** | The human-readable statement shown in the SIWE message. Defaults to "Sign in with Ethereum". |

## How it works

When a user clicks the Ethereum login button, the plugin opens a dedicated
authentication. The user connects their wallet, signs a SIWE message,
and is authenticated via an OmniAuth strategy on the server side.

After first sign-in, users are asked to associate an email address with their
account. If the connected address has an ENS name, it is suggested as the
default username.

Alternatively, existing users can connect their Ethereum accounts via
their profile settings.
