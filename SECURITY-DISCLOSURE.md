# SIWE Discourse Plugin — Security Disclosure

A month ago [we announced](https://discuss.ens.domains/t/siwe-discourse-plugin-update-user-action-item/21990) that we had taken over the Sign in with Ethereum Discourse plugin, shipped a full rewrite, and promised to publish the details of the patched security vulnerabilities after 30 days. The window has elapsed. This is that disclosure.

Four vulnerabilities were found in the original SpruceID plugin ([spruceid/discourse-siwe-auth](https://github.com/spruceid/discourse-siwe-auth), version 0.1.2 and earlier). All are fixed in [signinwithethereum/discourse-siwe-auth](https://github.com/signinwithethereum/discourse-siwe-auth) v1.1.0 and later. The ENS forum, which ran the old plugin, was upgraded before this disclosure.

## Summary

| # | Severity | Issue | Impact |
| - | --- | --- | --- |
| 1 | Critical | Unverified `eth_account` form field used as the user ID | Full account takeover of any SIWE-connected account |
| 2 | High | ENS name stored as the account identifier | Account takeover when an ENS domain changes hands |
| 3 | Medium | Nonce not invalidated after use | Replay of a captured SIWE signature within the same session |
| 4 | Medium | Client-supplied ENS name and avatar trusted by the server | Display-name and avatar impersonation |

Full technical details, including old code paths and step-by-step reproduction, are in the [technical write-up gist](https://gist.github.com/jwahdatehagh/069c316c629a564ad62d35ea8b5998de). The sections below summarise each issue and link to the commits that fixed it in the new plugin.

## 1. Account takeover via unverified `eth_account` form field

**Severity: Critical.** This is the one that matters.

The old server set the OmniAuth UID from a hidden form field called `eth_account`, submitted by the client alongside the SIWE message and signature:

```ruby
option :uid_field, :eth_account

uid do
  request.params[options.uid_field.to_s]  # straight from the POST body
end
```

The signature was validated against the address embedded in the SIWE message, but the server never checked that `eth_account` matched that address. An attacker could sign a valid SIWE message with their own wallet, then replace `eth_account` in the hidden form before submission with any address or ENS name they wanted to impersonate. The server would verify the signature (valid — for the attacker's own address), then log them in as whoever was named in `eth_account`.

No on-chain interaction with the target was required. Any Discourse account previously linked to a SIWE identity could be taken over by anyone.

**Fix:** the `eth_account` field was removed from both the frontend form and the server. The UID is now derived from `siwe_message.address` — the address inside the cryptographically verified payload — and no client-submitted identity data is trusted.

Fixed in [`5c86c58`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/5c86c58ec6f309cdb26b08a60bc8823c8135e189) (`lib/omniauth/strategies/siwe.rb`).

## 2. ENS name used as the account identifier

**Severity: High.**

The old frontend resolved the connecting wallet's primary ENS name in the browser and sent that string (e.g. `alice.eth`) as `eth_account`. Because `eth_account` was stored as the `provider_uid` on the `UserAssociatedAccount` record, the account was keyed to the ENS name rather than to the underlying Ethereum address.

ENS names are transferable and can expire. If `alice.eth` later changed ownership, the new owner could sign in, have their address resolve to `alice.eth` client-side, and be matched straight into the original user's Discourse account.

**Fix:** the UID is now always the raw Ethereum address, taken from the signed SIWE message. ENS names are used only for display (nickname, profile name) and are resolved server-side with forward verification — reverse-resolve the address to a name, then resolve that name back to an address, and only accept it if the two match.

Fixed in [`5c86c58`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/5c86c58ec6f309cdb26b08a60bc8823c8135e189), [`948f5d8`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/948f5d8), [`15aab22`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/15aab22).

## 3. Nonce not invalidated after use (replay)

**Severity: Medium.**

The old callback checked the nonce against the session but left it in place after a successful sign-in:

```ruby
if siwe_message.nonce != session[:nonce]
  return fail!("Invalid nonce")
end
```

An attacker who obtained a valid SIWE message + signature (from proxy logs, a shared network, error reports, anywhere they were captured) could replay it against the same session cookie while that session was still active. The nonce check would pass because the original value was still present.

**Fix:** the nonce is pulled out of the session and deleted in a single step, before it is compared. A replay finds nothing in the session and fails.

```ruby
nonce = session.delete(:nonce)
if siwe_message.nonce != nonce
  return fail!("Invalid nonce")
end
```

Fixed in [`259c91e`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/259c91eb305905f6f81a4ec38bde3de29dceafd6) (`lib/omniauth/strategies/siwe.rb:52`).

## 4. Unverified client-supplied ENS name and avatar

**Severity: Medium.**

Separately from vulnerability #1, the old plugin also accepted the display name and avatar URL as client-supplied form fields and used them directly for the Discourse profile:

```ruby
info do
  {
    name:  request.params[options.uid_field.to_s],
    image: request.params['eth_avatar']
  }
end
```

A user could edit the hidden fields before submitting the form and pick any ENS name or avatar URL they wanted on their profile. Even without the UID bug in #1, this was enough to impersonate any ENS identity visually in threads and user cards.

**Fix:** the `eth_name` and `eth_avatar` form fields are gone. ENS names are resolved and forward-verified on the server, and avatars are fetched through the ENS Metadata Service (`metadata.ens.domains`) which handles IPFS, Arweave and NFT formats uniformly.

Fixed in [`948f5d8`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/948f5d8), [`15aab22`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/15aab22), [`b66c0b8`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/b66c0b8), [`2a7b3a2`](https://github.com/signinwithethereum/discourse-siwe-auth/commit/2a7b3a2).

## Why this happened

All four bugs share a single root cause: the old plugin treated fields that came alongside the signed SIWE message as if they were part of it. The signature was verified, but the identity the server acted on (`eth_account`, `eth_name`, `eth_avatar`) came from sibling form fields the client could freely edit. Once `eth_account` was decoupled from the address inside the SIWE payload, there was no authentication — only the appearance of it.

The fix in the new plugin is architectural rather than incremental: the SIWE message is the only source of truth for who is signing in. Nothing the client sends outside of it is trusted for identity.

## If you still run the old plugin

If your forum is still on `spruceid/discourse-siwe-auth`, upgrade now. Swap the git URL in your `app.yml`:

```yml
hooks:
  after_code:
    - exec:
      cd: $home/plugins
      cmd:
        - sudo -E -u discourse git clone https://github.com/signinwithethereum/discourse-siwe-auth.git
```

Rebuild:

```bash
cd /var/discourse
./launcher rebuild app
```

After rebuild, set `siwe_ethereum_rpc_url` in **Admin > Settings** to a dedicated Ethereum RPC endpoint (Alchemy, Infura, etc.). This is needed for ENS resolution and smart contract wallet support.

Existing users will need to reconnect their wallet in their Discourse profile settings — the previous announcement has [step-by-step instructions](https://discuss.ens.domains/t/siwe-discourse-plugin-update-user-action-item/21990) for end users.

## Timeline

| Date | Action |
| --- | --- |
| 2026-03-05 | v1.0.0 released — full frontend rewrite, partial fixes to #2, #3, #4 |
| 2026-03-12 | v1.0.2 — server-side ENS resolution completes the fix for #4 |
| 2026-03-12 | v1.1.0 — UID derived from the verified SIWE message, nonce invalidation (fixes #1, #2, #3) |
| 2026-03-12 | User-action-item announcement posted on the ENS forum, 30-day disclosure window begins |
| 2026-04-20 | This public disclosure |

## Reporting

If you find a security issue in the plugin, please report it privately via a [GitHub Security Advisory](https://github.com/signinwithethereum/discourse-siwe-auth/security/advisories/new) rather than as a public issue.
