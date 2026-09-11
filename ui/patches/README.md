# apg-js 4.4.0

This patch belongs only to the Discourse plugin's pnpm workspace. It does not
modify or patch the shared Layers packages.

MetaMask Connect depends on `@spruceid/siwe-parser` through its permission
utilities. That parser uses apg-js, whose parser and AST enumerate callback
arrays with `for...in`. In Discourse's Ember environment, inherited enumerable
properties such as `_super` are then mistaken for grammar rules, crashing SDK
initialization before wallet connection.

The patch limits both callback enumerations to own keys. It does not change
Discourse globals or grammar validation. `pnpm install --frozen-lockfile` applies
it automatically; `pnpm test` covers inherited properties and invalid own
callbacks. Remove it when the installed upstream version handles own keys.
