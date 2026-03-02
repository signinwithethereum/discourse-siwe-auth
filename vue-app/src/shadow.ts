/**
 * Shadow DOM encapsulation for the SIWE auth widget.
 *
 * Prevents library styles (:root, html, body resets, component CSS)
 * from leaking into the host page by mounting inside a shadow root.
 */

/**
 * Remap document-level selectors to shadow-compatible equivalents.
 * :root → :host, html {} → :host {}, body {} → :host {}
 */
function adaptStyles(css: string): string {
  return css
    .replace(/:root/g, ':host')
    .replace(/\bhtml\s*\{/g, ':host {')
    .replace(/\bbody\s*\{/g, ':host {')
}

/**
 * Map Discourse CSS custom properties to @1001-digital/styles equivalents.
 * Each entry is [discourseVar, [...targetVars]].
 */
const DISCOURSE_VAR_MAP: [string, string[]][] = [
  ['--primary', ['--color', '--primary']],
  ['--secondary', ['--background']],
  ['--danger', ['--error']],
  ['--success', ['--success']],
  ['--primary-medium', ['--muted']],
  ['--font-family', ['--font-family']],
  ['--border-color', ['--content-border-color']],
]

/**
 * Read Discourse theme CSS variables from the host document and return
 * a `:host {}` block that overrides the @1001-digital/styles defaults.
 * Returns an empty string when no Discourse variables are present
 * (e.g. in standalone dev mode).
 */
export function getHostCSSOverrides(): string {
  const computed = getComputedStyle(document.documentElement)
  const declarations: string[] = []

  for (const [discourseVar, targetVars] of DISCOURSE_VAR_MAP) {
    const value = computed.getPropertyValue(discourseVar).trim()
    if (!value) continue
    for (const target of targetVars) {
      declarations.push(`${target}: ${value};`)
    }
  }

  return declarations.length ? `:host { ${declarations.join(' ')} }` : ''
}

/**
 * Attach a shadow root to the host element with an inner mount
 * point and a teleport target for dialogs/overlays.
 */
export function createShadowRoot(host: Element) {
  const shadow = host.attachShadow({ mode: 'open' })

  const root = document.createElement('div')
  root.style.height = '100%'
  shadow.appendChild(root)

  // Teleport target — dialogs/overlays render here instead of <body>
  const teleportTarget = document.createElement('div')
  teleportTarget.id = 'teleports'
  shadow.appendChild(teleportTarget)

  return { shadow, root, teleportTarget }
}

/**
 * Inject a CSS string into the shadow root via a <style> element.
 * Uses <style> rather than adoptedStyleSheets so that @layer ordering
 * is shared with component <style> blocks captured by captureDevStyles.
 * Remaps :root/html/body selectors to :host so custom properties
 * and base styles apply within the shadow tree.
 */
export function injectStyles(shadow: ShadowRoot, css: string) {
  const style = document.createElement('style')
  style.textContent = adaptStyles(css)
  shadow.appendChild(style)
}

/**
 * In dev mode, Vite injects Vue SFC <style> blocks into document.head
 * as <style data-vite-dev-id="..."> elements. We intercept them and
 * clone them into every registered shadow root so they:
 *   1. Don't leak into the host page
 *   2. Actually apply inside each shadow tree
 *
 * A shared registry + observer ensures multiple mount calls
 * all receive the same styles. On HMR updates Vite creates a fresh
 * <style> (it can't find the moved one inside shadow DOM) — we
 * deduplicate by removing the previous clone first.
 *
 * Returns a cleanup function that unregisters the shadow root and
 * tears down the observer when the last instance unmounts.
 */
const devStyleTargets = new Set<ShadowRoot>()
let devObserver: MutationObserver | null = null

function distributeStyle(style: HTMLStyleElement) {
  const id = style.getAttribute('data-vite-dev-id')

  for (const shadow of devStyleTargets) {
    if (id) {
      shadow.querySelector(`style[data-vite-dev-id="${id}"]`)?.remove()
    }

    const clone = style.cloneNode(true) as HTMLStyleElement
    if (clone.textContent) {
      clone.textContent = adaptStyles(clone.textContent)
    }
    shadow.appendChild(clone)
  }

  // Remove original so it doesn't leak into the host page
  style.remove()
}

export function captureDevStyles(shadow: ShadowRoot): () => void {
  // Clone already-captured styles from a sibling shadow (they were
  // moved out of <head> by an earlier mount).
  if (devStyleTargets.size > 0) {
    const [existing] = devStyleTargets
    for (const el of existing.querySelectorAll<HTMLStyleElement>(
      'style[data-vite-dev-id]',
    )) {
      shadow.appendChild(el.cloneNode(true))
    }
  }

  devStyleTargets.add(shadow)

  // Move any remaining Vite-injected styles from <head>
  for (const el of [
    ...document.head.querySelectorAll('style[data-vite-dev-id]'),
  ]) {
    distributeStyle(el as HTMLStyleElement)
  }

  // Shared observer — one for all mounted instances
  if (!devObserver) {
    devObserver = new MutationObserver((mutations) => {
      for (const { addedNodes } of mutations) {
        for (const node of addedNodes) {
          if (
            node instanceof HTMLStyleElement &&
            node.hasAttribute('data-vite-dev-id')
          ) {
            distributeStyle(node)
          }
        }
      }
    })
    devObserver.observe(document.head, { childList: true })
  }

  return () => {
    devStyleTargets.delete(shadow)
    if (devStyleTargets.size === 0 && devObserver) {
      devObserver.disconnect()
      devObserver = null
    }
  }
}
