import { readFileSync, writeFileSync, unlinkSync, readdirSync } from 'fs'
import { resolve } from 'path'
import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'

/**
 * After Vite writes the build output, reads any extracted CSS files,
 * prepends them to the JS bundle as `var __siwe_css__`, and deletes
 * the CSS files. This lets mountSiwe() inject component styles into
 * the shadow DOM at runtime.
 */
function cssToShadow(): Plugin {
  let outDir = ''
  return {
    name: 'css-to-shadow',
    configResolved(config) {
      outDir = config.build.outDir
    },
    closeBundle() {
      const absOut = resolve(outDir)
      const files = readdirSync(absOut)
      const cssFiles = files.filter((f) => f.endsWith('.css'))
      if (!cssFiles.length) return

      let css = ''
      for (const f of cssFiles) {
        css += readFileSync(resolve(absOut, f), 'utf-8')
        unlinkSync(resolve(absOut, f))
      }

      const jsFile = files.find((f) => f === 'siwe.iife.js')
      if (!jsFile) return

      const jsPath = resolve(absOut, jsFile)
      const js = readFileSync(jsPath, 'utf-8')
      // Prepend __siwe_css__ as a global before the IIFE
      writeFileSync(
        jsPath,
        `var __siwe_css__ = ${JSON.stringify(css)};\n` + js,
      )
    },
  }
}

export default defineConfig({
  plugins: [vue(), cssToShadow()],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  build: {
    lib: {
      entry: 'src/main.ts',
      formats: ['iife'],
      name: 'SiweAuth',
      fileName: () => 'siwe.iife.js',
    },
    outDir: '../public/javascripts',
    emptyOutDir: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  resolve: {
    dedupe: ['vue', '@wagmi/core', '@wagmi/vue'],
  },
  optimizeDeps: {
    exclude: ['@1001-digital/components'],
    include: [
      '@metamask/sdk',
      'eventemitter3',
      'qrcode',
      '@walletconnect/ethereum-provider',
      '@reown/appkit/core',
      '@safe-global/safe-apps-sdk',
      '@safe-global/safe-apps-provider',
    ],
  },
})
