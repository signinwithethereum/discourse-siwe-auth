/// <reference types="vite/client" />

interface ImportMeta {
  readonly server?: boolean
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, unknown>
  export default component
}

declare module '@1001-digital/styles?inline' {
  const css: string
  export default css
}
