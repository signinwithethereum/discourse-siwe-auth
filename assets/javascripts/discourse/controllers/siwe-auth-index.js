import Controller from '@ember/controller'
import { withPluginApi } from 'discourse/lib/plugin-api'
import loadScript from 'discourse/lib/load-script'

export default Controller.extend({
  init() {
    this._super(...arguments)
    this.initAuth()
  },

  async initAuth() {
    const settings = withPluginApi('0.11.7', (api) => {
      const siteSettings = api.container.lookup('site-settings:main')
      return {
        projectId: siteSettings.siwe_project_id,
        statement: siteSettings.siwe_statement,
      }
    })

    const csrfToken =
      document
        .querySelector('meta[name="csrf-token"]')
        ?.getAttribute('content') || ''

    await loadScript('/plugins/discourse-siwe-auth/javascripts/siwe.iife.js')

    if (window.mountSiwe) {
      window.mountSiwe('#siwe-mount', {
        csrfToken,
        callbackUrl: '/auth/siwe/callback',
        messageUrl: '/discourse-siwe/message',
        walletConnectProjectId: settings.projectId,
        statement: settings.statement,
      })
    }
  },
})
