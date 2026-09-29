import bodyClass from 'discourse/helpers/body-class'
import hideApplicationHeaderButtons from 'discourse/helpers/hide-application-header-buttons'
import hideApplicationSidebar from 'discourse/helpers/hide-application-sidebar'

export default <template>
  {{bodyClass 'siwe-login-page'}}
  {{hideApplicationHeaderButtons 'search' 'login' 'signup' 'menu'}}
  {{hideApplicationSidebar}}

  <form
    id='siwe-sign'
    method='POST'
    action='/auth/siwe/callback'
    style='display: none;'
  >
    <textarea
      id='eth_message'
      name='eth_message'
    ></textarea>
    <textarea
      id='eth_signature'
      name='eth_signature'
    ></textarea>
  </form>

  <div
    id='siwe-mount'
    class='siwe-mount'
  ></div>
</template>
