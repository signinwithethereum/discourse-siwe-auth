<script setup lang="ts">
import { ref, watch } from 'vue'
import { useAccount, useSignMessage } from '@wagmi/vue'
import { EvmConnect } from '@1001-digital/components'

const props = defineProps<{
  messageUrl: string
  callbackUrl: string
  csrfToken: string
  statement?: string
}>()

const status = ref<'idle' | 'signing' | 'submitting' | 'error'>('idle')
const errorMessage = ref('')

const { address, chainId, isConnected } = useAccount()
const { signMessageAsync } = useSignMessage()

async function fetchSiweMessage(
  ethAccount: string,
  chain: number,
): Promise<string> {
  const url = new URL(props.messageUrl, window.location.origin)
  url.searchParams.set('eth_account', ethAccount)
  url.searchParams.set('chain_id', String(chain))

  const res = await fetch(url.toString(), {
    headers: {
      Accept: 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-CSRF-Token': props.csrfToken,
    },
  })
  if (!res.ok)
    throw new Error(`Failed to fetch SIWE message: ${res.statusText}`)
  const { message } = await res.json()
  return message
}

function submitForm(
  account: string,
  message: string,
  signature: string,
  avatar: string,
) {
  const setField = (id: string, value: string) => {
    const el = document.getElementById(id) as HTMLTextAreaElement | null
    if (el) el.value = value
  }

  setField('eth_account', account)
  setField('eth_message', message)
  setField('eth_signature', signature)
  setField('eth_avatar', avatar)

  const form = document.getElementById('siwe-sign') as HTMLFormElement | null
  form?.submit()
}

async function signIn() {
  if (!address.value || !chainId.value) return

  status.value = 'signing'
  errorMessage.value = ''

  try {
    const message = await fetchSiweMessage(address.value, chainId.value)

    const signature = await signMessageAsync({ message })

    status.value = 'submitting'
    submitForm(address.value, message, signature, '')
  } catch (err: unknown) {
    status.value = 'error'
    if (err instanceof Error) {
      // User rejected signature
      if (
        err.message.includes('User rejected') ||
        err.message.includes('user rejected')
      ) {
        errorMessage.value = 'Signature rejected. Please try again.'
      } else {
        errorMessage.value = err.message
      }
    } else {
      errorMessage.value = 'An unknown error occurred.'
    }
  }
}

// Auto-sign when wallet connects
watch([isConnected, address], ([connected, addr]) => {
  if (connected && addr && status.value === 'idle') {
    signIn()
  }
})
</script>

<template>
  <div class="siwe-auth">
    <div
      v-if="status === 'signing'"
      class="siwe-status"
    >
      <p>Please sign the message in your wallet...</p>
    </div>

    <div
      v-else-if="status === 'submitting'"
      class="siwe-status"
    >
      <p>Verifying signature...</p>
    </div>

    <div
      v-else-if="status === 'error'"
      class="siwe-error"
    >
      <p>{{ errorMessage }}</p>
      <button
        class="siwe-retry-btn"
        @click="signIn"
      >
        Try again
      </button>
    </div>

    <EvmConnect v-if="status !== 'submitting'" />
  </div>
</template>

<style scoped>
.siwe-auth {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100%;
  gap: 1.5rem;
  padding: 2rem;
}

.siwe-status {
  text-align: center;
  font-size: 1.125rem;
}

.siwe-error {
  text-align: center;
  color: var(--color-danger, #e74c3c);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.siwe-retry-btn {
  padding: 0.5rem 1.25rem;
  border-radius: 0.375rem;
  border: 1px solid currentColor;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font-size: 0.875rem;
}

.siwe-retry-btn:hover {
  opacity: 0.8;
}
</style>
