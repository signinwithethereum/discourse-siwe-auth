<script setup lang="ts">
import { ref, watch } from 'vue'
import { useConnection, useDisconnect, useSignMessage } from '@wagmi/vue'
import { EvmAccount, EvmConnect } from '@1001-digital/components'

const props = defineProps<{
  messageUrl: string
  csrfToken: string
}>()

const status = ref<'idle' | 'signing' | 'submitting' | 'error'>('idle')
const errorMessage = ref('')

const { address, chainId, isConnected, connector } = useConnection()
const { mutateAsync: signMessageAsync } = useSignMessage()
const { mutate: disconnect } = useDisconnect()

// Track whether the user actively connected via EvmConnect
// (as opposed to an auto-reconnect on page load).
const userInitiated = ref(false)

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

function submitForm(account: string, message: string, signature: string) {
  const setField = (id: string, value: string) => {
    const el = document.getElementById(id) as HTMLTextAreaElement | null
    if (el) el.value = value
  }

  setField('eth_account', account)
  setField('eth_message', message)
  setField('eth_signature', signature)
  setField('eth_avatar', '')

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
    submitForm(address.value, message, signature)
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

// Auto-sign only when the user actively connects (not on page-load reconnect)
watch([isConnected, address], ([connected, addr]) => {
  if (connected && addr && status.value === 'idle' && userInitiated.value) {
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
        class="siwe-btn"
        @click="signIn"
      >
        Try again
      </button>
    </div>

    <div
      v-if="isConnected && address"
      class="siwe-connected"
    >
      <p>
        Connected via {{ connector?.name ?? 'wallet' }}
        <EvmAccount
          :address="address"
          class="siwe-address"
        />
      </p>

      <button
        v-if="status === 'idle'"
        class="siwe-sign-btn"
        @click="signIn"
      >
        Sign Message
      </button>

      <button
        class="siwe-btn siwe-btn--subtle"
        @click="disconnect()"
      >
        Disconnect
      </button>
    </div>

    <EvmConnect
      v-else-if="status !== 'submitting'"
      @connecting="userInitiated = true"
    />
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

  > * {
    width: 100%;
  }
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

.siwe-btn {
  padding: 0.5rem 1.25rem;
  border-radius: 0.375rem;
  border: 1px solid currentColor;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font-size: 0.875rem;
}

.siwe-btn:hover {
  opacity: 0.8;
}

.siwe-btn--subtle {
  font-size: 0.75rem;
  padding: 0.375rem 1rem;
  opacity: 0.6;
}

.siwe-connected {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
}

.siwe-connected p {
  font-size: 0.875rem;
  opacity: 0.7;
}

.siwe-address {
  font-family: monospace;
}

.siwe-sign-btn {
  padding: 0.625rem 1.5rem;
  border-radius: 0.375rem;
  border: none;
  background: var(--color-primary, #3b82f6);
  color: #fff;
  cursor: pointer;
  font-size: 1rem;
}

.siwe-sign-btn:hover {
  opacity: 0.9;
}
</style>
