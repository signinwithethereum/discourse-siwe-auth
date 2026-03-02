<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useConnection, useDisconnect, useSignMessage } from '@wagmi/vue'
import {
  Button,
  EvmAccount,
  EvmConnect,
  Loading,
  useEnsWithAvatar,
  useResolveUri,
} from '@1001-digital/components'

const props = defineProps<{
  messageUrl: string
  csrfToken: string
}>()

const status = ref<'idle' | 'signing' | 'submitting' | 'error'>('idle')
const errorMessage = ref('')

const { address, chainId, isConnected, connector } = useConnection()
const { mutateAsync: signMessageAsync } = useSignMessage()
const { mutate: disconnectAccount } = useDisconnect()

const disconnect = () => {
  status.value = 'idle'
  errorMessage.value = ''
  disconnectAccount()
}

// Track whether the user actively connected via EvmConnect
// (as opposed to an auto-reconnect on page load).
const userInitiated = ref(false)

// ENS resolution
const { data: ensData } = useEnsWithAvatar(address)
const resolve = useResolveUri()
const ensName = computed(() => ensData.value?.ens ?? '')
const ensAvatar = computed(() => resolve(ensData.value?.data?.avatar) ?? '')

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
  name: string,
  avatar: string,
) {
  const setField = (id: string, value: string) => {
    const el = document.getElementById(id) as HTMLTextAreaElement | null
    if (el) el.value = value
  }

  setField('eth_account', account)
  setField('eth_message', message)
  setField('eth_signature', signature)
  setField('eth_name', name)
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
    submitForm(
      address.value,
      message,
      signature,
      ensName.value,
      ensAvatar.value,
    )
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
    <Loading
      v-if="status === 'signing'"
      spinner
      stacked
      :txt="
        connector?.name
          ? `Requesting signature from ${connector.name}...`
          : 'Requesting signature...'
      "
    />

    <Loading
      v-else-if="status === 'submitting'"
      spinner
      stacked
      txt="Verifying signature..."
    />

    <template v-else-if="isConnected && status === 'error'">
      <p class="error">{{ errorMessage }}</p>
      <Button
        class="block danger"
        @click="signIn"
      >
        Try again
      </Button>
      <hr />
    </template>

    <template v-if="isConnected && address">
      <Button
        v-if="status === 'idle'"
        class="block"
        @click="signIn"
      >
        Sign Message
      </Button>
      <Button
        class="block tertiary"
        @click="disconnect()"
      >
        Switch wallet (<EvmAccount
          :address="address"
          class="siwe-address"
        />)
      </Button>
    </template>

    <EvmConnect
      v-else-if="status !== 'submitting'"
      @connecting="userInitiated = true"
    />
  </div>
</template>

<style scoped>
.siwe-auth {
  flex-direction: column;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100%;
  gap: var(--spacer);
  padding: var(--spacer);

  > * {
    width: 100%;
  }

  .error {
    color: var(--error);
  }

  .centered {
    text-align: center;
  }
}
</style>
