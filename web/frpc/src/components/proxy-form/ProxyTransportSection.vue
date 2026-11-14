<template>
  <ConfigSection title="Transport" collapsible :readonly="readonly"
    :has-value="form.useEncryption || form.useCompression || !!form.bandwidthLimit || (!!form.bandwidthLimitMode && form.bandwidthLimitMode !== 'client') || !!form.proxyProtocolVersion || (showProxyProtocolMode && !!form.proxyProtocolMode) || (showSocketMark && form.socketMark != null)">
    <div class="field-row two-col">
      <ConfigField label="Use Encryption" type="switch" v-model="form.useEncryption" :readonly="readonly" />
      <ConfigField label="Use Compression" type="switch" v-model="form.useCompression" :readonly="readonly" />
    </div>
    <div class="field-row three-col">
      <ConfigField label="Bandwidth Limit" type="text" v-model="form.bandwidthLimit" placeholder="1MB" tip="e.g., 1MB, 500KB" :readonly="readonly" />
      <ConfigField label="Bandwidth Limit Mode" type="select" v-model="form.bandwidthLimitMode"
        :options="[{ label: 'Client', value: 'client' }, { label: 'Server', value: 'server' }]" :readonly="readonly" />
      <ConfigField label="Proxy Protocol" type="select" v-model="form.proxyProtocolVersion"
        :options="[{ label: 'None', value: '' }, { label: 'v1', value: 'v1' }, { label: 'v2', value: 'v2' }, { label: 'tproxy', value: 'tproxy' }]" :readonly="readonly" />
    </div>
    <div v-if="showProxyProtocolMode || showSocketMark" class="field-row two-col">
      <ConfigField
        v-if="showProxyProtocolMode"
        label="Proxy Protocol Mode"
        type="select"
        v-model="form.proxyProtocolMode"
        :options="[{ label: 'Default (first-packet)', value: '' }, { label: 'first-packet', value: 'first-packet' }, { label: 'per-packet', value: 'per-packet' }]"
        :readonly="readonly"
      />
      <ConfigField
        v-if="showSocketMark"
        label="Socket Mark"
        type="number"
        v-model="form.socketMark"
        :min="0"
        :max="2147483647"
        placeholder="1"
        tip="Linux fwmark for policy routing (defaults to 1)"
        :readonly="readonly"
      />
    </div>
  </ConfigSection>
</template>

<script setup lang="ts">
import { computed, watch } from 'vue'
import type { ProxyFormData } from '../../types'
import ConfigSection from '../ConfigSection.vue'
import ConfigField from '../ConfigField.vue'

const props = withDefaults(defineProps<{
  modelValue: ProxyFormData
  readonly?: boolean
}>(), { readonly: false })

const emit = defineEmits<{ 'update:modelValue': [value: ProxyFormData] }>()

const form = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val),
})

const showProxyProtocolMode = computed(
  () =>
    (form.value.type === 'udp' || form.value.type === 'sudp') &&
    (form.value.proxyProtocolVersion === 'v1' ||
      form.value.proxyProtocolVersion === 'v2'),
)

watch(
  [
    showProxyProtocolMode,
    () => form.value.proxyProtocolMode,
    () => props.readonly,
  ],
  ([visible, mode, readonly]) => {
    if (!visible && !readonly && mode) {
      form.value.proxyProtocolMode = ''
    }
  },
  { immediate: true },
)

const showSocketMark = computed(
  () => form.value.proxyProtocolVersion === 'tproxy',
)

watch(
  [showSocketMark, () => form.value.socketMark, () => props.readonly],
  ([visible, socketMark, readonly]) => {
    if (!visible && !readonly && socketMark != null) {
      form.value.socketMark = undefined
    }
  },
  { immediate: true },
)
</script>

<style scoped lang="scss">
@use '@/assets/css/form-layout';
</style>
