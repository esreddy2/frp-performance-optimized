import { defineComponent, reactive } from 'vue'
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import ProxyTransportSection from '../src/components/proxy-form/ProxyTransportSection.vue'
import ConfigSection from '../src/components/ConfigSection.vue'
import { createDefaultProxyForm } from '../src/types/proxy-form'
import type { ProxyType } from '../src/types/constants'

const ConfigFieldStub = defineComponent({
  props: ['label', 'type', 'modelValue', 'options', 'readonly', 'min', 'max'],
  template: '<div class="config-field-stub" :data-label="label" />',
})

const stubs = {
  ConfigField: ConfigFieldStub,
  'el-icon': defineComponent({ template: '<span><slot /></span>' }),
  ArrowDown: defineComponent({ template: '<span />' }),
}

function mountSection(
  overrides: Partial<ReturnType<typeof createDefaultProxyForm>>,
  readonly = false,
) {
  const form = reactive(createDefaultProxyForm())
  Object.assign(form, overrides)
  return {
    form,
    wrapper: mount(ProxyTransportSection, {
      props: { modelValue: form, readonly },
      global: { stubs },
    }),
  }
}

describe('ProxyTransportSection', () => {
  it.each([
    ['udp', 'v1'],
    ['udp', 'v2'],
    ['sudp', 'v1'],
    ['sudp', 'v2'],
  ] as const)(
    'shows Proxy Protocol Mode for %s when proxyProtocolVersion is %s',
    (type, proxyProtocolVersion) => {
      const { wrapper } = mountSection({ type, proxyProtocolVersion })
      expect(
        wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
      ).toBe(true)
    },
  )

  it.each(['tcp', 'http', 'https', 'tcpmux', 'stcp', 'xtcp'] as ProxyType[])(
    'hides Proxy Protocol Mode for %s even when proxyProtocolVersion is v2',
    (type) => {
      const { wrapper } = mountSection({ type, proxyProtocolVersion: 'v2' })
      expect(
        wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
      ).toBe(false)
    },
  )

  it.each(['', 'tproxy'])(
    'hides Proxy Protocol Mode for udp when proxyProtocolVersion is %s',
    (proxyProtocolVersion) => {
      const { wrapper } = mountSection({ type: 'udp', proxyProtocolVersion })
      expect(
        wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
      ).toBe(false)
    },
  )

  it('hides and resets Proxy Protocol Mode when switching type from udp to tcp', async () => {
    const { form, wrapper } = mountSection({
      type: 'udp',
      proxyProtocolVersion: 'v2',
      proxyProtocolMode: 'per-packet',
    })

    expect(
      wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
    ).toBe(true)

    form.type = 'tcp'
    await wrapper.vm.$nextTick()

    expect(
      wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
    ).toBe(false)
    expect(form.proxyProtocolMode).toBe('')
  })

  it.each(['tproxy', ''])(
    'hides and resets Proxy Protocol Mode when switching proxyProtocolVersion from v2 to %s',
    async (nextVersion) => {
      const { form, wrapper } = mountSection({
        type: 'sudp',
        proxyProtocolVersion: 'v2',
        proxyProtocolMode: 'per-packet',
      })

      form.proxyProtocolVersion = nextVersion
      await wrapper.vm.$nextTick()

      expect(
        wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
      ).toBe(false)
      expect(form.proxyProtocolMode).toBe('')
    },
  )

  it('preserves Proxy Protocol Mode when switching between udp/sudp and v1/v2', async () => {
    const { form, wrapper } = mountSection({
      type: 'udp',
      proxyProtocolVersion: 'v1',
      proxyProtocolMode: 'per-packet',
    })

    form.type = 'sudp'
    form.proxyProtocolVersion = 'v2'
    await wrapper.vm.$nextTick()

    expect(
      wrapper.find('[data-label="Proxy Protocol Mode"]').exists(),
    ).toBe(true)
    expect(form.proxyProtocolMode).toBe('per-packet')
  })

  it('does not mutate proxyProtocolMode in readonly mode', async () => {
    const { form, wrapper } = mountSection(
      {
        type: 'udp',
        proxyProtocolVersion: 'v2',
        proxyProtocolMode: 'per-packet',
      },
      true,
    )

    form.type = 'tcp'
    await wrapper.vm.$nextTick()

    expect(form.proxyProtocolMode).toBe('per-packet')
  })

  it('clears stale proxyProtocolMode immediately on mount when not readonly', () => {
    const { form } = mountSection({
      type: 'tcp',
      proxyProtocolVersion: 'v2',
      proxyProtocolMode: 'per-packet',
    })

    expect(form.proxyProtocolMode).toBe('')
  })

  it('does not clear stale proxyProtocolMode on mount when readonly', () => {
    const { form } = mountSection(
      {
        type: 'tcp',
        proxyProtocolVersion: 'v2',
        proxyProtocolMode: 'per-packet',
      },
      true,
    )

    expect(form.proxyProtocolMode).toBe('per-packet')
  })

  it('clears stale proxyProtocolMode when modelValue is replaced via props', async () => {
    const { wrapper } = mountSection({
      type: 'tcp',
      proxyProtocolVersion: '',
      proxyProtocolMode: '',
    })

    const nextForm = reactive(createDefaultProxyForm())
    Object.assign(nextForm, {
      type: 'http',
      proxyProtocolVersion: 'v2',
      proxyProtocolMode: 'per-packet',
    })

    await wrapper.setProps({ modelValue: nextForm })
    await wrapper.vm.$nextTick()

    expect(nextForm.proxyProtocolMode).toBe('')
  })

  it('shows Socket Mark with min=0 and max=2147483647 when proxyProtocolVersion is tproxy', () => {
    const { wrapper } = mountSection({
      type: 'tcp',
      proxyProtocolVersion: 'tproxy',
    })

    const field = wrapper
      .findAllComponents(ConfigFieldStub)
      .find((c) => c.props('label') === 'Socket Mark')
    expect(field).toBeDefined()
    expect(field!.props('min')).toBe(0)
    expect(field!.props('max')).toBe(2147483647)
  })

  it.each(['', 'v1', 'v2'])(
    'hides Socket Mark when proxyProtocolVersion is %s',
    (proxyProtocolVersion) => {
      const { wrapper } = mountSection({
        type: 'tcp',
        proxyProtocolVersion,
      })

      expect(wrapper.find('[data-label="Socket Mark"]').exists()).toBe(false)
    },
  )

  it.each(['v2', ''])(
    'hides and resets socketMark when switching proxyProtocolVersion from tproxy to %s',
    async (nextVersion) => {
      const { form, wrapper } = mountSection({
        type: 'tcp',
        proxyProtocolVersion: 'tproxy',
        socketMark: 2,
      })

      expect(wrapper.find('[data-label="Socket Mark"]').exists()).toBe(true)

      form.proxyProtocolVersion = nextVersion
      await wrapper.vm.$nextTick()

      expect(wrapper.find('[data-label="Socket Mark"]').exists()).toBe(false)
      expect(form.socketMark).toBeUndefined()
    },
  )

  it('clears socketMark=0 when switching proxyProtocolVersion away from tproxy', async () => {
    const { form, wrapper } = mountSection({
      type: 'tcp',
      proxyProtocolVersion: 'tproxy',
      socketMark: 0,
    })

    form.proxyProtocolVersion = ''
    await wrapper.vm.$nextTick()

    expect(form.socketMark).toBeUndefined()
  })

  it('does not mutate socketMark in readonly mode', async () => {
    const { form, wrapper } = mountSection(
      {
        type: 'tcp',
        proxyProtocolVersion: 'tproxy',
        socketMark: 2,
      },
      true,
    )

    form.proxyProtocolVersion = 'v2'
    await wrapper.vm.$nextTick()

    expect(form.socketMark).toBe(2)
  })

  it.each([0, 2])(
    'clears stale socketMark=%s immediately on mount when not readonly',
    (socketMark) => {
      const { form } = mountSection({
        type: 'tcp',
        proxyProtocolVersion: 'v2',
        socketMark,
      })

      expect(form.socketMark).toBeUndefined()
    },
  )

  it('does not clear stale socketMark on mount when readonly and does not count it as hasValue', () => {
    const { form, wrapper } = mountSection(
      {
        type: 'tcp',
        proxyProtocolVersion: '',
        socketMark: 2,
      },
      true,
    )

    expect(form.socketMark).toBe(2)
    expect(wrapper.findComponent(ConfigSection).props('hasValue')).toBe(false)
    expect(wrapper.find('.not-configured-badge').exists()).toBe(true)
  })

  it('clears stale socketMark when modelValue is replaced via props', async () => {
    const { wrapper } = mountSection({
      type: 'tcp',
      proxyProtocolVersion: '',
      socketMark: undefined,
    })

    const nextForm = reactive(createDefaultProxyForm())
    Object.assign(nextForm, {
      type: 'tcp',
      proxyProtocolVersion: 'v1',
      socketMark: 5,
    })

    await wrapper.setProps({ modelValue: nextForm })
    await wrapper.vm.$nextTick()

    expect(nextForm.socketMark).toBeUndefined()
  })

  it('clears stale socketMark when switching from readonly to editable', async () => {
    const { form, wrapper } = mountSection(
      {
        type: 'tcp',
        proxyProtocolVersion: 'v2',
        socketMark: 3,
      },
      true,
    )

    expect(form.socketMark).toBe(3)

    await wrapper.setProps({ readonly: false })
    await wrapper.vm.$nextTick()

    expect(form.socketMark).toBeUndefined()
  })

  it('clamps negative Socket Mark input to 0 with real ConfigField', async () => {
    const form = reactive(createDefaultProxyForm())
    form.type = 'tcp'
    form.proxyProtocolVersion = 'tproxy'

    const InputStub = defineComponent({
      props: ['modelValue', 'disabled', 'placeholder', 'type'],
      emits: ['update:modelValue'],
      template:
        '<input :value="modelValue ?? \'\'" :disabled="disabled" :placeholder="placeholder" @input="$emit(\'update:modelValue\', $event.target.value)" />',
    })

    const wrapper = mount(ProxyTransportSection, {
      props: { modelValue: form, readonly: false },
      global: {
        stubs: {
          'el-icon': defineComponent({ template: '<span><slot /></span>' }),
          ArrowDown: defineComponent({ template: '<span />' }),
          'el-form-item': defineComponent({
            props: ['label'],
            template: '<div class="form-item-stub" :data-label="label"><slot /></div>',
          }),
          'el-input': InputStub,
          'el-switch': defineComponent({
            props: ['modelValue', 'disabled'],
            template: '<button :disabled="disabled" />',
          }),
          PopoverMenu: defineComponent({
            template: '<div class="popover-stub"><slot filterText="" /></div>',
          }),
          PopoverMenuItem: defineComponent({ template: '<div><slot /></div>' }),
          KeyValueEditor: defineComponent({ template: '<div />' }),
          StringListEditor: defineComponent({ template: '<div />' }),
        },
      },
    })

    const socketMarkItem = wrapper.find('[data-label="Socket Mark"]')
    expect(socketMarkItem.exists()).toBe(true)

    const input = socketMarkItem.find('input')
    await input.setValue('-5')

    expect(form.socketMark).toBe(0)
    expect((input.element as HTMLInputElement).value).toBe('0')
  })

  it('clamps Socket Mark input above 2147483647 to 2147483647 with real ConfigField', async () => {
    const form = reactive(createDefaultProxyForm())
    form.type = 'tcp'
    form.proxyProtocolVersion = 'tproxy'

    const InputStub = defineComponent({
      props: ['modelValue', 'disabled', 'placeholder', 'type'],
      emits: ['update:modelValue', 'blur'],
      template:
        '<input :value="modelValue ?? \'\'" :disabled="disabled" :placeholder="placeholder" @input="$emit(\'update:modelValue\', $event.target.value)" @blur="$emit(\'blur\', $event)" />',
    })

    const wrapper = mount(ProxyTransportSection, {
      props: { modelValue: form, readonly: false },
      global: {
        stubs: {
          'el-icon': defineComponent({ template: '<span><slot /></span>' }),
          ArrowDown: defineComponent({ template: '<span />' }),
          'el-form-item': defineComponent({
            props: ['label'],
            template: '<div class="form-item-stub" :data-label="label"><slot /></div>',
          }),
          'el-input': InputStub,
          'el-switch': defineComponent({
            props: ['modelValue', 'disabled'],
            template: '<button :disabled="disabled" />',
          }),
          PopoverMenu: defineComponent({
            template: '<div class="popover-stub"><slot filterText="" /></div>',
          }),
          PopoverMenuItem: defineComponent({ template: '<div><slot /></div>' }),
          KeyValueEditor: defineComponent({ template: '<div />' }),
          StringListEditor: defineComponent({ template: '<div />' }),
        },
      },
    })

    const socketMarkItem = wrapper.find('[data-label="Socket Mark"]')
    expect(socketMarkItem.exists()).toBe(true)

    const input = socketMarkItem.find('input')
    await input.setValue('2147483648')

    expect(form.socketMark).toBe(2147483647)
    expect((input.element as HTMLInputElement).value).toBe('2147483647')

    await input.setValue('2147483647')
    expect(form.socketMark).toBe(2147483647)
    expect((input.element as HTMLInputElement).value).toBe('2147483647')

    await input.setValue('-')
    await wrapper.vm.$nextTick()
    expect(form.socketMark).toBe(2147483647)
    expect((input.element as HTMLInputElement).value).toBe('2147483647')
  })
})
