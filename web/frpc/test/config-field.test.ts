import { defineComponent, nextTick } from 'vue'
import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { ElFormItem, ElInput } from 'element-plus'
import ConfigField from '../src/components/ConfigField.vue'

const InputStub = defineComponent({
  props: ['modelValue', 'disabled', 'placeholder', 'type'],
  emits: ['update:modelValue', 'blur'],
  template:
    '<input :value="modelValue ?? \'\'" :disabled="disabled" :placeholder="placeholder" :type="type === \'password\' ? \'password\' : \'text\'" @input="$emit(\'update:modelValue\', $event.target.value)" @blur="$emit(\'blur\', $event)" />',
})

const FormItemStub = defineComponent({
  template: '<div class="form-item-stub"><slot /></div>',
})

const stubs = {
  'el-form-item': FormItemStub,
  'el-input': InputStub,
  'el-switch': defineComponent({
    props: ['modelValue', 'disabled'],
    emits: ['update:modelValue'],
    template: '<button :disabled="disabled" @click="$emit(\'update:modelValue\', !modelValue)">switch</button>',
  }),
  KeyValueEditor: defineComponent({ template: '<div class="key-value-stub" />' }),
  StringListEditor: defineComponent({ template: '<div class="string-list-stub" />' }),
  PopoverMenu: defineComponent({ template: '<div class="popover-stub"><slot /></div>' }),
  PopoverMenuItem: defineComponent({ template: '<div><slot /></div>' }),
}

describe('ConfigField', () => {
  it('clamps numeric input and emits the public model update', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: 100, min: 1, max: 65535 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('70000')

    expect(wrapper.emitted('update:modelValue')).toContainEqual([65535])
    expect((input.element as HTMLInputElement).value).toBe('65535')
  })

  it('clamps negative numeric input to min=0', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: undefined, min: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-5')

    expect(wrapper.emitted('update:modelValue')).toContainEqual([0])
    expect((input.element as HTMLInputElement).value).toBe('0')
  })

  it('keeps a leading sign as an editable draft until it becomes numeric', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: 100 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await wrapper.setProps({ modelValue: 200 })
    expect((input.element as HTMLInputElement).value).toBe('200')

    await input.setValue('-')

    expect(wrapper.emitted('update:modelValue')).toContainEqual([undefined])
    await wrapper.setProps({ modelValue: undefined })
    expect((input.element as HTMLInputElement).value).toBe('-')

    await input.setValue('-1')
    expect(wrapper.emitted('update:modelValue')).toContainEqual([-1])
    expect((input.element as HTMLInputElement).value).toBe('-1')
  })

  it('does not leave preserveNumberDraft stuck when modelValue is already undefined', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Bind Port', type: 'number', modelValue: undefined },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    expect((input.element as HTMLInputElement).value).toBe('-')

    await input.setValue('')
    expect((input.element as HTMLInputElement).value).toBe('')

    await wrapper.setProps({ modelValue: 100 })
    expect((input.element as HTMLInputElement).value).toBe('100')

    await wrapper.setProps({ modelValue: undefined })
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('treats whitespace-only input as empty instead of 0', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: 100 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('   ')

    expect(wrapper.emitted('update:modelValue')).toEqual([[undefined]])
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('clears whitespace-only input even when modelValue is already undefined', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: undefined },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('   ')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toEqual([[undefined]])
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('trims surrounding whitespace on valid integer input', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: undefined, min: 1, max: 65535 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue(' 42 ')

    expect(wrapper.emitted('update:modelValue')).toEqual([[42]])
    expect((input.element as HTMLInputElement).value).toBe('42')
  })

  it.each(['Infinity', '-Infinity', '+Infinity', 'NaN', '9'.repeat(400)])(
    'rejects non-finite input %s without emitting',
    async (raw) => {
      const wrapper = mount(ConfigField, {
        props: { label: 'Socket Mark', type: 'number', modelValue: 5, min: 0 },
        global: { stubs },
      })

      const input = wrapper.find('input')
      await input.setValue(raw)
      await nextTick()

      expect(wrapper.emitted('update:modelValue')).toBeUndefined()
      expect((input.element as HTMLInputElement).value).toBe('5')
    },
  )

  it.each(['1.', '1.0', '1.5', '.', '1e5', '0x10', 'abc'])(
    'rejects non-integer input %s and restores previous value',
    async (raw) => {
      const wrapper = mount(ConfigField, {
        props: { label: 'Port', type: 'number', modelValue: 1 },
        global: { stubs },
      })

      const input = wrapper.find('input')
      await input.setValue(raw)
      await nextTick()

      expect(wrapper.emitted('update:modelValue')).toBeUndefined()
      expect((input.element as HTMLInputElement).value).toBe('1')
    },
  )

  it('preserves leading minus draft when user types invalid "-."', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Bind Port', type: 'number', modelValue: undefined },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    expect((input.element as HTMLInputElement).value).toBe('-')

    await input.setValue('-.')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toEqual([[undefined]])
    expect((input.element as HTMLInputElement).value).toBe('-')
  })

  it('normalizes -0 and +0 to positive zero', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Remote Port', type: 'number', modelValue: undefined, min: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-0')

    const emitted = wrapper.emitted('update:modelValue')
    expect(emitted).toHaveLength(1)
    expect(Object.is(emitted![0][0], 0)).toBe(true)
    expect((input.element as HTMLInputElement).value).toBe('0')
  })

  it('resyncs DOM input when clamped value matches existing modelValue', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: 0, min: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-5')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toEqual([[0]])
    expect((input.element as HTMLInputElement).value).toBe('0')
  })

  it('renders an empty readonly field as a disabled placeholder', () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Secret', readonly: true, modelValue: '' },
      global: { stubs },
    })

    const input = wrapper.find('input').element as HTMLInputElement
    expect(wrapper.find('.config-field-label').text()).toBe('Secret')
    expect(input.disabled).toBe(true)
    expect(input.value).toBe('—')
  })

  it('renders numeric 0 in readonly mode instead of placeholder dash', () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Remote Port', type: 'number', readonly: true, modelValue: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input').element as HTMLInputElement
    expect(input.disabled).toBe(true)
    expect(input.value).toBe('0')
  })

  it.each([
    String(Number.MAX_SAFE_INTEGER + 1),
    '9'.repeat(21),
    String(Number.MIN_SAFE_INTEGER - 1),
  ])(
    'rejects unsafe integer %s without precision loss or scientific notation',
    async (raw) => {
      const wrapper = mount(ConfigField, {
        props: { label: 'Timeout (s)', type: 'number', modelValue: 5 },
        global: { stubs },
      })

      const input = wrapper.find('input')
      await input.setValue(raw)
      await nextTick()

      expect(wrapper.emitted('update:modelValue')).toBeUndefined()
      expect((input.element as HTMLInputElement).value).toBe('5')
    },
  )

  it('accepts Number.MAX_SAFE_INTEGER and Number.MIN_SAFE_INTEGER', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Bind Port', type: 'number', modelValue: undefined },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue(String(Number.MAX_SAFE_INTEGER))
    expect(wrapper.emitted('update:modelValue')).toContainEqual([Number.MAX_SAFE_INTEGER])

    await input.setValue(String(Number.MIN_SAFE_INTEGER))
    expect(wrapper.emitted('update:modelValue')).toContainEqual([Number.MIN_SAFE_INTEGER])
  })

  it('clamps finite large integer to max when max is within safe integer range', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Local Port', type: 'number', modelValue: undefined, min: 0, max: 65535 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('9'.repeat(20))

    expect(wrapper.emitted('update:modelValue')).toEqual([[65535]])
    expect((input.element as HTMLInputElement).value).toBe('65535')
  })

  it('resyncs real Element Plus ElInput DOM value on rejected and clamped-equal inputs', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: 0, min: 0 },
      global: {
        components: { ElFormItem, ElInput },
        stubs: {
          KeyValueEditor: stubs.KeyValueEditor,
          StringListEditor: stubs.StringListEditor,
          PopoverMenu: stubs.PopoverMenu,
          PopoverMenuItem: stubs.PopoverMenuItem,
        },
      },
    })

    const input = wrapper.find('input')
    expect((input.element as HTMLInputElement).value).toBe('0')

    await input.setValue('1.')
    await nextTick()
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect((input.element as HTMLInputElement).value).toBe('0')

    await input.setValue('-5')
    await nextTick()
    expect(wrapper.emitted('update:modelValue')).toEqual([[0]])
    expect((input.element as HTMLInputElement).value).toBe('0')

    await input.setValue('   ')
    await nextTick()
    expect(wrapper.emitted('update:modelValue')).toEqual([[0], [undefined]])
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('rejects leading "-" when min >= 0 without emitting', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: undefined, min: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('restores previous modelValue when "-" is entered with min >= 0', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: 5, min: 0 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect((input.element as HTMLInputElement).value).toBe('5')
  })

  it('allows leading "-" draft when min < 0 and "+" draft when min >= 0', async () => {
    const negWrapper = mount(ConfigField, {
      props: { label: 'Offset', type: 'number', modelValue: undefined, min: -10 },
      global: { stubs },
    })
    const negInput = negWrapper.find('input')
    await negInput.setValue('-')
    expect((negInput.element as HTMLInputElement).value).toBe('-')

    const posWrapper = mount(ConfigField, {
      props: { label: 'Socket Mark', type: 'number', modelValue: undefined, min: 0 },
      global: { stubs },
    })
    const posInput = posWrapper.find('input')
    await posInput.setValue('+')
    expect((posInput.element as HTMLInputElement).value).toBe('+')
  })

  it.each(['-', '+'])(
    'clears dangling "%s" draft on blur when modelValue is undefined',
    async (sign) => {
      const wrapper = mount(ConfigField, {
        props: { label: 'Port', type: 'number', modelValue: 100 },
        global: { stubs },
      })

      const input = wrapper.find('input')
      await input.setValue(sign)
      await wrapper.setProps({ modelValue: undefined })
      expect((input.element as HTMLInputElement).value).toBe(sign)

      await input.trigger('blur')
      await nextTick()

      expect((input.element as HTMLInputElement).value).toBe('')
    },
  )

  it('clears dangling "-" draft on blur with real Element Plus ElInput', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Port', type: 'number', modelValue: undefined },
      global: {
        components: { ElFormItem, ElInput },
        stubs: {
          KeyValueEditor: stubs.KeyValueEditor,
          StringListEditor: stubs.StringListEditor,
          PopoverMenu: stubs.PopoverMenu,
          PopoverMenuItem: stubs.PopoverMenuItem,
        },
      },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    expect((input.element as HTMLInputElement).value).toBe('-')

    await input.trigger('blur')
    await nextTick()

    expect((input.element as HTMLInputElement).value).toBe('')
  })

  it('does not alter valid numeric value on blur', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Offset', type: 'number', modelValue: undefined },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-42')
    await wrapper.setProps({ modelValue: -42 })
    await input.trigger('blur')
    await nextTick()

    expect((input.element as HTMLInputElement).value).toBe('-42')
  })

  it('rejects leading "+" when max < 0 without emitting', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Offset', type: 'number', modelValue: -5, max: -1 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('+')
    await nextTick()

    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect((input.element as HTMLInputElement).value).toBe('-5')
  })

  it('clears active "-" draft if min dynamically changes to >= 0', async () => {
    const wrapper = mount(ConfigField, {
      props: { label: 'Offset', type: 'number', modelValue: undefined, min: -10 },
      global: { stubs },
    })

    const input = wrapper.find('input')
    await input.setValue('-')
    expect((input.element as HTMLInputElement).value).toBe('-')

    await wrapper.setProps({ min: 0 })
    await nextTick()

    expect((input.element as HTMLInputElement).value).toBe('')
  })
})
