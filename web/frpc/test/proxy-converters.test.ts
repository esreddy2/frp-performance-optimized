import { describe, expect, it } from 'vitest'
import {
  createDefaultProxyForm,
  createDefaultVisitorForm,
} from '../src/types/proxy-form'
import {
  formToStoreProxy,
  formToStoreVisitor,
  storeProxyToForm,
} from '../src/types/proxy-converters'

describe('proxy converters', () => {
  it('serializes only configured proxy fields into the typed store block', () => {
    const form = createDefaultProxyForm()
    Object.assign(form, {
      name: 'web',
      type: 'http',
      enabled: false,
      localIP: '10.0.0.8',
      localPort: 8080,
      useEncryption: true,
      customDomains: ['example.com', ''],
      locations: ['/api', ''],
      metadatas: [{ key: 'team', value: 'edge' }],
    })

    expect(formToStoreProxy(form)).toEqual({
      name: 'web',
      type: 'http',
      http: {
        enabled: false,
        localIP: '10.0.0.8',
        localPort: 8080,
        transport: { useEncryption: true },
        metadatas: { team: 'edge' },
        customDomains: ['example.com'],
        locations: ['/api'],
      },
    })
  })

  it('round-trips store values while applying form defaults', () => {
    const form = storeProxyToForm({
      name: 'tcp-proxy',
      type: 'tcp',
      tcp: {
        localPort: 9000,
        customDomains: 'unused-for-tcp',
        enabled: false,
        metadatas: { owner: 'platform' },
      },
    })

    expect(form).toMatchObject({
      name: 'tcp-proxy',
      type: 'tcp',
      enabled: false,
      localIP: '127.0.0.1',
      localPort: 9000,
      metadatas: [{ key: 'owner', value: 'platform' }],
      multiplexer: 'httpconnect',
    })
  })

  it.each(['stcp', 'xtcp'] as const)(
    'serializes virtual_net for %s visitors',
    (type) => {
      const form = createDefaultVisitorForm()
      Object.assign(form, {
        name: 'visitor',
        type,
        pluginType: 'virtual_net',
        pluginDestinationIP: ' 192.0.2.10 ',
        bindPort: 6000,
      })

      expect(formToStoreVisitor(form)[type]).toMatchObject({
        plugin: { type: 'virtual_net', destinationIP: '192.0.2.10' },
        bindPort: 6000,
      })
    },
  )

  it('does not serialize virtual_net for SUDP visitors', () => {
    const form = createDefaultVisitorForm()
    Object.assign(form, {
      name: 'visitor',
      type: 'sudp',
      pluginType: 'virtual_net',
      pluginDestinationIP: '192.0.2.10',
      bindPort: 6000,
    })

    expect(formToStoreVisitor(form).sudp).toEqual({ bindPort: 6000 })
  })

  it.each([
    ['udp', 'v1'],
    ['udp', 'v2'],
    ['sudp', 'v1'],
    ['sudp', 'v2'],
  ] as const)(
    'serializes proxyProtocolMode for %s proxies with %s proxyProtocol',
    (type, proxyProtocolVersion) => {
      const form = createDefaultProxyForm()
      Object.assign(form, {
        name: `${type}-proxy`,
        type,
        localPort: 5353,
        proxyProtocolVersion,
        proxyProtocolMode: 'per-packet',
      })

      expect(formToStoreProxy(form)[type]).toMatchObject({
        transport: {
          proxyProtocol: proxyProtocolVersion,
          proxyProtocolMode: 'per-packet',
        },
      })
    },
  )

  it.each(['tcp', 'http', 'https', 'tcpmux', 'stcp', 'xtcp'] as const)(
    'does not serialize proxyProtocolMode for %s proxies',
    (type) => {
      const form = createDefaultProxyForm()
      Object.assign(form, {
        name: `${type}-proxy`,
        type,
        localPort: 8080,
        proxyProtocolVersion: 'v2',
        proxyProtocolMode: 'per-packet',
      })

      expect(formToStoreProxy(form)[type]).toMatchObject({
        transport: {
          proxyProtocol: 'v2',
        },
      })
      expect(formToStoreProxy(form)[type]?.transport).not.toHaveProperty(
        'proxyProtocolMode',
      )
    },
  )

  it('does not serialize proxyProtocolMode when proxyProtocolVersion is tproxy or empty', () => {
    const tproxyForm = createDefaultProxyForm()
    Object.assign(tproxyForm, {
      name: 'udp-tproxy',
      type: 'udp',
      localPort: 5353,
      proxyProtocolVersion: 'tproxy',
      proxyProtocolMode: 'per-packet',
      socketMark: 2,
    })

    expect(formToStoreProxy(tproxyForm).udp).toMatchObject({
      transport: {
        proxyProtocol: 'tproxy',
        socketMark: 2,
      },
    })
    expect(formToStoreProxy(tproxyForm).udp?.transport).not.toHaveProperty(
      'proxyProtocolMode',
    )

    const emptyForm = createDefaultProxyForm()
    Object.assign(emptyForm, {
      name: 'udp-empty-pp',
      type: 'udp',
      localPort: 5353,
      proxyProtocolVersion: '',
      proxyProtocolMode: 'per-packet',
    })

    expect(formToStoreProxy(emptyForm).udp?.transport).toBeUndefined()
  })

  it.each([
    ['udp', 'v1'],
    ['udp', 'v2'],
    ['sudp', 'v1'],
    ['sudp', 'v2'],
  ] as const)(
    'preserves proxyProtocolMode in storeProxyToForm for %s proxies with %s proxyProtocol',
    (type, proxyProtocol) => {
      const form = storeProxyToForm({
        name: `${type}-proxy`,
        type,
        [type]: {
          localPort: 5353,
          transport: {
            proxyProtocol,
            proxyProtocolMode: 'per-packet',
          },
        },
      })

      expect(form.proxyProtocolVersion).toBe(proxyProtocol)
      expect(form.proxyProtocolMode).toBe('per-packet')
    },
  )

  it.each(['tcp', 'http', 'https', 'tcpmux', 'stcp', 'xtcp'] as const)(
    'clears proxyProtocolMode in storeProxyToForm for %s proxies',
    (type) => {
      const form = storeProxyToForm({
        name: `${type}-proxy`,
        type,
        [type]: {
          localPort: 8080,
          transport: {
            proxyProtocol: 'v2',
            proxyProtocolMode: 'per-packet',
          },
        },
      })

      expect(form.proxyProtocolVersion).toBe('v2')
      expect(form.proxyProtocolMode).toBe('')
    },
  )

  it.each(['tproxy', ''] as const)(
    'clears proxyProtocolMode in storeProxyToForm for udp proxies when proxyProtocol is %s',
    (proxyProtocol) => {
      const form = storeProxyToForm({
        name: 'udp-proxy',
        type: 'udp',
        udp: {
          localPort: 5353,
          transport: {
            ...(proxyProtocol ? { proxyProtocol } : {}),
            proxyProtocolMode: 'per-packet',
          },
        },
      })

      expect(form.proxyProtocolVersion).toBe(proxyProtocol)
      expect(form.proxyProtocolMode).toBe('')
    },
  )

  it.each([0, 2])(
    'preserves socketMark=%s in storeProxyToForm when proxyProtocol is tproxy',
    (socketMark) => {
      const form = storeProxyToForm({
        name: 'tcp-tproxy',
        type: 'tcp',
        tcp: {
          localPort: 8080,
          transport: {
            proxyProtocol: 'tproxy',
            socketMark,
          },
        },
      })

      expect(form.proxyProtocolVersion).toBe('tproxy')
      expect(form.socketMark).toBe(socketMark)
    },
  )

  it.each(['v1', 'v2', ''] as const)(
    'clears socketMark in storeProxyToForm when proxyProtocol is %s',
    (proxyProtocol) => {
      const form = storeProxyToForm({
        name: 'tcp-proxy',
        type: 'tcp',
        tcp: {
          localPort: 8080,
          transport: {
            ...(proxyProtocol ? { proxyProtocol } : {}),
            socketMark: 2,
          },
        },
      })

      expect(form.proxyProtocolVersion).toBe(proxyProtocol)
      expect(form.socketMark).toBeUndefined()
    },
  )

  it('does not serialize socketMark when proxyProtocolVersion is not tproxy', () => {
    const v2Form = createDefaultProxyForm()
    Object.assign(v2Form, {
      name: 'tcp-v2',
      type: 'tcp',
      localPort: 8080,
      proxyProtocolVersion: 'v2',
      socketMark: 2,
    })

    expect(formToStoreProxy(v2Form).tcp?.transport).toEqual({
      proxyProtocol: 'v2',
    })

    const emptyForm = createDefaultProxyForm()
    Object.assign(emptyForm, {
      name: 'tcp-empty',
      type: 'tcp',
      localPort: 8080,
      proxyProtocolVersion: '',
      socketMark: 2,
    })

    expect(formToStoreProxy(emptyForm).tcp?.transport).toBeUndefined()
  })
})
