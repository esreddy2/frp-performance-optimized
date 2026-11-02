export const PROXY_TYPES = [
  'tcp',
  'udp',
  'http',
  'https',
  'tcpmux',
  'stcp',
  'sudp',
  'xtcp',
] as const

export type ProxyType = (typeof PROXY_TYPES)[number]

export const VISITOR_TYPES = ['stcp', 'sudp', 'xtcp'] as const

export type VisitorType = (typeof VISITOR_TYPES)[number]
