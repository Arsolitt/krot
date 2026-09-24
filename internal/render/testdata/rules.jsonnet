local rulesets = import 'rulesets.jsonnet';

{
  proxyServer(extra=[]):: [
    { protocol: 'dns', action: 'hijack-dns' },
    { rule_set: ['geosite-category-ads-all'], action: 'reject', method: 'drop' },
    { ip_is_private: true, action: 'reject', method: 'drop' },
    { rule_set: rulesets.tags.ruReject, action: 'reject', method: 'drop' },
  ] + extra,

  client():: [
    { inbound: 'tun-in', action: 'resolve', strategy: 'prefer_ipv4' },
    { inbound: 'tun-in', action: 'sniff', timeout: '2s' },
    { protocol: 'dns', action: 'hijack-dns' },
    { rule_set: ['geosite-category-ads-all'], action: 'reject', method: 'drop' },
    { ip_is_private: true, outbound: 'direct' },
    { rule_set: rulesets.tags.ruDirect, outbound: 'direct' },
    { rule_set: rulesets.tags.intlProxy, outbound: 'proxy' },
  ],

  rejectDomain(suffix):: { domain_suffix: [suffix], action: 'reject', method: 'drop' },
}
