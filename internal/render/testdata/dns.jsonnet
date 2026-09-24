local ruDomainRuleSets = [
  'geosite-category-bank-ru',
  'geosite-category-ecommerce-ru',
  'geosite-category-entertainment-ru',
  'geosite-category-gov-ru',
  'geosite-category-media-ru',
  'geosite-category-ru',
  'geosite-category-travel-ru',
  'geosite-dzen',
  'geosite-ozon',
  'geosite-mailru',
  'geosite-mailru-group',
];

{
  proxyServer():: {
    servers: [
      { type: 'local', tag: 'dns-local' },
      { type: 'tls', tag: 'dns-remote', server: '8.8.8.8', server_port: 853, detour: 'direct' },
    ],
    rules: [
      { rule_set: ['geosite-category-ru'], action: 'route', server: 'dns-local' },
    ],
    final: 'dns-remote',
    strategy: 'prefer_ipv4',
  },

  client(final='dns-ru', cache_capacity=null, extraRuleSets=[])::
    {
      servers: [
        { type: 'tls', tag: 'dns-ru', server: '77.88.8.8', server_port: 853, detour: 'direct' },
        { type: 'tls', tag: 'dns-intl', server: '8.8.8.8', server_port: 853, detour: 'proxy' },
      ],
      rules: [
        { rule_set: ruDomainRuleSets + extraRuleSets, action: 'route', server: 'dns-ru' },
      ],
      final: final,
      strategy: 'prefer_ipv4',
    }
    + (if cache_capacity != null then { cache_capacity: cache_capacity } else {}),
}
