// Rule-sets are mirrored into a single repo (Arsolitt/sing-box-rules, rule-set
// branch) that exists on two backends with identical filenames:
//   - GitHub  — public CDN, reachable from anywhere (default source)
//   - GitLab  — self-hosted at gitlab.example.com, only worth using from
//               hosts that can reach it directly (home clients)
// Tags are kept identical to the upstream naming because they are referenced by
// the routing rules; only the download base URL and detour vary per caller.
local githubBase = 'https://raw.githubusercontent.com/Arsolitt/sing-box-rules/rule-set/';
local gitlabBase = 'https://gitlab.example.com/Arsolitt/sing-box-rules/-/raw/rule-set/';

local rule(tag, filename, detour, base) = {
  type: 'remote',
  tag: tag,
  format: 'binary',
  url: base + filename + '.srs',
  download_detour: detour,
  update_interval: '24h',
};

local sagernet(name, detour, base) = rule('geosite-' + name, 'sagernet-geosite-' + name, detour, base);

local geoip(name, detour, base) = rule('geoip-' + name, 'sagernet-geoip-' + name, detour, base);

local itdog(tag, detour, base, filename=null) =
  rule(tag, 'itdog-' + (if filename != null then filename else tag), detour, base);

local arsolitt(name, detour, base) = rule(name, name, detour, base);

{
  // Download bases exposed so call sites can opt into the self-hosted mirror,
  // e.g. rulesets.client(base=rulesets.gitlab).
  github:: githubBase,
  gitlab:: gitlabBase,

  ads(detour, base=githubBase):: [sagernet('category-ads-all', detour, base)],

  ruGeosite(detour, base=githubBase):: [
    sagernet('category-ru', detour, base),
    sagernet('category-bank-ru', detour, base),
    sagernet('category-ecommerce-ru', detour, base),
    sagernet('category-entertainment-ru', detour, base),
    sagernet('category-gov-ru', detour, base),
    sagernet('category-media-ru', detour, base),
    sagernet('category-travel-ru', detour, base),
    sagernet('dzen', detour, base),
    sagernet('ozon', detour, base),
    sagernet('mailru', detour, base),
    sagernet('mailru-group', detour, base),
  ],

  ruCommon(detour, base=githubBase)::
    self.ads(detour, base)
    + self.ruGeosite(detour, base)
    + [geoip('ru', detour, base)]
    + [itdog('russia-outside', detour, base, 'russia_outside')],

  proxyServer(detour='direct', base=githubBase)::
    self.ruCommon(detour, base),

  googleSuite(detour, base=githubBase):: [
    sagernet('google', detour, base),
    sagernet('youtube', detour, base),
    sagernet('openai', detour, base),
  ],

  intlApps(detour, base=githubBase):: [
    itdog('russia-inside', detour, base, 'russia_inside'),
    itdog('geoblock', detour, base),
    itdog('telegram', detour, base),
    itdog('discord', detour, base),
    itdog('meta', detour, base),
    itdog('twitter', detour, base),
    itdog('youtube', detour, base),
    itdog('tiktok', detour, base),
    itdog('news', detour, base),
    itdog('cloudflare', detour, base),
    itdog('cloudfront', detour, base),
    itdog('hetzner', detour, base),
    itdog('ovh', detour, base),
    itdog('digitalocean', detour, base),
    itdog('google-meet', detour, base, 'google_meet'),
    itdog('roblox', detour, base),
  ],

  cdnProviders(detour, base=githubBase):: [
    arsolitt('akamai', detour, base),
    arsolitt('amazon', detour, base),
    arsolitt('cdn77', detour, base),
    arsolitt('cloudflare-full', detour, base),
    arsolitt('community-v1', detour, base),
    arsolitt('fastly', detour, base),
    arsolitt('github', detour, base),
    arsolitt('haproxy', detour, base),
    arsolitt('hetzner-full', detour, base),
    arsolitt('linode', detour, base),
    arsolitt('microsoft', detour, base),
    arsolitt('oracle', detour, base),
    arsolitt('shopify', detour, base),
  ],

  aiDev(detour, base=githubBase):: [
    sagernet('category-dev', detour, base),
    sagernet('anthropic', detour, base),
    sagernet('deepseek', detour, base),
    sagernet('groq', detour, base),
  ],

  client(detour='direct', base=githubBase)::
    self.proxyServer(detour, base)
    + self.googleSuite(detour, base)
    + self.intlApps(detour, base)
    + self.cdnProviders(detour, base)
    + self.aiDev(detour, base),

  tags:: {
    local ruBase = [
      'geoip-ru',
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
      'russia-outside',
    ],

    ruReject: ruBase,
    ruDirect: ruBase + ['direct-v1'],

    intlProxy: [
      'russia-inside',
      'geoblock',
      'telegram',
      'discord',
      'meta',
      'twitter',
      'youtube',
      'tiktok',
      'news',
      'cloudflare',
      'cloudfront',
      'hetzner',
      'hetzner-full',
      'ovh',
      'digitalocean',
      'google-meet',
      'roblox',
      'fastly',
      'cdn77',
      'linode',
      'amazon',
      'microsoft',
      'github',
      'cloudflare-full',
      'community-v1',
      'proxy-v1',
      'geosite-openai',
      'geosite-google',
      'geosite-youtube',
      'akamai',
      'haproxy',
      'oracle',
      'geosite-category-dev',
      'geosite-anthropic',
      'geosite-deepseek',
      'geosite-groq',
      'shopify',
    ],
  },
}
