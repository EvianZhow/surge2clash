/* eslint no-fallthrough: 0 */
const ini = require('js-ini');
const jsYaml = require('js-yaml');
const {parseProxy, parseProxyGroup} = require('./parser');

const isTrue = value => typeof value === 'boolean' ? value : value == 'true';

const defaultClashConf = {
  port: 7890,
  'socks-port': 7891,
  'redir-port': 7892,
  'allow-lan': true,
  mode: 'Rule',
  'log-level': 'info',
  'external-controller': '127.0.0.1:9090',
  secret: ''
};

const defaultDNSConf = {
  enable: true,
  ipv6: false,
  listen: '0.0.0.0:53',
  'enhanced-mode': 'fake-ip',
  nameserver: [
    '119.28.28.28',
    '119.29.29.29',
    '223.5.5.5',
    'tls://dns.rubyfish.cn:853'
  ],
  fallback: [
    'tls://1.0.0.1:853',
    'tls://8.8.4.4:853'
  ]
};

const clashConf = Object.assign({}, defaultClashConf);

// eslint-disable-next-line complexity
function surge2Clash(surgeConfText, query) {
  const surgeConf = ini.parse(surgeConfText, {
    comment: '#',
    autoTyping: false,
    dataSections: ['Rule', 'URL Rewrite', 'Header Rewrite', 'SSID Setting']
  });

  const dns = Object.assign({}, defaultDNSConf, {
    enable: Boolean(query.win),
    nameserver: surgeConf.General['dns-server'].split(/,\s+/).filter(i => i.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) || i.match(/^\w+:\/\//)),
    ipv6: isTrue(surgeConf.General.ipv6)
  });

  clashConf.dns = dns;

  const proxys = parseProxy(surgeConf, {stringify: Boolean(query.win)}) || [];
  const proxyGroups = parseProxyGroup(surgeConf, {stringify: Boolean(query.win)}) || [];

  clashConf.Proxy = proxys;
  clashConf['Proxy Group'] = proxyGroups;

  const extraRules = [];
  if (query.extraRulesData && query.extraRulesData.length > 0) {
    const {extraRulesData: data, charSet = 'utf-8'} = query;
    const buff = Buffer.from(data, 'base64');
    buff.toString(charSet).split('\n').map(e => {
      extraRules.push(e.trim());
    });
  }

  clashConf.Rule = (extraRules.concat(!query.overrideRules ? (surgeConf.Rule || []) : [])).map(i => {
    // Remove unsupported keywords
    return i.replace(/no-resolve|,\s*no-resolve|,\s*force-remote-dns|force-remote-dns|dns-failed|,\s*dns-failed/, '');
  }).map(i => {
    // Remove inline comments
    return i.replace(/\s*\/\/[^;)]*$/, '');
  }).filter(i => !i.startsWith('USER-AGENT') && !i.startsWith('PROCESS-NAME'));

  const allowedQueryOverrides = ['port', 'socks-port', 'redir-port'];

  if (query.port) {
    query.port = parseInt(query.port, 10);
  }

  if (query['socks-port']) {
    query['socks-port'] = parseInt(query['socks-port'], 10);
  }

  if (query['redir-port']) {
    query['redir-port'] = parseInt(query['redir-port'], 10);
  }

  const ret = Object.assign(clashConf, Object.keys(query)
    .filter(key => allowedQueryOverrides.includes(key))
    .reduce((obj, key) => {
      obj[key] = query[key];
      return obj;
    }, {}));
  return (jsYaml.safeDump(ret));
}

module.exports = surge2Clash;
