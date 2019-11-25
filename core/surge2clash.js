/* eslint no-fallthrough: 0 */
const ini = require('js-ini');
const jsYaml = require('js-yaml');

const splitByCommas = string => (string || "").split(/,\s*/).map(e => e.trim());
const isTrue = value => typeof value === 'boolean' ? value : value == 'true';

const defaultClashConf = {
  port: 7890,
  'socks-port': 1080,
  'redir-port':7892,
  'allow-lan': true,
  mode: 'Rule',
  'log-level': 'info',
  'external-controller': '127.0.0.1:9090',
  secret: ''
}

const clashConf = Object.assign({}, defaultClashConf);

function parseProxy(surgeConf, options = {}) {
  const proxys = [];
  for (const name of Object.keys(surgeConf.Proxy)) {
    const proxy = splitByCommas(surgeConf.Proxy[name]);
    let tls = false;
    let proxyConf;
    let protocol;
    let i = 1;
    // eslint-disable-next-line default-case
    switch (proxy[0]) {
      case 'custom':
        protocol = 'ss';
        proxys.push({
          name,
          type: protocol,
          server: proxy[i++],
          port: parseInt(proxy[i++], 10),
          cipher: proxy[i++],
          password: proxy[i++]
        });
        break;
      case 'https':
        protocol = 'http';
        tls = true;
      case 'http':
        protocol = 'http';
        proxyConf = {
          name,
          type: protocol,
          server: proxy[i++],
          port: parseInt(proxy[i++], 10)
        };
        if (tls) {
          proxyConf.tls = true;
        }

        if (proxy[i]) {
          proxyConf.username = proxy[i++];
        }

        if (proxy[i]) {
          proxyConf.password = proxy[i++];
        }

        if (proxy.length > i) {
          for (let {length} = proxy; i < length; i++) {
            const [key, value] = proxy[i].split('=');
            // eslint-disable-next-line max-depth
            if (key === 'skip-cert-verify') {
              proxyConf['skip-cert-verify'] = value;
            }
          }
        }

        if (options.win) {
          proxys.push(proxyConf);
        } else {
          proxys.push(JSON.stringify(proxyConf));
        }

        break;
      case 'socks5-tls':
        protocol = 'socks5';
        tls = true;
      case 'socks5':
        protocol = 'socks5';
        proxyConf = {
          name,
          type: protocol,
          server: proxy[i++],
          port: proxy[i++]
        };
        if (tls) {
          proxyConf.tls = true;
        }

        if (proxy[i]) {
          proxyConf.username = proxy[i++];
        }

        if (proxy[i]) {
          proxyConf.password = proxy[i++];
        }

        if (proxy.length > i) {
          for (let {length} = proxy; i < length; i++) {
            const [key, value] = proxy[i].split('=');
            // eslint-disable-next-line max-depth
            if (key === 'skip-cert-verify') {
              proxyConf['skip-cert-verify'] = value;
            }
          }
        }

        if (options.win) {
          proxys.push(proxyConf);
        } else {
          proxys.push(JSON.stringify(proxyConf));
        }
    }
  }
  return proxys;
}

function parseProxyGroup(surgeConf, option = {}) {
  const proxyGroups = [];
  const reservedKeywords = ['DIRECT'];
  
  for (const name of Object.keys(surgeConf['Proxy Group'])) {
    const group = splitByCommas(surgeConf['Proxy Group'][name]);
    const each = {
      name,
      type: group[0]
    };
    const proxies = [];
    for (let i = 1; i < group.length; i++) {
      if (Object.keys(surgeConf.Proxy).includes(group[i]) || // ref from proxy section
        reservedKeywords.includes(group[i]) || // ref from reserved keywords
        Object.keys(surgeConf['Proxy Group']).includes(group[i])) { // ref from previous proxy group
        proxies.push(group[i]);
      } else if (group[i].indexOf('=') !== -1) {
        const [key, val] = group[i].split(/\s*=\s*/);
        each[key] = val;
      }
    }

    each.proxies = proxies;
    proxyGroups.push(each);
  }
  return proxyGroups;
}

// eslint-disable-next-line complexity
function surge2Clash(surgeConfText, query) {
  const surgeConf = ini.parse(surgeConfText, {
    comment: '#',
    autoTyping: false,
    dataSections: ['Rule', 'URL Rewrite', 'Header Rewrite', 'SSID Setting'],
  });

  const dns = {
    enable: !!query.dns,
    listen: '0.0.0.0:53',
    fallback: '8.8.8.8'
  };

  dns.nameserver = surgeConf.General['dns-server'].split(/,\s+/).filter(i => i.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) || i.match(/^\w+:\/\//));
  dns.ipv6 = isTrue(surgeConf.General.ipv6);
  if(!query.win) {
    clashConf.dns = dns;
  }

  const proxys = parseProxy(surgeConf, query) || [];
  const proxyGroups = parseProxyGroup(surgeConf, query) || [];

  clashConf.Proxy = proxys;
  clashConf['Proxy Group'] = proxyGroups;

  clashConf.Rule = (surgeConf.Rule || []).map(i => {
    // remove unsupported keywords
    return i.replace(/no-resolve|,\s*no-resolve|,\s*force-remote-dns|force-remote-dns|dns-failed|,\s*dns-failed/, '');
  }).map(i => {
    // remove inline comments
    return i.replace(/\s*\/\/[^;)]*$/, '');
  }).filter(i => !i.startsWith('USER-AGENT') && !i.startsWith('PROCESS-NAME'));

  delete query.win;
  delete query.charSet;
  delete query.data;
  delete query.url;

  if (query.port) {
    query.port = parseInt(query.port, 10);
  }

  if (query['socks-port']) {
    query.port = parseInt(query['socks-port'], 10);
  }

  if (query['redir-port']) {
    query.port = parseInt(query['redir-port'], 10);
  }

  const ret = Object.assign(clashConf, query);
  return (jsYaml.safeDump(ret));
}

module.exports = surge2Clash;
