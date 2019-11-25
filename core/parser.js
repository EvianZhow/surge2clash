const splitByCommas = string => (string || '').split(/,\s*/).map(e => e.trim());

function parseHTTPProxyLine(name, confLine, option = {}) {
  let i = 1;
  const params = splitByCommas(confLine);
  const protocol = 'http';
  const proxyConf = {
    name,
    type: protocol,
    server: params[i++],
    port: parseInt(params[i++], 10)
  };
  if (option.tls) {
    proxyConf.tls = true;
  }

  if (params[i]) {
    proxyConf.username = params[i++];
  }

  if (params[i]) {
    proxyConf.password = params[i++];
  }

  if (params.length > i) {
    for (let {length} = params; i < length; i++) {
      const [key, value] = params[i].split('=');
      // eslint-disable-next-line max-depth
      if (key === 'skip-cert-verify') {
        proxyConf['skip-cert-verify'] = value;
      }
    }
  }

  return proxyConf;
}

function parseSOCKSProxyLine(name, confLine, option = {}) {
  let i = 1;
  const params = splitByCommas(confLine);
  const protocol = 'socks5';

  const proxyConf = {
    name,
    type: protocol,
    server: params[i++],
    port: params[i++]
  };
  if (option.tls) {
    proxyConf.tls = true;
  }

  if (params[i]) {
    proxyConf.username = params[i++];
  }

  if (params[i]) {
    proxyConf.password = params[i++];
  }

  if (params.length > i) {
    for (let {length} = params; i < length; i++) {
      const [key, value] = params[i].split('=');
      // eslint-disable-next-line max-depth
      if (key === 'skip-cert-verify') {
        proxyConf['skip-cert-verify'] = value;
      }
    }
  }

  return proxyConf;
}

function parseCustomProxyLine(name, confLine, option = {}) {
  let i = 1;
  const params = splitByCommas(confLine);
  const protocol = 'ss';
  return {
    name,
    type: protocol,
    server: params[i++],
    port: parseInt(params[i++], 10),
    cipher: params[i++],
    password: params[i++]
  };
}

function parseProxy(surgeConf, options = {}) {
  const proxys = [];
  Object.keys(surgeConf.Proxy).map(k => {
    const e = surgeConf.Proxy[k];
    let proxyConf;
    const option = {};
    switch (splitByCommas(e)[0]) {
      case 'custom':
        proxyConf = parseCustomProxyLine(k, e);
        break;
      case 'https':
        option.tls = true;
      case 'http':
        proxyConf = parseHTTPProxyLine(k, e, option);
        break;
      case 'socks5-tls':
        option.tls = true;
      case 'socks5':
        proxyConf = parseSOCKSProxyLine(k, e, option);
        break;
      default:
        break;
    }

    if (options.stringify) {
      proxys.push(proxyConf);
    } else {
      proxys.push(JSON.stringify(proxyConf));
    }
  });

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

    if (group[0] === 'url-test') {
      each.interval = option.interval || 300;
    }

    const proxies = [];
    for (let i = 1; i < group.length; i++) {
      if (Object.keys(surgeConf.Proxy).includes(group[i]) || // Ref from proxy section
        reservedKeywords.includes(group[i]) || // Ref from reserved keywords
        Object.keys(surgeConf['Proxy Group']).includes(group[i])) { // Ref from previous proxy group
        proxies.push(group[i]);
      } else if (group[i].includes('=')) {
        const [key, val] = group[i].split(/\s*=\s*/);
        each[key] = val;
      }
    }

    each.proxies = proxies;
    proxyGroups.push(each);
  }

  return proxyGroups;
}

module.exports = {
  parseProxy,
  parseProxyGroup
};
