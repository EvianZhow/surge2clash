import test from 'ava';
const parser = require('../core/parser');

test('Test HTTP Proxy Type Single-Line Parse', t => {
  // ProxyHTTP = http, 1.2.3.4, 443, username, password
  const proxyName = 'ProxyHTTP';
  const singleLine = 'http, 1.2.3.4, 443, username, password';
  const expected = {
    name: 'ProxyHTTP',
    type: 'http',
    server: '1.2.3.4',
    port: 443,
    username: 'username',
    password: 'password'
  };
  t.deepEqual(parser.parseHTTPProxyLine(proxyName, singleLine, {}), expected);
});

test('Test HTTPS Proxy Type Single-Line Parse', t => {
  // ProxyHTTPS = https, 1.2.3.4, 443, username, password
  const proxyName = 'ProxyHTTP';
  const singleLine = 'https, 1.2.3.4, 443, username, password';
  const expected = {
    name: 'ProxyHTTP',
    type: 'http',
    server: '1.2.3.4',
    port: 443,
    tls: true,
    username: 'username',
    password: 'password'
  };
  t.deepEqual(parser.parseHTTPProxyLine(proxyName, singleLine, {tls: true}), expected);
});

test('Test SOCKS Proxy Type Single-Line Parse', t => {
  // ProxySOCKS5 = socks5, 1.2.3.4, 443, username, password
  const proxyName = 'ProxySOCKS5';
  const singleLine = 'socks5, 1.2.3.4, 443, username, password';
  const expected = {
    name: 'ProxySOCKS5',
    type: 'socks5',
    server: '1.2.3.4',
    port: 443,
    username: 'username',
    password: 'password'
  };
  t.deepEqual(parser.parseSOCKSProxyLine(proxyName, singleLine, {}), expected);
});

test('Test SOCKS-TLS Proxy Type Single-Line Parse', t => {
  // ProxySOCKS5TLS = socks5-tls, 1.2.3.4, 443, username, password, skip-cert-verify=true
  const proxyName = 'ProxySOCKS5TLS';
  const singleLine = 'socks5-tls, 1.2.3.4, 443, username, password, skip-cert-verify=true';
  const expected = {
    name: 'ProxySOCKS5TLS',
    type: 'socks5',
    server: '1.2.3.4',
    port: 443,
    tls: true,
    username: 'username',
    password: 'password',
    'skip-cert-verify': 'true'
  };
  t.deepEqual(parser.parseSOCKSProxyLine(proxyName, singleLine, {tls: true}), expected);
});

test('Test Custom Proxy Type Single-Line Parse', t => {
  // ProxySS = custom, 1.2.3.4, 8388, aes-256-cfb, foobar!, https://nssurge.io/shadowsocks/SSEncrypt.module
  const proxyName = 'ProxySS';
  const singleLine = 'custom, 1.2.3.4, 8388, aes-256-cfb, foobar!, https://nssurge.io/shadowsocks/SSEncrypt.module';
  const expected = {
    name: 'ProxySS',
    type: 'ss',
    server: '1.2.3.4',
    port: 8388,
    cipher: 'aes-256-cfb',
    password: 'foobar!'
  };
  t.deepEqual(parser.parseCustomProxyLine(proxyName, singleLine, {}), expected);
});

test('Test Custom Proxy with Obfuscation Type Single-Line Parse', t => {
  // Proxy = custom, server, port, aes-128-gcm, password, http://example.com/SSEncrypt.module,obfs=http,obfs-host=cloudfront.net
  const proxyName = 'ProxySS';
  const singleLine = 'custom, 1.2.3.4, 8388, aes-128-gcm, password, http://example.com/SSEncrypt.module, obfs=http, obfs-host=baidu.net';
  const expected = {
    name: 'ProxySS',
    type: 'ss',
    server: '1.2.3.4',
    port: 8388,
    cipher: 'aes-128-gcm',
    password: 'password',
    plugin: 'obfs',
    'plugin-opts': {
      mode: 'http',
      host: 'baidu.net'
    }
  };
  t.deepEqual(parser.parseCustomProxyLine(proxyName, singleLine, {}), expected);
});

test('Test Custom Proxy with Default Obfuscation Type Single-Line Parse', t => {
  // Proxy = custom, server, port, aes-128-gcm, password, http://example.com/SSEncrypt.module,obfs=http,obfs-host=cloudfront.net
  const proxyName = 'ProxySS';
  const singleLine = 'custom, 1.2.3.4, 8388, aes-128-gcm, password, http://example.com/SSEncrypt.module, obfs=tls';
  const expected = {
    name: 'ProxySS',
    type: 'ss',
    server: '1.2.3.4',
    port: 8388,
    cipher: 'aes-128-gcm',
    password: 'password',
    plugin: 'obfs',
    'plugin-opts': {
      mode: 'tls',
      host: 'cloudfront.net'
    }
  };
  t.deepEqual(parser.parseCustomProxyLine(proxyName, singleLine, {}), expected);
});
