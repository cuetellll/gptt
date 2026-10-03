import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import ts from 'typescript';

async function sourceModule(name, replacements = {}) {
  const input = await fs.readFile(new URL(`../src/${name}.ts`, import.meta.url), 'utf8');
  let code = ts.transpileModule(input, {
    compilerOptions: { target: ts.ScriptTarget.ES2021, module: ts.ModuleKind.ESNext },
  }).outputText;
  for (const [from, to] of Object.entries(replacements)) code = code.replaceAll(from, to);
  return `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
}

const configURL = await sourceModule('config');
const { buildAetherConfig, buildConfig, buildTestConfig } = await import(
  await sourceModule('singbox', { "'./config'": JSON.stringify(configURL), '"./config"': JSON.stringify(configURL) })
);
const { parseLinks, decodeSubscription } = await import(await sourceModule('parser'));
const uri = 'vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#Test';
const node = parseLinks([uri]).nodes[0];

// CI additionally validates these fixtures with the real Windows sing-box binary.
if (process.env.MAHYAR_CONFIG_OUTPUT) {
  const dir = process.env.MAHYAR_CONFIG_OUTPUT;
  await fs.mkdir(dir, { recursive: true });
  for (const mode of ['tun', 'proxy']) {
    await fs.writeFile(`${dir}/model1-${mode}.json`, JSON.stringify(buildConfig(node, mode, 12334)));
    await fs.writeFile(`${dir}/model2-${mode}.json`, JSON.stringify(buildAetherConfig(mode, 12334, 1819)));
  }
}

test('model 1 preserves the selected subscription outbound', () => {
  assert.ok(node);
  const c = buildConfig(node, 'proxy', 12334);
  assert.equal(c.outbounds[0].type, 'vless');
  assert.equal(c.outbounds[0].server, 'example.com');
  assert.equal(c.route.final, 'proxy');
});

test('model 2 chains both connection modes into Aether SOCKS5', () => {
  for (const mode of ['tun', 'proxy']) {
    const c = buildAetherConfig(mode, 12334, 1819);
    assert.deepEqual(c.outbounds[0], {
      type: 'socks', server: '127.0.0.1', server_port: 1819, version: '5', tag: 'proxy',
    });
    assert.equal(c.inbounds.find((i) => i.type === 'mixed').listen, '127.0.0.1');
    assert.equal(c.inbounds.find((i) => i.type === 'mixed').listen_port, 12334);
    assert.equal(c.experimental.clash_api.external_controller, '127.0.0.1:12335');
  }
});

test('Tunnel Mode has automatic strict routing; Proxy Mode has no TUN', () => {
  const tunnel = buildAetherConfig('tun', 12334, 1819);
  const inbound = tunnel.inbounds.find((i) => i.type === 'tun');
  assert.equal(inbound.auto_route, true);
  assert.equal(inbound.strict_route, true);
  assert.equal(buildAetherConfig('proxy', 12334, 1819).inbounds.some((i) => i.type === 'tun'), false);
});

test('Aether bypass precedes all TUN rules to prevent a recursive tunnel', () => {
  const c = buildAetherConfig('tun', 12334, 1819);
  assert.equal(c.route.rules[0].outbound, 'direct');
  assert.ok(c.route.rules[0].process_name.includes('aether.exe'));
  assert.equal(c.route.auto_detect_interface, true);
});

test('application DNS travels through the model-2 outbound', () => {
  const c = buildAetherConfig('tun', 12334, 1819);
  assert.equal(c.dns.servers.find((s) => s.tag === 'dns-remote').detour, 'proxy');
  assert.ok(c.route.rules.some((r) => r.action === 'hijack-dns'));
});

test('real-delay test tags match the backend API', () => {
  assert.deepEqual(buildTestConfig([node, node]).outbounds.map((o) => o.tag), ['n0', 'n1', 'direct']);
});

test('plain and base64 subscriptions still parse', () => {
  assert.equal(parseLinks(decodeSubscription(uri)).nodes.length, 1);
  assert.equal(parseLinks(decodeSubscription(Buffer.from(uri).toString('base64'))).nodes.length, 1);
});

test('generated connection configs round-trip through JSON', () => {
  for (const mode of ['tun', 'proxy']) {
    const c = buildAetherConfig(mode, 12334, 1819);
    assert.deepEqual(JSON.parse(JSON.stringify(c)), c);
  }
});
