import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

// ==============================================================================
// --- LÓGICA DE DECRIPTOGRAFIA JUNIPER TYPE 9 (Convertida para TypeScript) ---
// ==============================================================================

const MAGIC = "$9$";
const FAMILY = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"];
const EXTRA: { [key: string]: number } = {};
const NUM_ALPHA: string[] = [];
const ALPHA_NUM: { [key: string]: number } = {};

// Initialize lookup tables
FAMILY.forEach((familyItem, i) => {
  familyItem.split('').forEach(char => {
    EXTRA[char] = 3 - i;
  });
});

FAMILY.forEach(familyItem => {
  NUM_ALPHA.push(...familyItem.split(''));
});

NUM_ALPHA.forEach((char, i) => {
  ALPHA_NUM[char] = i;
});

const ENCODING = [
  [1, 4, 32], [1, 16, 32], [1, 8, 32], [1, 64], [1, 32], [1, 4, 16, 128], [1, 32, 64]
];

function nibble(charRef: string, length: number): [string, string] {
  const nib = charRef.slice(0, length);
  const rest = charRef.slice(length);
  if (nib.length !== length) {
    throw new Error("String de entrada inesperadamente curta.");
  }
  return [nib, rest];
}

function gap(c1: string, c2: string): number {
  return (ALPHA_NUM[c2] - ALPHA_NUM[c1]) % NUM_ALPHA.length - 1;
}

function gapDecode(gaps: number[], decTable: number[]): string {
  const sum = gaps.reduce((acc, g, i) => acc + g * decTable[i], 0);
  return String.fromCharCode(sum % 256);
}

function juniperDecrypt(encryptedPass: string): string {
  if (!encryptedPass.startsWith(MAGIC)) {
    throw new Error(`Não é uma senha type 9 (não inicia com '${MAGIC}').`);
  }
  
  let chars = encryptedPass.slice(MAGIC.length);
  const [first, remainingAfterFirst] = nibble(chars, 1);
  chars = remainingAfterFirst;
  
  const [, remainingAfterExtra] = nibble(chars, EXTRA[first]);
  chars = remainingAfterExtra;
  
  let prev = first;
  let decryptedText = "";
  
  while (chars.length > 0) {
    const decodeTable = ENCODING[decryptedText.length % ENCODING.length];
    const [nibbleChars, remainingChars] = nibble(chars, decodeTable.length);
    chars = remainingChars;
    
    const gaps: number[] = [];
    for (const char of nibbleChars) {
      const g = gap(prev, char);
      prev = char;
      gaps.push(g);
    }
    
    decryptedText += gapDecode(gaps, decodeTable);
  }
  
  return decryptedText;
}

// ==============================================================================
// --- FUNÇÕES AUXILIARES ---
// ==============================================================================

function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_ -]/g, '_');
}

function quoteIfNeeded(name: string): string {
  return name.includes(' ') ? `"${name}"` : name;
}

function analyzePskStrength(password: string): string[] {
  const weaknesses: string[] = [];
  
  if (password.length < 14) {
    weaknesses.push("comprimento curto (menor que 14 caracteres)");
  }
  if (!/[a-z]/.test(password)) {
    weaknesses.push("falta de letras minúsculas");
  }
  if (!/[A-Z]/.test(password)) {
    weaknesses.push("falta de letras maiúsculas");
  }
  if (!/[0-9]/.test(password)) {
    weaknesses.push("falta de números");
  }
  if (!/[^a-zA-Z0-9]/.test(password)) {
    weaknesses.push("falta de caracteres especiais");
  }
  
  return weaknesses;
}

// ==============================================================================
// --- TIPOS E INTERFACES ---
// ==============================================================================

interface IkeProposal {
  auth?: string;
  enc?: string;
  dh?: string;
  lifetime?: string;
}

interface IkePolicy {
  encrypted_psk?: string;
  mode?: string;
  proposal?: string;
}

interface IkeGateway {
  policy?: string;
  peer_ip?: string;
  ext_if?: string;
  version?: string;
}

interface IpsecProposal {
  auth?: string;
  enc?: string;
  lifetime?: string;
}

interface IpsecPolicy {
  pfs?: string;
  proposal?: string;
}

interface TunnelInterface {
  ip_cidr?: string;
  unit?: string;
  description?: string;
}

interface TrafficSelector {
  local?: string;
  remote?: string;
}

interface IpsecVpn {
  local_id?: string;
  remote_id?: string;
  traffic_selectors?: { [key: string]: TrafficSelector };
  monitor_ip?: string;
  bind_if?: string;
  ike_gw?: string;
  ipsec_policy?: string;
}

interface ParsedData {
  ike_proposals: { [key: string]: IkeProposal };
  ike_policies: { [key: string]: IkePolicy };
  ike_gateways: { [key: string]: IkeGateway };
  ipsec_proposals: { [key: string]: IpsecProposal };
  ipsec_policies: { [key: string]: IpsecPolicy };
  tunnel_interfaces: { [key: string]: TunnelInterface };
  ipsec_vpns: { [key: string]: IpsecVpn };
}

// ==============================================================================
// --- FUNÇÃO PRINCIPAL DE PARSING ---
// ==============================================================================

function parseJuniperConfig(fileContent: string): ParsedData {
  const data: ParsedData = {
    ike_proposals: {},
    ike_policies: {},
    ike_gateways: {},
    ipsec_proposals: {},
    ipsec_policies: {},
    tunnel_interfaces: {},
    ipsec_vpns: {}
  };
  
  const lines = fileContent.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    
    // IKE Policy PSK
    let match = line.match(/set security ike policy (\S+) pre-shared-key ascii-text "(\$9\$[a-zA-Z0-9./+-]+)"/);
    if (match) {
      const [, policyName, encryptedPsk] = match;
      if (!data.ike_policies[policyName]) data.ike_policies[policyName] = {};
      data.ike_policies[policyName].encrypted_psk = encryptedPsk;
      continue;
    }
    
    // Tunnel Interfaces
    match = line.match(/set interfaces (st\d+) unit (\d+) family inet( address ([\d\./]+))?/);
    if (match) {
      const [, baseIf, unit, , ip] = match;
      const fullIf = `${baseIf}.${unit}`;
      if (!data.tunnel_interfaces[fullIf]) data.tunnel_interfaces[fullIf] = {};
      if (ip) data.tunnel_interfaces[fullIf].ip_cidr = ip;
      data.tunnel_interfaces[fullIf].unit = unit;
      continue;
    }
    
    // Interface Description
    match = line.match(/set interfaces (st\d+) unit (\d+) description (.*)/);
    if (match) {
      const [, baseIf, unit, desc] = match;
      const fullIf = `${baseIf}.${unit}`;
      if (!data.tunnel_interfaces[fullIf]) data.tunnel_interfaces[fullIf] = {};
      data.tunnel_interfaces[fullIf].description = desc.trim();
      continue;
    }
    
    // IPSEC VPN Local ID
    match = line.match(/set security ipsec vpn (\S+) ike proxy-identity local ([\d./]+)/);
    if (match) {
      const [, vpnName, localId] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].local_id = localId;
      continue;
    }
    
    // IPSEC VPN Remote ID
    match = line.match(/set security ipsec vpn (\S+) ike proxy-identity remote ([\d./]+)/);
    if (match) {
      const [, vpnName, remoteId] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].remote_id = remoteId;
      continue;
    }
    
    // Traffic Selector Local
    match = line.match(/set security ipsec vpn (\S+) traffic-selector (\S+) local-ip ([\d./]+)/);
    if (match) {
      const [, vpnName, tsName, localIp] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      if (!data.ipsec_vpns[vpnName].traffic_selectors) data.ipsec_vpns[vpnName].traffic_selectors = {};
      if (!data.ipsec_vpns[vpnName].traffic_selectors![tsName]) data.ipsec_vpns[vpnName].traffic_selectors![tsName] = {};
      data.ipsec_vpns[vpnName].traffic_selectors![tsName].local = localIp;
      continue;
    }
    
    // Traffic Selector Remote
    match = line.match(/set security ipsec vpn (\S+) traffic-selector (\S+) remote-ip ([\d./]+)/);
    if (match) {
      const [, vpnName, tsName, remoteIp] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      if (!data.ipsec_vpns[vpnName].traffic_selectors) data.ipsec_vpns[vpnName].traffic_selectors = {};
      if (!data.ipsec_vpns[vpnName].traffic_selectors![tsName]) data.ipsec_vpns[vpnName].traffic_selectors![tsName] = {};
      data.ipsec_vpns[vpnName].traffic_selectors![tsName].remote = remoteIp;
      continue;
    }
    
    // VPN Monitor
    match = line.match(/set security ipsec vpn (\S+) vpn-monitor destination-ip ([\d.]+)/);
    if (match) {
      const [, vpnName, monitorIp] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].monitor_ip = monitorIp;
      continue;
    }
    
    // Continue parsing other configuration elements...
    // (Adding more regex patterns for completeness)
    
    // IKE Proposal configurations
    match = line.match(/ike proposal (\S+) authentication-algorithm (\S+)/);
    if (match) {
      const [, proposalName, auth] = match;
      if (!data.ike_proposals[proposalName]) data.ike_proposals[proposalName] = {};
      data.ike_proposals[proposalName].auth = auth;
      continue;
    }
    
    match = line.match(/ike proposal (\S+) encryption-algorithm (\S+)/);
    if (match) {
      const [, proposalName, enc] = match;
      if (!data.ike_proposals[proposalName]) data.ike_proposals[proposalName] = {};
      data.ike_proposals[proposalName].enc = enc;
      continue;
    }
    
    match = line.match(/ike proposal (\S+) dh-group (\S+)/);
    if (match) {
      const [, proposalName, dh] = match;
      if (!data.ike_proposals[proposalName]) data.ike_proposals[proposalName] = {};
      data.ike_proposals[proposalName].dh = dh;
      continue;
    }
    
    match = line.match(/ike proposal (\S+) lifetime-seconds (\d+)/);
    if (match) {
      const [, proposalName, lifetime] = match;
      if (!data.ike_proposals[proposalName]) data.ike_proposals[proposalName] = {};
      data.ike_proposals[proposalName].lifetime = lifetime;
      continue;
    }
    
    // IKE Policy configurations
    match = line.match(/ike policy (\S+) mode (\S+)/);
    if (match) {
      const [, policyName, mode] = match;
      if (!data.ike_policies[policyName]) data.ike_policies[policyName] = {};
      data.ike_policies[policyName].mode = mode;
      continue;
    }
    
    match = line.match(/ike policy (\S+) proposals (\S+)/);
    if (match) {
      const [, policyName, proposal] = match;
      if (!data.ike_policies[policyName]) data.ike_policies[policyName] = {};
      data.ike_policies[policyName].proposal = proposal;
      continue;
    }
    
    // IKE Gateway configurations
    match = line.match(/ike gateway (\S+) ike-policy (\S+)/);
    if (match) {
      const [, gatewayName, policy] = match;
      if (!data.ike_gateways[gatewayName]) data.ike_gateways[gatewayName] = {};
      data.ike_gateways[gatewayName].policy = policy;
      continue;
    }
    
    match = line.match(/ike gateway (\S+) address (\S+)/);
    if (match) {
      const [, gatewayName, peerIp] = match;
      if (!data.ike_gateways[gatewayName]) data.ike_gateways[gatewayName] = {};
      data.ike_gateways[gatewayName].peer_ip = peerIp;
      continue;
    }
    
    match = line.match(/ike gateway (\S+) external-interface (\S+)/);
    if (match) {
      const [, gatewayName, extIf] = match;
      if (!data.ike_gateways[gatewayName]) data.ike_gateways[gatewayName] = {};
      data.ike_gateways[gatewayName].ext_if = extIf;
      continue;
    }
    
    match = line.match(/ike gateway (\S+) version (\S+)/);
    if (match) {
      const [, gatewayName, version] = match;
      if (!data.ike_gateways[gatewayName]) data.ike_gateways[gatewayName] = {};
      data.ike_gateways[gatewayName].version = version;
      continue;
    }
    
    // IPsec Proposal configurations
    match = line.match(/ipsec proposal (\S+) authentication-algorithm (\S+)/);
    if (match) {
      const [, proposalName, auth] = match;
      if (!data.ipsec_proposals[proposalName]) data.ipsec_proposals[proposalName] = {};
      data.ipsec_proposals[proposalName].auth = auth;
      continue;
    }
    
    match = line.match(/ipsec proposal (\S+) encryption-algorithm (\S+)/);
    if (match) {
      const [, proposalName, enc] = match;
      if (!data.ipsec_proposals[proposalName]) data.ipsec_proposals[proposalName] = {};
      data.ipsec_proposals[proposalName].enc = enc;
      continue;
    }
    
    match = line.match(/ipsec proposal (\S+) lifetime-seconds (\d+)/);
    if (match) {
      const [, proposalName, lifetime] = match;
      if (!data.ipsec_proposals[proposalName]) data.ipsec_proposals[proposalName] = {};
      data.ipsec_proposals[proposalName].lifetime = lifetime;
      continue;
    }
    
    // IPsec Policy configurations
    match = line.match(/ipsec policy (\S+) perfect-forward-secrecy keys (\S+)/);
    if (match) {
      const [, policyName, pfs] = match;
      if (!data.ipsec_policies[policyName]) data.ipsec_policies[policyName] = {};
      data.ipsec_policies[policyName].pfs = pfs;
      continue;
    }
    
    match = line.match(/ipsec policy (\S+) proposals (\S+)/);
    if (match) {
      const [, policyName, proposal] = match;
      if (!data.ipsec_policies[policyName]) data.ipsec_policies[policyName] = {};
      data.ipsec_policies[policyName].proposal = proposal;
      continue;
    }
    
    // IPsec VPN configurations
    match = line.match(/ipsec vpn (\S+) bind-interface (st0\.\d+)/);
    if (match) {
      const [, vpnName, bindIf] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].bind_if = bindIf;
      continue;
    }
    
    match = line.match(/ipsec vpn (\S+) ike gateway (\S+)/);
    if (match) {
      const [, vpnName, ikeGw] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].ike_gw = ikeGw;
      continue;
    }
    
    match = line.match(/ipsec vpn (\S+) ike ipsec-policy (\S+)/);
    if (match) {
      const [, vpnName, ipsecPolicy] = match;
      if (!data.ipsec_vpns[vpnName]) data.ipsec_vpns[vpnName] = {};
      data.ipsec_vpns[vpnName].ipsec_policy = ipsecPolicy;
      continue;
    }
  }
  
  return data;
}

// ==============================================================================
// --- GERAÇÃO DE CONFIGURAÇÃO PALO ALTO ---
// ==============================================================================

interface TargetOptions {
  type: 'firewall' | 'panorama';
  template?: string;
}

interface ConvOptions {
  local_remote_id: boolean;
  proxy_id: boolean;
  monitor: boolean;
}

interface ZoneOptions {
  enabled: boolean;
  name?: string;
}

interface RouterOptions {
  type?: 'virtual' | 'logical';
  name?: string;
}

interface ConfigFiles {
  [filename: string]: string;
}

function generatePaloAltoConfigs(
  data: ParsedData,
  targetOptions: TargetOptions,
  convOptions: ConvOptions,
  localPaInterface: string,
  localPaIp: string,
  zoneOptions: ZoneOptions,
  routerOptions: RouterOptions
): ConfigFiles {
  if (!data || !data.ipsec_vpns || Object.keys(data.ipsec_vpns).length === 0) {
    throw new Error("Nenhuma VPN IPsec encontrada para converter");
  }

  const basePrefix = targetOptions.type === 'panorama' 
    ? `set template ${quoteIfNeeded(targetOptions.template!)} config`
    : "set";
  
  const templateNameQ = targetOptions.template ? quoteIfNeeded(targetOptions.template) : "";
  
  const allConfigsClean: string[] = [];
  const decryptedSecretsLog: string[] = [];
  const securityRecommendations: string[] = [
    "===================================================",
    "= Relatório de Recomendações de Segurança IPsec =",
    "===================================================",
    ""
  ];

  const algoMap: { [key: string]: string } = {
    "hmac-sha1-96": "sha1",
    "hmac-sha-256-128": "sha256",
    "sha-256": "sha256",
    "sha1": "sha1",
    "aes-256-cbc": "aes-256-cbc",
    "aes-128-cbc": "aes-128-cbc",
    "3des-cbc": "3des",
    "3des": "3des"
  };

  const configFiles: ConfigFiles = {};
  let convertedCount = 0;
  const totalTunnels = Object.keys(data.ipsec_vpns).length;

  for (const [vpnName, vpnDetails] of Object.entries(data.ipsec_vpns)) {
    const safeVpnName = sanitizeName(vpnName);
    const singleTunnelConfig: string[] = [];
    const currentTunnelWeaknesses: string[] = [];

    try {
      const ikeGwName = vpnDetails.ike_gw!;
      const ikeGw = data.ike_gateways[ikeGwName];
      if (!ikeGw) throw new Error(`IKE Gateway '${ikeGwName}' não encontrado`);

      const ikePolicyName = ikeGw.policy!;
      const ikePolicy = data.ike_policies[ikePolicyName];
      if (!ikePolicy) throw new Error(`IKE Policy '${ikePolicyName}' não encontrada`);

      const encryptedPsk = ikePolicy.encrypted_psk!;
      let decryptedPassword: string;
      
      try {
        decryptedPassword = juniperDecrypt(encryptedPsk);
        decryptedSecretsLog.push(`Túnel: ${vpnName} (Política IKE: ${ikePolicyName}) -> ${decryptedPassword}`);
      } catch (e) {
        decryptedPassword = "DECRYPTION_FAILED";
        decryptedSecretsLog.push(`Túnel: ${vpnName} (Política IKE: ${ikePolicyName}) -> ERRO: ${e}`);
      }

      const ipsecPolicyName = vpnDetails.ipsec_policy!;
      const ipsecPolicy = data.ipsec_policies[ipsecPolicyName];
      if (!ipsecPolicy) throw new Error(`IPsec Policy '${ipsecPolicyName}' não encontrada`);

      const ikeProposal = data.ike_proposals[ikePolicy.proposal!];
      const ipsecProposal = data.ipsec_proposals[ipsecPolicy.proposal!];
      
      if (!ikeProposal) throw new Error(`IKE Proposal '${ikePolicy.proposal}' não encontrada`);
      if (!ipsecProposal) throw new Error(`IPsec Proposal '${ipsecPolicy.proposal}' não encontrada`);

      const tunnelIf = data.tunnel_interfaces[vpnDetails.bind_if!];
      if (!tunnelIf) throw new Error(`Interface de túnel '${vpnDetails.bind_if}' não encontrada`);
      
      const tunnelUnit = tunnelIf.unit!;

      // Security analysis
      if (decryptedPassword !== "DECRYPTION_FAILED") {
        const pskWeaknesses = analyzePskStrength(decryptedPassword);
        if (pskWeaknesses.length > 0) {
          currentTunnelWeaknesses.push(`Pre-Shared Key Insegura: ${pskWeaknesses.join(', ')}.`);
        }
      }

      // Continue with other security checks...
      if (ikeProposal.enc?.includes('3des')) {
        currentTunnelWeaknesses.push("Fase 1 (IKE) Encryption: Uso do algoritmo 3DES, considerado fraco. Recomenda-se AES-256-GCM.");
      }

      if (['sha1', 'md5'].includes(ikeProposal.auth || '')) {
        currentTunnelWeaknesses.push(`Fase 1 (IKE) Hashing: Uso de ${ikeProposal.auth?.toUpperCase()}, considerado fraco/quebrado. Recomenda-se SHA256 ou superior.`);
      }

      // Generate PA config names
      const paIkeCryptoName = quoteIfNeeded(`IKE-CRYPTO-${safeVpnName}`);
      const paIpsecCryptoName = quoteIfNeeded(`IPSEC-CRYPTO-${safeVpnName}`);
      const paIkeGwName = quoteIfNeeded(`IKE-GW-${safeVpnName}`);
      const paIpsecTunnelName = quoteIfNeeded(`IPSEC-TUNNEL-${safeVpnName}`);
      const paTunnelIfName = `tunnel.${tunnelUnit}`;

      // Build configuration
      singleTunnelConfig.push(`# ================== Início da Configuração para o Túnel: ${vpnName} ==================`);

      // IKE Crypto Profile
      singleTunnelConfig.push(
        `${basePrefix} network ike crypto-profiles ike-crypto-profiles ${paIkeCryptoName} hash ${algoMap[ikeProposal.auth || ''] || 'sha1'}`,
        `${basePrefix} network ike crypto-profiles ike-crypto-profiles ${paIkeCryptoName} dh-group ${ikeProposal.dh || 'group2'}`,
        `${basePrefix} network ike crypto-profiles ike-crypto-profiles ${paIkeCryptoName} encryption ${algoMap[ikeProposal.enc || ''] || 'aes-256-cbc'}`,
        `${basePrefix} network ike crypto-profiles ike-crypto-profiles ${paIkeCryptoName} lifetime seconds ${ikeProposal.lifetime || '28800'}`,
        ""
      );

      // IPsec Crypto Profile
      singleTunnelConfig.push(
        `${basePrefix} network ike crypto-profiles ipsec-crypto-profiles ${paIpsecCryptoName} esp authentication ${algoMap[ipsecProposal.auth || ''] || 'sha1'}`,
        `${basePrefix} network ike crypto-profiles ipsec-crypto-profiles ${paIpsecCryptoName} esp encryption ${algoMap[ipsecProposal.enc || ''] || 'aes-256-cbc'}`
      );

      if (ipsecPolicy.pfs) {
        singleTunnelConfig.push(`${basePrefix} network ike crypto-profiles ipsec-crypto-profiles ${paIpsecCryptoName} dh-group ${ipsecPolicy.pfs}`);
      }

      singleTunnelConfig.push(
        `${basePrefix} network ike crypto-profiles ipsec-crypto-profiles ${paIpsecCryptoName} lifetime seconds ${ipsecProposal.lifetime || '3600'}`,
        ""
      );

      // Interface configuration
      let configAddedForInterface = false;
      if (tunnelIf.ip_cidr) {
        singleTunnelConfig.push(`${basePrefix} network interface tunnel units ${paTunnelIfName} ip ${tunnelIf.ip_cidr}`);
        configAddedForInterface = true;
      }

      if (tunnelIf.description) {
        singleTunnelConfig.push(`${basePrefix} network interface tunnel units ${paTunnelIfName} comment "${tunnelIf.description}"`);
        configAddedForInterface = true;
      }

      // Zone configuration
      if (zoneOptions.enabled && zoneOptions.name) {
        const zoneNameQ = quoteIfNeeded(zoneOptions.name);
        if (targetOptions.type === 'panorama') {
          singleTunnelConfig.push(`set template ${templateNameQ} config vsys vsys1 zone ${zoneNameQ} network layer3 ${paTunnelIfName}`);
        } else {
          singleTunnelConfig.push(`set zone ${zoneNameQ} network layer3 ${paTunnelIfName}`);
        }
        configAddedForInterface = true;
      }

      // Router configuration
      if (routerOptions.type && routerOptions.name) {
        const routerNameQ = quoteIfNeeded(routerOptions.name);
        if (routerOptions.type === 'logical') {
          singleTunnelConfig.push(`${basePrefix} network logical-router ${routerNameQ} interface ${paTunnelIfName}`);
        } else if (routerOptions.type === 'virtual') {
          singleTunnelConfig.push(`${basePrefix} network virtual-router ${routerNameQ} interface ${paTunnelIfName}`);
        }
        configAddedForInterface = true;
      }

      if (configAddedForInterface) {
        singleTunnelConfig.push("");
      }

      // IKE Gateway
      singleTunnelConfig.push(`${basePrefix} network ike gateway ${paIkeGwName} authentication pre-shared-key key ${decryptedPassword}`);

      // Local/Remote ID
      if (convOptions.local_remote_id) {
        if (vpnDetails.local_id) {
          singleTunnelConfig.push(`${basePrefix} network ike gateway ${paIkeGwName} local-id type ipaddr id ${vpnDetails.local_id}`);
        }
        if (vpnDetails.remote_id) {
          singleTunnelConfig.push(`${basePrefix} network ike gateway ${paIkeGwName} peer-id type ipaddr id ${vpnDetails.remote_id}`);
        }
      }

      // IKE Version
      const ikeVersion = ikeGw.version || 'v1-only';
      if (ikeVersion.includes('v2')) {
        singleTunnelConfig.push(
          `${basePrefix} network ike gateway ${paIkeGwName} protocol version ikev2`,
          `${basePrefix} network ike gateway ${paIkeGwName} protocol ikev2 ike-crypto-profile ${paIkeCryptoName}`
        );
      } else {
        singleTunnelConfig.push(
          `${basePrefix} network ike gateway ${paIkeGwName} protocol version ikev1`,
          `${basePrefix} network ike gateway ${paIkeGwName} protocol ikev1 ike-crypto-profile ${paIkeCryptoName}`
        );
        
        if (ikePolicy.mode === 'main') {
          singleTunnelConfig.push(`${basePrefix} network ike gateway ${paIkeGwName} protocol ikev1 exchange-mode main`);
        }
      }

      singleTunnelConfig.push(
        `${basePrefix} network ike gateway ${paIkeGwName} local-address interface ${localPaInterface} ip ${localPaIp}`,
        `${basePrefix} network ike gateway ${paIkeGwName} peer-address ip ${ikeGw.peer_ip || '0.0.0.0'}`,
        ""
      );

      // IPsec Tunnel
      singleTunnelConfig.push(
        `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} auto-key ike-gateway ${paIkeGwName}`,
        `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} auto-key ipsec-crypto-profile ${paIpsecCryptoName}`
      );

      // Tunnel Monitor
      if (convOptions.monitor && vpnDetails.monitor_ip) {
        singleTunnelConfig.push(
          `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} tunnel-monitor enable yes`,
          `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} tunnel-monitor destination-ip ${vpnDetails.monitor_ip}`
        );
      }

      // Proxy IDs
      if (convOptions.proxy_id && vpnDetails.traffic_selectors) {
        for (const [tsName, tsDetails] of Object.entries(vpnDetails.traffic_selectors)) {
          singleTunnelConfig.push(
            `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} auto-key proxy-id ${tsName} protocol any`,
            `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} auto-key proxy-id ${tsName} local ${tsDetails.local || '0.0.0.0/0'}`,
            `${basePrefix} network tunnel ipsec ${paIpsecTunnelName} auto-key proxy-id ${tsName} remote ${tsDetails.remote || '0.0.0.0/0'}`
          );
        }
      }

      singleTunnelConfig.push(`${basePrefix} network tunnel ipsec ${paIpsecTunnelName} tunnel-interface ${paTunnelIfName}`);
      singleTunnelConfig.push(`# ================== Fim da Configuração para o Túnel: ${vpnName} ==================\n`);

      // Save individual tunnel config
      configFiles[`${safeVpnName}.txt`] = singleTunnelConfig.join('\n');

      // Add to consolidated config (excluding comments)
      allConfigsClean.push(...singleTunnelConfig.slice(1, -1));
      convertedCount++;

      // Add security recommendations for this tunnel
      securityRecommendations.push(`--- Túnel: ${vpnName} ---`);
      if (currentTunnelWeaknesses.length > 0) {
        currentTunnelWeaknesses.forEach(weakness => {
          securityRecommendations.push(`  - [ALERTA] ${weakness}`);
        });
      } else {
        securityRecommendations.push("  - [OK] Nenhuma fraqueza de configuração óbvia encontrada.");
      }
      securityRecommendations.push("");

    } catch (error) {
      console.error(`ERRO ao converter túnel '${vpnName}': ${error}`);
      continue;
    }
  }

  // Save consolidated files
  if (decryptedSecretsLog.length > 0) {
    configFiles["decrypt_secrets.txt"] = "# Log de senhas Pre-Shared Key decriptografadas\n\n" + decryptedSecretsLog.join('\n');
  }

  if (allConfigsClean.length > 0) {
    configFiles["consolidado_config.txt"] = allConfigsClean.join('\n');
  }

  configFiles["Recomendacoes_de_Seguranca.txt"] = securityRecommendations.join('\n');

  console.log(`Conversão finalizada. ${convertedCount} de ${totalTunnels} túneis foram convertidos com sucesso.`);

  return configFiles;
}

// ==============================================================================
// --- ENDPOINT PRINCIPAL ---
// ==============================================================================

serve(async (req) => {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    return new Response('ok', {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
      },
    })
  }

  try {
    if (req.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Método não permitido' }), {
        status: 405,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const formData = await req.formData();
    
    // Get uploaded file
    const file = formData.get('file') as File;
    if (!file) {
      return new Response(JSON.stringify({ error: 'Nenhum arquivo enviado.' }), {
        status: 400,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const fileContent = await file.text();

    // Parse form options
    const targetOptions: TargetOptions = {
      type: (formData.get('target_type') as 'firewall' | 'panorama') || 'firewall',
      template: formData.get('template_name') as string || undefined
    };

    const convOptions: ConvOptions = {
      local_remote_id: formData.get('convert_local_remote_id') === 'true',
      proxy_id: formData.get('convert_proxy_id') === 'true',
      monitor: formData.get('convert_monitor') === 'true'
    };

    const zoneOptions: ZoneOptions = {
      enabled: formData.get('use_zone') === 'true',
      name: formData.get('zone_name') as string || undefined
    };

    const routerType = formData.get('router_type') as string;
    const routerOptions: RouterOptions = {
      type: routerType !== 'none' ? (routerType as 'virtual' | 'logical') : undefined,
      name: formData.get('router_name') as string || undefined
    };

    const localPaInterface = formData.get('pa_interface') as string || '';
    const localPaIp = formData.get('pa_ip') as string || '';

    // Parse Juniper config
    const juniperData = parseJuniperConfig(fileContent);

    // Generate Palo Alto configs
    const configFiles = generatePaloAltoConfigs(
      juniperData,
      targetOptions,
      convOptions,
      localPaInterface,
      localPaIp,
      zoneOptions,
      routerOptions
    );

    // Create ZIP file in memory
    const zip = new Uint8Array(await createZip(configFiles));

    return new Response(zip, {
      headers: {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="palo_alto_configs.zip"',
        'Access-Control-Allow-Origin': '*'
      },
    });

  } catch (error) {
    console.error('Erro no processamento:', error);
    return new Response(JSON.stringify({ error: `Ocorreu um erro interno: ${error}` }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
});

// Simple ZIP creation function
async function createZip(files: ConfigFiles): Promise<ArrayBuffer> {
  // This is a simplified ZIP implementation
  // In a real scenario, you might want to use a proper ZIP library
  
  const encoder = new TextEncoder();
  const zipData: Uint8Array[] = [];
  
  // ZIP file header
  for (const [filename, content] of Object.entries(files)) {
    const fileData = encoder.encode(content);
    const filenameData = encoder.encode(filename);
    
    // Local file header
    const localHeader = new Uint8Array(30 + filenameData.length);
    const view = new DataView(localHeader.buffer);
    
    view.setUint32(0, 0x04034b50, true); // Local file header signature
    view.setUint16(4, 20, true); // Version needed to extract
    view.setUint16(6, 0, true); // General purpose bit flag
    view.setUint16(8, 0, true); // Compression method (stored)
    view.setUint16(10, 0, true); // File last modification time
    view.setUint16(12, 0, true); // File last modification date
    view.setUint32(14, crc32(fileData), true); // CRC-32
    view.setUint32(18, fileData.length, true); // Compressed size
    view.setUint32(22, fileData.length, true); // Uncompressed size
    view.setUint16(26, filenameData.length, true); // File name length
    view.setUint16(28, 0, true); // Extra field length
    
    localHeader.set(filenameData, 30);
    
    zipData.push(localHeader);
    zipData.push(fileData);
  }
  
  // Calculate total size and create final buffer
  const totalSize = zipData.reduce((sum, arr) => sum + arr.length, 0) + 22; // +22 for end of central directory
  const result = new Uint8Array(totalSize);
  
  let offset = 0;
  for (const data of zipData) {
    result.set(data, offset);
    offset += data.length;
  }
  
  // End of central directory record
  const endOfCentral = new DataView(result.buffer, offset, 22);
  endOfCentral.setUint32(0, 0x06054b50, true); // End of central dir signature
  endOfCentral.setUint16(4, 0, true); // Number of this disk
  endOfCentral.setUint16(6, 0, true); // Disk where central directory starts
  endOfCentral.setUint16(8, Object.keys(files).length, true); // Number of central directory records on this disk
  endOfCentral.setUint16(10, Object.keys(files).length, true); // Total number of central directory records
  endOfCentral.setUint32(12, 0, true); // Size of central directory
  endOfCentral.setUint32(16, offset, true); // Offset of start of central directory
  endOfCentral.setUint16(20, 0, true); // ZIP file comment length
  
  return result.buffer;
}

// Simple CRC32 implementation
function crc32(data: Uint8Array): number {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c;
  }
  
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}