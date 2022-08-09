/*
 *  Author: SpringHack - springhack@live.cn
 *  Last modified: 2022-08-10 12:41:40
 *  Filename: dns.js
 *  Description: Created by SpringHack using vim automatically.
 */
const {Packet, createServer} = require('dns2');
const {parse} = require('ip6addr');
const crypto = require('crypto');
const http = require('http');

const MAGIC_VARIABLES = {
  ACME_CHALLENGE: '_acme-challenge',
  ACME_CHALLENGE_CNAME: '_acme-challenge-cname'
};

const caList = [
  ['issue', 'letsencrypt.org'], ['issuewild', 'letsencrypt.org'],
  ['issue', 'zerossl.com'], ['issuewild', 'zerossl.com'], ['issue', 'ssl.com'],
  ['issuewild', 'ssl.com'], ['issue', 'digicert.com'],
  ['issuewild', 'digicert.com']
];

const isHex = (data) => /^[A-Fa-f0-9]{1,4}$/.test(data);

const generateIPv4 = (name) => {
  const parts = name.replace(/-/g, '.').split('.');
  const ipParts = [];
  for (const part of parts) {
    if (part.length === 8) {
      const a =
          isHex(part.substr(0, 2)) ? parseInt(part.substr(0, 2), 16) : NaN;
      const b =
          isHex(part.substr(2, 2)) ? parseInt(part.substr(2, 2), 16) : NaN;
      const c =
          isHex(part.substr(4, 2)) ? parseInt(part.substr(4, 2), 16) : NaN;
      const d =
          isHex(part.substr(6, 2)) ? parseInt(part.substr(6, 2), 16) : NaN;
      if (a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 &&
          d >= 0 && d <= 255) {
        return `${a}.${b}.${c}.${d}`;
      }
    } else {
      if (/^\d+$/.test(part)) {
        const ipPart = parseInt(part, 10);
        if (ipPart >= 0 && ipPart <= 255) {
          ipParts.push(ipPart);
        }
      }
    }
  }
  if (ipParts.length < 4) {
    return null;
  }
  return ipParts.slice(0, 4).join('.');
};

const generateIPv6 = (name) => {
  const parts = name.split('.');
  for (const part of parts) {
    const ipParts = part.split(/-+/).map((dig) => {
      if (dig === '') {
        return '0';
      }
      return dig;
    });
    let isValid = !!ipParts.length && ipParts.length <= 8;
    for (const ipPart of ipParts) {
      const num = isHex(ipPart) ? parseInt(ipPart, 16) : NaN;
      if (isNaN(num) || num > 65535) {
        isValid = false;
      }
    }
    if (isValid) {
      const maybeValue = part.replace(/-/g, ':');
      const maybeParts = maybeValue.split('::');
      if (ipParts.length === 8 ||
          (ipParts.length < 8 && maybeParts.length === 2)) {
        return maybeValue;
      }
    }
  }
  return null;
};

class TxtResource {
  #txtMap_ = new Map();
  ensureExist(key) {
    if (!this.#txtMap_.get(key)) {
      this.#txtMap_.set(key, new Set());
    }
  }
  getItem(key) {
    this.ensureExist(key);
    return [...this.#txtMap_.get(key)];
  }
  setItem(key, value) {
    this.ensureExist(key);
    return this.#txtMap_.get(key).add(value);
  }
  removeItem(key, value) {
    this.ensureExist(key);
    return this.#txtMap_.get(key).delete(value);
  }
}

const txts = new TxtResource();
const options = {
  auth: crypto.randomUUID(),
  token: crypto.randomUUID(),
  dnsPort: '53',
  dnsAddress: '0.0.0.0',
  httpPort: '5333',
  httpAddress: '0.0.0.0'
};

for (let index = 0; index < process.argv.length; ++index) {
  if (process.argv[index] === '--help') {
    console.error(JSON.stringify(options, null, 2));
    process.exit(0);
  }
  if (process.argv[index].startsWith('--')) {
    if (index + 1 < process.argv.length &&
        !process.argv[index + 1].startsWith('--')) {
      options[process.argv[index].substring(2)] = process.argv[index + 1];
    } else {
      console.error(`illegal option=${process.argv[index].substring(2)}`);
      process.exit(1);
    }
  }
}

const createSOARecord = (name) => {
  return {
    name,
    type: Packet.TYPE.SOA,
    class: Packet.CLASS.IN,
    ttl: 300,
    primary: name,
    admin: 'springhack.live.cn',
    serial: 2016121301,
    refresh: 300,
    retry: 3,
    expiration: 10,
    minimum: 10,
  };
};

const server = createServer({
  udp: true,
  handle(request, send) {
    const response = Packet.createResponseFromRequest(request);
    for (const question of request.questions) {
      const {name: originalName, type} = question;
      const name = originalName.toLowerCase();
      switch (type) {
        case Packet.TYPE.CNAME: {
          if (!name.startsWith(MAGIC_VARIABLES.ACME_CHALLENGE)) {
            response.authorities.push(createSOARecord(name));
            break;
          }
          const sub = name.split('.')[0];
          switch (sub) {
            case MAGIC_VARIABLES.ACME_CHALLENGE: {
              response.answers.push({
                name,
                type,
                ttl: 300,
                class: Packet.CLASS.IN,
                domain: name.replace(
                    MAGIC_VARIABLES.ACME_CHALLENGE,
                    MAGIC_VARIABLES.ACME_CHALLENGE_CNAME)
              });
              break;
            }
            default:
              break;
          }
          break;
        }
        case Packet.TYPE.A: {
          if (name.startsWith(MAGIC_VARIABLES.ACME_CHALLENGE_CNAME)) {
            const obj = {
              name,
              type,
              address: '1.1.1.1',
              ttl: 300,
              class: Packet.CLASS.IN
            };
            response.answers.push(obj);
            break;
          }
          const address = generateIPv4(name);
          if (!address) {
            response.authorities.push(createSOARecord(name));
            break;
          }
          const obj = {name, type, address, ttl: 300, class: Packet.CLASS.IN};
          response.answers.push(obj);
          break;
        }
        case Packet.TYPE.AAAA: {
          const address = generateIPv6(name);
          if (!address) {
            response.authorities.push(createSOARecord(name));
            break;
          }
          const obj = {
            name,
            type,
            ttl: 300,
            class: Packet.CLASS.IN,
            address: parse(address).toString({format: 'v6', zeroElide: false})
          };
          response.answers.push(obj);
          break;
        }
        case Packet.TYPE.TXT: {
          let records = txts.getItem(name);
          if (!records.size) {
            records = txts.getItem(name.replace(
                MAGIC_VARIABLES.ACME_CHALLENGE_CNAME,
                MAGIC_VARIABLES.ACME_CHALLENGE));
          }
          for (const data of records) {
            const obj = {name, type, data, class: Packet.CLASS.IN, ttl: 300};
            response.answers.push(obj);
          }
          if (!response.answers.length) {
            response.authorities.push(createSOARecord(name));
          }
          break;
        }
        case Packet.TYPE.CAA: {
          for (const ca of caList) {
            const [tag, value] = ca;
            const obj = {
              tag,
              name,
              type,
              value,
              flags: 0,
              class: Packet.CLASS.IN,
              ttl: 300
            };
            response.answers.push(obj);
          }
          break;
        }
        default:
          response.authorities.push(createSOARecord(name));
      }
    }
    send(response);
  }
});

server.listen({
  udp: {
    port: parseInt(options.dnsPort),
    address: options.dnsAddress,
    type: 'udp4'
  }
});

const resolveAcmeDNS = (request, response) => {
  const {url, headers} = request;
  switch (url.substring(1)) {
    case 'register': {
      return response.writeHead(201, 'not impl').end('{}');
    }
    case 'update': {
      const headerAuth = headers['x-api-user'];
      const headerToken = headers['x-api-key'];
      if (headerAuth !== options.auth || headerToken !== options.token) {
        return response.writeHead(500, 'not auth').end();
      }
      let body = '';
      request.on('data', chunk => body += chunk);
      request.on('end', () => {
        let data = {};
        try {
          for (const [k, v] of Object.entries(JSON.parse(body.toString()))) {
            data[k.toLowerCase()] = v;
          }
        } catch (e) {
          return response.writeHead(500, 'invalid request').end();
        }
        if (txts.setItem(data.subdomain, data.txt)) {
          response.writeHead(200, {'Content-Type': 'application/json'})
          return response.end(JSON.stringify({txt: data.txt}));
        }
        return response.writeHead(500, 'set failed').end();
      });
      return;
    }
    default: {
      response.writeHead(500, 'not support').end();
    }
  }
};

const httpServer = http.createServer((request, response) => {
  const {url, method, headers} = request;
  if (!url) {
    return response.writeHead(500, 'not support').end();
  }
  if (method.toLowerCase() == 'post') {
    return resolveAcmeDNS(request, response);
  }
  if (url === '/health') {
    return response.writeHead(200, 'fine').end();
  }
  if (headers[options.auth] !== options.token) {
    return response.writeHead(500, 'not auth').end();
  }
  const urlParts = url.substring(1).split('/');
  const [operation, key, value] = urlParts;
  switch (operation) {
    case 'get': {
      if (!key) {
        response.writeHead(500, 'no key').end();
      }
      return response.end(JSON.stringify(txts.getItem(key)));
    }
    case 'set': {
      if (!key || !value) {
        return response.writeHead(500, 'no key/value').end();
      }
      return response.end(JSON.stringify(txts.setItem(key, value)));
    }
    case 'del': {
      if (!key || !value) {
        return response.writeHead(500, 'no key/value').end();
      }
      return response.end(JSON.stringify(txts.removeItem(key, value)));
    }
    default: {
      return response.writeHead(500, 'invalid operation').end();
    }
  }
});

httpServer.listen(parseInt(options.httpPort), options.httpAddress);

console.log(`start with options=${JSON.stringify(options, null, 2)}`);
