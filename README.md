# dosk_dns

- STATUS: WIP

> custom wildcard dns like sslip.io/nip.io but support acme challenge


### Usage

1. git clone this repo on your public server `demo.dns.server`, npm install and run, remember output `auth` and `token`

2. change your domain's `ns` record to `demo.dns.server`

3. install `acme.sh` and copy `dns_dosk.sh` to `~/.acme.sh/dnsapi/dns_dosk.sh`

4. make some env:

```shell
export Dosk_Server='http://demo.dns.server:5333' # without last slash character
export Dosk_Token=[your output token]
export Dosk_Auth=[your output auth]
```

5. acquire ssl certificates as normal, using `--dns dns_dosk` for `DNS-01`
