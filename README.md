# TsunamiSight

A client that extracts vulnerability-related observations from the
[Tsunami Security Scanner plugins](https://github.com/google/tsunami-security-scanner-plugins)
repository and publishes them as
[sightings](https://www.vulnerability-lookup.org/user-manual/sightings/)
on a Vulnerability-Lookup instance.

Each committed Tsunami detector is a compiled, executable proof-of-concept for
a specific vulnerability. Google's newer **templated** plugins (`.textproto`
files under `templated/templateddetector/plugins/`) are also parsed for CVE
sightings. TsunamiSight emits one sighting per `(plugin, CVE)` pair with the
default type `published-proof-of-concept`.

## Installation

```bash
$ pipx install TsunamiSight
$ export TSUNAMISIGHT_CONFIG=~/.TsunamiSight/conf.py
$ git clone https://github.com/google/tsunami-security-scanner-plugins.git tsunami-security-scanner-plugins
```

Copy `tsunamisight/conf_sample.py` to your chosen config path and fill in the
token + URL.

### With Docker

```bash
git clone <this repo>
cd TsunamiSight
cp tsunamisight/conf_sample.py tsunamisight/conf.py   # then fill in token
docker compose up --build
```

## Usage

```
TsunamiSight --help
usage: TsunamiSight [-h] [--init] [--dry-run]

Extract CVE references from the Tsunami plugins repo and publish sightings.

options:
  -h, --help   show this help message and exit
  --init       Full sweep: emit sightings for every CVE-bearing plugin.
  --dry-run    Parse and print (plugin, CVE, timestamp) triples without POSTing.
```

## License

[TsunamiSight](https://github.com/vulnerability-lookup/TsunamiSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2026 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2026 Philippe Parage - https://github.com/pparage
~~~

