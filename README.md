# wsee
A CDN Domain Fronting Tool or Websocket Discovery / Finder / Checker Tool. Should work on any CDN but more focused on `CloudFlare` and `CloudFront` CDN. This tool is an enhancement from `cfchecker` by `fdxreborn` that only focused on Cloudflare findings, but this repo takes it to more wide-range. Providing more enhancement and option **[WIP]**
[cfchecker by fdxreborn](https://github.com/fdxreborn/cfchecker)

## Features
##### Following the newer date, `wsee` already made several improvement from previous repo;
- `wsee: to go` an Easy to use, scans whenever needed with Clean interactive Python script. Only require a minimal 3rd-party package, makes it usable accros Linux Distribution even on `Termux`
- A Fast domain queries using Multiprocessing to interlude all cpu cores, shorten your time.
- More queries support beyond `CloudFlare` and `CloudFront`.
- Has a `Local WebSocket Finder` that allows you to discover more websocket possibilities without `domain-fronting` restriction.
- ***Don't have a wordlist?*** : `wsee` got you covered with `subdomain enumeration` feature using `HackerTarget` as source.
- Accept `.csv` as wordlist, breaking the barrier of must used `.txt` and made it compatible for other Enumeration Tool Output.
- New Enhancement each Updates

# How it works
The tool works follow the general idea of Upgrading protocol into `101` HTTP Status code using a basic packet request; of Python `requests` package.
```
r = requests.get("http://" + domain, headers=headers, timeout=0.7, allow_redirects=False)
```
Even tho it's following the general idea, `wsee` uses more vary technique that follows specific CDN adjustment. For example, `CloudFront` CDN tends to work in `80` port and the target domain act as an open proxy.

# Installation
Probably i shouldn't need to mention this; as it's only requires basic `requests` pkg of Python. Altho it might changes in the future.

##### First Use - Download
```
apt install python3
apt install git
git clone https://github.com/MC874/wsee
python3 -m pip install requests
```

##### Running `wsee.py` script.
```
cd wsee
python3 wsee.py
```

<p align="center"><img alt="Preview" src="https://i.postimg.cc/bYkbMnFQ/Screenshot-2022-05-23-16-40-37-84.jpg"></p>





