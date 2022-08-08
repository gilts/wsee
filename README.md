# wsee
A CDN Domain Fronting Tool or Websocket Discovery / Finder / Checker Tool. Should work on any CDN but more focused on `CloudFlare` and `CloudFront` CDN.  This tool uses several technique to make sure any endpoint can fall under `websocket` protocol. This tool also can be used for **Bug  Hunters** to find any delicate domain related to AWS and CloudFlare. Currently, This tool identify CloudFlare addresses via DNS Proxy level, it may miss some CloudFlare Endpoint that only supports CloudFlare SSL. Expect more Enhancement at future releases!

## Features
- `wsee: to go` an Easy to use, scans whenever needed with Clean interactive Python script. Only require a minimal 3rd-party package, makes it usable accros any device that supports for ```python```. PS: Even work on ```Termux``` and ```WSL```.
- A Fast domain queries using Multiprocessing to interlude all cpu cores, shorten your time.
- Wait, Multiprocessing isn't enough? The new integration has offer `ThreadPool` as an alternative. 
- Has a `Local WebSocket Finder` that allows you to discover more websocket possibilities without `domain-fronting` restriction.
- More vary technique such as `ZGrab` to accurately find more `Local Websocket` for your endpoint.
- ***Don't have a wordlist?*** : `wsee` got you covered with `subdomain enumeration` feature using `HackerTarget` as source.
- Accept `.csv` as wordlist, breaking the barrier of must used `.txt` and made it compatible for other Enumeration Tool Output.
- New Enhancement each Updates

# How it works
##### **Main Propose**
The tool works follow the general idea of Upgrading protocol into `101` HTTP Status code using a basic packet request:
```
r = requests.get("http://" + domain, headers=headers, timeout=0.7, allow_redirects=False)
```
Even though it uses a basic package, some websockets are Headers dependant. Some websocket may require `X-SS` or `Sec-` or `User-Agent` entry in order to upgrade connection. Make sure to add those manually into `headers` or `wsocket` variable and the script will do the rest.

##### **ZGrab Integration**
In the latest version, a new technique is implemented. You can now find more accurate `Local Websocket` using `ZGrab`. This Repo uses modified ZGrab to able use custom `cipher` and also http header. ZGrab technique can give more result than the Default finder but it takes more time to scan and also could bloat your DNS. Personally, i do some double scan using Default Finder and ZGrab to find more result.

##### **ZGrab Resoluion**
- As mentioned in previous section; ZGrab can bloat your DNS. Make sure to switch your DNS into `1.1.1.1` CloudFlare DNS or `8.8.8.8` Google DNS. You can achieve this by using `Warp` VPN that you can download at PlayStore. Alternatively, you can manually setup your DNS into `/etc/resolv.conf`
```
### CloudFlare DNS
nameserver 1.1.1.1
nameserver 1.1.1.1
nameserver 1.1.1.1.cloudflare-dns.com
nameserver 1.0.0.1.cloudflare-dns.com

### Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver google.dns
```
- Another thing is to limit your ZGrab queries using `Ulimit`, however this can only applicable on `Linux` environment. You can try adjust the Ulimit value to balance it with your Internet Speed. Append this inside `commando` variable:
```
ulimit -n 50000
```

# Installation
```
apt install python3
apt install git
git clone https://github.com/MC874/wsee
cd wsee
chmod +x *
./install.sh
python3 wsee.py
```

# Credit
This Repo is build on top of other works, i'm not a jerk that steals other people work.
- Thanks to [@fdxreborn](https://github.com/fdxreborn) for letting me to enhance his tools. This Repo is built on top of his awesome works at [cfchecker](https://github.com/fdxreborn/cfchecker)
- Also thanks [@PalindromeLabs](https://github.com/PalindromeLabs) for ZGrab uses in Websocket Discovery. This repo borrows some material from [STEWS: Security Testing and Enumeration of WebSockets](https://github.com/PalindromeLabs/STEWS)

You can also support my work by offering me some free Doughnut xD:
https://saweria.co/mc874

<p align="center"><img alt="Preview" src="https://i.postimg.cc/bYkbMnFQ/Screenshot-2022-05-23-16-40-37-84.jpg"></p>
