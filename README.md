# wsee
A CDN Domain Fronting Tool or Websocket Discovery. Should work on any CDN but more focused on `CloudFlare` and `CloudFront` CDN.  This tool provides multiple technique to ensure target endpoint can fall under specific protocol, indicated via `101` statuses. Can be used for **Bug  Hunters** to find any delicate domain related to CDN especially on FreeNet / Free Internet fields.

## Features
- `wsee: to go` an Easy to use, scans whenever needed with Clean interactive Python script. Usable across any device that supports for `python`. PS: Even work on `Termux` and `WSL`.
- A Fast domain queries using `Multiprocessing` to interlude all cpu cores, shorten your time.
- Has a `Local WebSocket` finder; that allows you to discover more websocket possibilities without `domain-fronting` restriction.
- More vary technique such as `ZGrab` to accurately find more `Local Websocket` for your endpoint.
- ***Don't have a wordlist?*** : `wsee` got you covered with `Online Subdomain Enumeration` feature using `HackerTarget` as source.
- Accept `.csv` as wordlist, breaking the barrier of must used `.txt` and made it compatible for other Enumeration Tool Output.
- Supports for Internal Storage for `Termux` users.
- Supports for HTTP2 Protocol Upgrade indicated as `h2c`.
- New `Rotate` Mode feature; Now you can rotate `proxy` and `hostname` individually. This is useful if the target only accept specific proxy or ssl masking.
- Auto script updater handled with config located in `.wsee/CONFIG`
- New Enhancement each Updates

# How it works
##### **Main Propose**
The tool works; is by following the general idea of Upgrading protocol indicated in `101` HTTP Status code, which assume that the Endpoint supports the target protocol:
```
headers = { "Connection": "Upgrade", "Upgrade": protocol }
```
Even though it uses a basic headers, some Endpoint are Headers dependant. In `websocket` for example; it may require `X-SS` or `Sec-` or `User-Agent` entry in order upgrade connection to be accepted by the server, this usually happen on `Amazon` endpoints. Make sure to add those manually into the headers and the script will do the rest.

##### **SSL Failure**
In the newer version of `OpenSSL`; it doesn't support `Legacy Connection` and consider it as an exception. Due to this, you need to install custom OpenSSL Config by simply define it into your environment variable:
```
export OPENSSL_CONF=/openssl.cnf
```

##### **ZGrab Resolution**
- ZGrab can bloat your DNS. Make sure to switch your DNS into `1.1.1.1` CloudFlare DNS or `8.8.8.8` Google DNS. You can achieve this by using [Warp VPN](https://apkcombo.com/1111-vpn/com.cloudflare.onedotonedotonedotone) that you can download at PlayStore. Alternatively, you can manually setup your DNS into `/etc/resolv.conf`
```
### CloudFlare DNS
nameserver 1.1.1.1
nameserver 1.0.0.1

### Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
```
##### **Internal Storage**
For Termux users; you can now takes input from Internal Storage. `Termux` is able to create a symlink to your storage from mounted `./storage/shared/`, you can negate manually using `custom path` or create `host` folder inside your phone storage. Make sure to create symlink first inside the Termux:
```
termux-setup-storage
```
##### **Disable Update**
Latest releases introduce auto-update feature. It's a small feature but you're now no longer needs to scrape whole directory to install new releases. You can just change `true` statement into `false` inside wsee config located in `.wsee/CONFIG`:
```
{
	"config":{
		"update-wsee": false,
		"update-database": false
}}
```

# Installation
`wsee` uses 3rd-party module, make sure to install `requests` before running, or else:
```
apt install python3, python3-pip
apt install git
git clone https://github.com/MC189/wsee
cd wsee
chmod +x *
python3 -m pip install requests
python3 wsee.py
```

# Credit
This Repo is build on top of other works, I'm not a jerk that steals other people work.
- Thanks to [@fdxreborn](https://github.com/fdxreborn) for letting me to enhance his tools. This Repo is built on top of his awesome works at [cfchecker](https://github.com/fdxreborn/cfchecker)
- Also thanks to [@PalindromeLabs](https://github.com/PalindromeLabs) for ZGrab uses in Websocket Discovery. This repo borrows some material from [STEWS: Security Testing and Enumeration of WebSockets](https://github.com/PalindromeLabs/STEWS)

You can also support my work by offering me some free Doughnut xD:
https://saweria.co/mc874

<p align="center"><img alt="Preview" src="https://i.postimg.cc/bYkbMnFQ/Screenshot-2022-05-23-16-40-37-84.jpg"></p>
