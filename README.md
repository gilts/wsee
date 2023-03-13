# wsee
A CDN Domain Fronting Tool or Websocket Discovery. This tool provides multiple technique to ensure target endpoint can fall under specific `protocol` or statuses, indicated via `101` or `200` or even Any!. Can be used for **Bug  Hunters** to find any delicate domain related to `CDN`, `Websocket`, `HTTP/2`, or Bug-Host in general. Should work on any CDN but only featured `Cloudflare` and `Cloudfront` as in-built ready to use.

## Features
- A Fast domain queries using `Multiprocessing` to interlude all cpu cores, shorten your time.
- Has a `Local WebSocket` finder; that allows you to discover more websocket possibilities without `domain-fronting` restriction.
- More vary technique such as `ZGrab` to accurately find more `Local Websocket` for your endpoint.
- ***Don't have a wordlist?*** : `wsee` got you covered with `Online Subdomain Enumeration` feature using `HackerTarget` as source.
- Supports for Internal Storage for `Termux` users.
- Supports for `HTTP/2` Protocol (clear-text only).
- `Rotate Proxy` feature that will brute list of Proxy against single Hostname. Currently only Supports for Proxy that runs on `443`or `80` port (Based on CloudFlare Proxy)
- `Rotate Hostname` feature that will brute list of Hostname against single Proxy. This is usefull for CDN Distribution IP's that has multiple Domain on a single IP or SSL Masking.
- Auto script updater handled with config located in `.wsee/CONFIG`
- Also include `Normal` mode, to find SSL/Direct bugs without protocol or domain fronting.
- `HeartBeat` when attempt to send a request, this prevent connection lost interrupt in mid-scan.
- `Custom Headers` to Include important headers required for some `endpoint`.
- Has `scope` feature to include supplementary Status Codes such as: `301`, `302`, `4xx`, or Any.
- New Enhancement each Updates

# How it works
##### **Main Propose**
The tool works; is by following the general idea of Upgrading protocol indicated in `101` Status or anything that returns a Status Code, which assume that the Endpoint supports the target protocol:
```
headers = { "Connection": "Upgrade", "Upgrade": protocol }
```
Even though it uses a basic header, some Endpoint are Headers dependant. In `websocket` for example; it may require `X-SS` or `Sec-` or `User-Agent` entry in order upgrade connection to be accepted by the server, this usually happen on `Amazon` endpoints. Make sure to add those manually in Custom Headers and the script will do the rest.

##### **SSL Failure**
In the newer version of `OpenSSL`; it doesn't support `Legacy Connection` and consider it as an exception. Due to this, you need to install custom OpenSSL Config by simply define it into your environment variable:
```
export OPENSSL_CONF=./.wsee/openssl.cnf
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
Latest releases introduce auto-update feature. It's a small feature but now, you're no longer need to scrape the whole directory to install new releases. To `Disable` it: You can just change `true` statement into `false` inside **WSee** config located in `.wsee/CONFIG`:
```
{
	"config":{
		"update-wsee": false,
		"update-database": false
}}
```
##### **Custom Headers**
Adding Custom Headers must in `Dict`ionary format. The new headers will override the Default Payloads mentioned in `./bin/payloads`.
```
{'X-API-Key': 'blah123', 'X-Forwarded-For': 'blah.com'}
```

# Installation
**WSee** uses 3rd-party module, make sure to install `requests` before running, or else:
```
apt install python3, python3-pip, git
git clone https://github.com/Gilts/wsee
cd wsee
chmod +x *
python3 -m pip -r requirements.txt
python3 wsee.py
```

# Credit
This Repo is build on top of other works, I'm not a jerk that steals other people work.
- Thanks to [@fdxreborn](https://github.com/fdxreborn) for letting me to enhance his tools. This Repo is built on top of his awesome works at [cfchecker](https://github.com/fdxreborn/cfchecker)
- Also thanks to [@PalindromeLabs](https://github.com/PalindromeLabs) for ZGrab uses in Websocket Discovery. This repo borrows some material from [STEWS: Security Testing and Enumeration of WebSockets](https://github.com/PalindromeLabs/STEWS)

# Contribute
You can also contribute to this project by creating a pull-request or donating some CDN domain. Your contribution will be listed in our [Guild](https://github.com/Guild-Net) as-well in future content related to **WSee**. Currently; we're looking for `(GCP) Google Cloud Platform`, `Akamai` and `Fastly` CDN Domain. Alternatively, you can also support my work by offering me some free Doughnut xD:
https://saweria.co/mc874

**Do note that** : 
- Your CDN domain will be used for `domain-fronting` purposes.
- The risk of being public should be taken as personal consideration. 

<p align="center"><img alt="Preview" src="https://i.postimg.cc/bYkbMnFQ/Screenshot-2022-05-23-16-40-37-84.jpg"></p>
