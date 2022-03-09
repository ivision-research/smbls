# smbls

This is a simple Impacket-based tool to check a set of credentials against many Windows hosts and get permission for SMB shares.

For the input, you give it a list of IPs/hostnames and a set of credentials, which are the domain, username, and either password or LM/NTLM hashes. The output is a JSON array of host information, including errors, SMB metadata, and information about each share, including whether the account has read access.

There are already many ways to do this. This tool was written to perform in large, heterogeneous networks where existing tools ended up being slow or unreliable in practice. It performs well in this environment because:

- It's reliable due to comprehensive error checking and simple code
- It's very fast due to parallelization
- The output is JSON

The main limitation is that it does not check whether a share is writeable or not, because the known way to do that requires attempting to write to it.

## Install

`pip install smbls`

Alternatively, you can just drop [smbls/\_\_init\_\_.py](smbls/__init__.py) as `smbls.py` on a box with python3.9+ and Impacket installed and run that.

## Usage

```
Create targets file:
$ printf '10.0.0.1\n10.0.0.2\n...' > targets.txt
Or for CIDR notation, consider
$ nmap -sL -n 10.0.0.0/24 | awk '/scan report for/{print $5}' > targets.txt

For a single-user scan:
$ smbls -c exampledomain/exampleuser:examplepassword targets.txt -o out.json

Or for a multi-user scan:
1. create creds file:
$ echo 'exampledomain/exampleuser:examplepassword' > creds.txt
$ echo 'localhost/exampleuser#aad3b435b51404eeaad3b435b51404ee:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >> creds.txt
2. run scan:
$ smbls -C creds.txt targets.txt -O example_dir
```

### Output parsing

Here are some shell-based examples.

Get list of targets with admin access:

```sh
jq -r '.[]|select(.admin)|.info.getServerDNSHostName' out.json
```

Get list of share names:

```sh
jq -r '.[].shares[]?|.name' out.json | sort -iu
```

Find hosts with given share name:

```sh
# Search for D drives
jq -r 'path(..|select(.name?==$name))[0]' out.json --arg name D
```

List hosts with corresponding readable shares:

```sh
jq -r '[.[] | select(.shares) | {ip: (.info.getRemoteHost), host: (.info.getServerDNSHostName), readshares: [.shares[] | select(.access != "") | {name: .name, type: .type, remark: .remark}]} | select(.readshares != [])]' out.json
# With less output
jq -r '.[] | select(.shares) | {host: (.info.getServerDNSHostName), readshares: [.shares[] | select(.access != "") | .name]} | select(.readshares != [])' out.json
# Excluding print$ and IPC$ shares:
jq -r '.[] | select(.shares) | {host: (.info.getServerDNSHostName), readshares: [.shares[] | select(.access != "" and ([.name] | inside($badsharenames) | not)) | .name]} | select(.readshares != [])' --argjson badsharenames '["print$", "IPC$"]' out.json

```

List hosts that failed auth:

```sh
jq -r 'path(.[]|select(.errtype == "auth"))[0]' out.json
```

List hosts that had a connection error (to remove them from future scans):

```sh
jq -r 'path(.[]|select(.errtype == "conn"))[0]' out.json
```

Get results for hosts that succeeded auth:

```sh
jq -r '.[]|select(.errtype == "")' out.json
```
