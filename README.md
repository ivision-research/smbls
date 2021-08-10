# smbls

This is a simple Impacket-based tool to check a set of credentials against many Windows hosts and get permission for SMB shares.

For the input, you give it a list of IPs/hostnames and a set of credentials, which are the domain, username, and either password or lm/ntlm hashes. The output is a JSON array of host information, including errors, SMB metadata, and information about each share, including whether the account has read access.

There are already many ways to do this. This tool was written to perform in large, heterogeneous networks where existing tools ended up being slow or unreliable in practice. It performs well in this environment because:

- It's reliable due to comprehensive error checking and simple code
- It's very fast due to parallelization
- The output is JSON

The main limitation is that it does not check whether a share is writeable or not, because the known way to do that requires attempting to write to it.

## Install

git clone and `pip install .`

A pypi release is planned.

Alternatively, you can just drop [smbls/\_\_init\_\_.py](smbls/__init__.py) as `smbls.py` on a box with python3.7+ and Impacket installed and run that.

## Usage

```
# Create creds file:
$ echo '{"domain": "exampledomain", "username": "exampleuser", "password": "examplepassword"}' > creds.json
# Or
$ echo '{"domain": "localhost", "username": "exampleuser", "lmhash": "aad3b435b51404eeaad3b435b51404ee", "nthash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > creds.json

# Create targets file:
$ printf '10.0.0.1\n10.0.0.2\n...' > targets.txt
# Or for CIDR notation, consider
$ nmap -sL -n 10.0.0.0/24 | awk '/scan report for/{print $5}' > targets.txt

# Run scan:
$ smbls -c creds.json -t targets.txt -o out.json
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
jq -r '.[] | select(.shares) | {ip: (.info.getRemoteHost), host: (.info.getServerDNSHostName), readshares: [.shares[] | select(.access != "") | {name: .name, type: .type, remark: .remark}]} | select(.readshares != [])' out.json
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
