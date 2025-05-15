# smbls

This is a simple Impacket-based tool to check credentials against many Windows hosts and get permission data for SMB shares.

For the input, you give it a list of IPs/hostnames and sets of credentials, which are the domain, username, and either password or LM/NTLM hashes. The output is a JSON object of host information, including errors, SMB metadata, and information about each share, especially [permission data](#share-permissions). Then you can use the companion report generator to extract and format analyses from the data.

There are already many ways to do this. This tool was written to perform in large, heterogeneous networks where existing tools ended up being slow or unreliable in practice. It performs well in this environment because:

- It won't bail out due to errors in the middle of a scan.
- It's very fast due to parallelization.
- The output is JSON.

## Install

`pip install smbls`

The requirements are Python3.9+ and [Impacket](https://github.com/fortra/impacket).

## Usage

### Run a scan

```
Create targets file:
$ printf '10.0.0.1\n10.0.0.2\n...' > targets.txt
Or consider:
$ nmap --open -Pn -p445 10.0.0.0/24 | awk '/scan report for/{print $5}' > targets.txt

For a single-user scan listing share contents:
$ smbls -l -c exampledomain/exampleuser:examplepassword targets.txt -o out.json

Or for a multi-user scan:
1. create creds file:
$ echo 'exampledomain/exampleuser:examplepassword' > creds.txt
$ echo 'localhost/exampleuser#aad3b435b51404eeaad3b435b51404ee:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >> creds.txt
2. run scan:
$ smbls -C creds.txt targets.txt -O example_dir
```

Performance note: it is more efficient to test the connectability of the targets list with a tool like nmap first, rather than scanning whole IP ranges with `smbls`. The slowest part of a scan is usually waiting for connections that time out.

### Analyze the data

`smblsreport` takes in an `smbls` JSON output file and prints the specified report in tsv format. The report types are metadata, hosts, and shares. For each report type, you can specify a list of selection filters and a list of fields to print. Some examples:

```
To print the name and contents of readable shares:
$ smblsreport -f out.json shares -s readable -p contents

To print the name, if signing is required, and the SMB version of hosts where
the scanning user has admin access:
$ smblsreport -f out.json hosts -s admin -p signing,smbver
```

See `smblsreport -h` for a full listing of select and print options. Please open an issue if there's another you'd like to see implemented.

### Library usage

```python
import smbls


for host, scan in smbls.run_scan(
    targets=["10.0.0.1", "localhost"],
    creds_list=[
        {
            "domain": "localhost",
            "username": "Administrator",
            "password": "Password1!",
        }
    ],
    share_auth_only=False,
    share_write=False,
    share_list=True,
    share_list_ipc=False,
):
    print(host, scan)
```

## Share permissions

In `smbls<2.0.0`, the only scanning method was to connect to each share and attempt to list the root path. In March 2022, an experimental branch was pushed that switched to parsing the `MaximalAccess` bitmask returned from the share connection instead. As of version 2, it returns results for both, also returns directory permissions for the root, and optionally attempts writing too.

SMB shares can have permissions limited in three ways: share permissions, directory/folder permissions, and Central Access Policies.

- Share permissions specify the maximum access that a user can have in the share. They're limited to checking "Full Control", "Change", and "Read" (`GENERIC_ALL`, `GENERIC_WRITE`, and `GENERIC_READ|GENERIC_EXECUTE`).
- Directory permissions are the normal permissions of the directory that is shared (or if it's not a directory, the analog for whatever it is). These can be set on the root share directory or any of the subdirectories or files, with very flexible inheritance and granular permissions.
- Central Access Policies are set via GPO and can add additional limitations such as only allowing access from certain locations.

Any of the three permission systems can deny an action---in other words, you need to be allowed by all three. The SMB protocol exposes the share permissions on connection (as `MaximalAccess` in a response to `TREE_CONNECT` in the protocol and `max_share_perms` in the `smbls` JSON output) and allows querying directory permissions (as `QUERY_INFO` in the protocol and as `dacl` for the root directory in the JSON output).

`smbls` changes behavior with command-line flags:

- With default options, list objects in the share root to check read access.
- With `-w`, additionally create and delete a directory named `smblstest` to check write access (only in directory shares).
- With `-l`, additionally return the listed files (for directory shares only) in the JSON output.
- With `-i`, additionally return the listed named pipes for IPC shares in the JSON output.

So `smbls` JSON output has up to four permission fields:

- `max_share_perms` contains the share permissions, which are commonly further limited by directory permissions.
- `dacl` contains the discretionary access control list (DACL) for the root directory of the share. This is a list of access control entries (ACEs) which either allow or deny (rare) a user or group the specified permission. For example, an ACE can allow all domain users read access to the directory. Even if they grant a permission, it is still restricted by the share permissions.
- `read_access` contains whether or not a directory listing was successful.
- `write_access` optionally contains whether or not creating and deleting a directory was successful.

In the following sample excerpt from a scan using a normal user account, the share permissions allow read+write permissions, but directory permissions only allow Users read access in the root share directory, which is confirmed by `write_access` being `false`:

```JSON
{
    "max_share_perms": "GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ",
    "read_access": true,
    "write_access": false,
    "dacl": [
        "ALLOWED,System (or LocalSystem),GENERIC_ALL",
        "ALLOWED,Administrators,GENERIC_ALL",
        "ALLOWED,Users,GENERIC_EXECUTE|GENERIC_READ",
        "ALLOWED,Creator Owner ID,GENERIC_ALL"
    ]
    ...
}
```

To reiterate, please note these caveats:

- `max_share_perms` and `dacl` contain the permissions that can be limited by the other and by Central Access Policies. The `read_access` and `write_access` fields can contradict these fields.
- `read_access`, `write_access`, and `dacl` report permissions at the share root. Subdirectories and individual files on the share may have different permissions.

## Versioning

Versions have the format `major.minor.patch`. Compatibility is considered for the JSON output and the `smbls.run_scan` function interface. Console output, reporting output, and other functions can change at in minor versions.

- Major version updates can remove, rename, or rearrange fields in the JSON output. No compatibility is expected. As of version 3, the `smbls.run_scan` function interface can only be changed with a major version update.
- Minor version updates can add new fields or add information to field values in the JSON output. All functions other than `run_scan` can change.
- Patch version updates can change the wording of field values such as clarifying error messages or fixing bugs.
