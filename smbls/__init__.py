#!/usr/bin/env python3

import argparse
import json
from enum import IntFlag
from multiprocessing import Pool

from impacket.dcerpc.v5 import srvs
from impacket.smbconnection import SessionError, SMBConnection


class STypes(IntFlag):
    """Share Types"""

    DISKTREE = srvs.STYPE_DISKTREE
    PRINTQ = srvs.STYPE_PRINTQ
    DEVICE = srvs.STYPE_DEVICE
    IPC = srvs.STYPE_IPC
    CLUSTER_FS = srvs.STYPE_CLUSTER_FS
    CLUSTER_SOFS = srvs.STYPE_CLUSTER_SOFS
    CLUSTER_DFS = srvs.STYPE_CLUSTER_DFS

    SPECIAL = srvs.STYPE_SPECIAL
    TEMPORARY = srvs.STYPE_TEMPORARY


def list_shares(argbundle):
    creds, host = argbundle
    try:
        smbconn = SMBConnection(host, host, timeout=5)
        smbconn.login(
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("domain", ""),
            creds.get("lmhash", ""),
            creds.get("nthash", ""),
        )

    except OSError as e:
        return (host, {"errtype": "conn", "error": str(e.strerror)})
    except SessionError as e:
        return (host, {"errtype": "auth", "error": str(e)})
    except Exception as e:
        return (host, {"errtype": "unknown_init", "error": str(e)})
    try:
        # Get info
        info = dict()
        for attr in [
            "getServerDomain",
            "getServerOS",
            "getDialect",
            "isLoginRequired",
            "isSigningRequired",
            "doesSupportNTLMv2",
            "getRemoteName",
            "getRemoteHost",
            "getServerName",
            "getServerDNSDomainName",
            "getServerDNSHostName",
        ]:
            try:
                res = getattr(smbconn, attr)()
            except Exception as e:
                res = f"error: {e}"
            info[attr] = res

        # Get shares
        admin = False
        try:
            shares = list()
            for share in smbconn.listShares():
                share_name = share["shi1_netname"][:-1]
                try:
                    smbconn.listPath(share_name, "*")
                    access = "READ"
                    access_error = ""
                except SessionError as e:
                    access_error = str(e)
                    access = ""
                if (share_name == "C$" or share_name == "ADMIN$") and access:
                    admin = True
                shares.append(
                    {
                        "name": share_name,
                        "type_raw": STypes(share["shi1_type"]),
                        # STYPE has a flag of 0 that is valid when the masked
                        # value is 0, which IntFlag doesn't look for. This
                        # adds the 0 flag (DISKTREE) iff there's a masked
                        # value.
                        "type": str(STypes(share["shi1_type"])).removeprefix("STypes.")
                        + (
                            "|DISKTREE"
                            if STypes(share["shi1_type"]) & srvs.STYPE_MASK == 0
                            and STypes(share["shi1_type"]) != 0
                            else ""
                        ),
                        "remark": share["shi1_remark"][:-1],
                        "access": access,
                        "access_error": access_error,
                    }
                )
        except Exception as e:
            return (host, {"errtype": "shares", "error": str(e)})

        return (
            host,
            {
                "errtype": "",
                "error": "",
                "info": info,
                "shares": shares,
                "admin": admin,
            },
        )
    except Exception as e:
        return (host, {"errtype": "unknown", "error": str(type(e)) + str(e)})
    finally:
        smbconn.close()


def main():
    class CustomFormatter(
        argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter
    ):
        pass

    parser = argparse.ArgumentParser(
        formatter_class=CustomFormatter,
        epilog="""
# Create creds file:
$ echo '{"domain": "exampledomain", "username": "exampleuser", "password": "examplepassword"}' > creds.json
# Or
$ echo '{"domain": "localhost", "username": "exampleuser", "lmhash": "aad3b435b51404eeaad3b435b51404ee", "nthash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > creds.json

# Create targets file:
$ printf '10.0.0.1\n10.0.0.2\n...' > targets.txt
# Or for CIDR notation, consider
$ nmap -sL -n 10.0.0.0/24 | awk '/scan report for/{print $5}' > targets.txt

# Run scan:
$ smbls -c creds.json -t targets.txt -o out.json""",
    )
    parser.add_argument(
        "-c",
        dest="creds",
        default="creds.json",
        help="JSON credential object. See below for examples",
    )
    parser.add_argument(
        "-t",
        dest="targets",
        default="targets.txt",
        help="one host per line",
    )
    parser.add_argument("-o", dest="output", default="out.json", help="output file")
    parser.add_argument(
        "-j",
        dest="threads",
        type=int,
        default=32,
        help="multiprocessing threads. This is heavily I/O-bound, so high numbers are fine",
    )
    args = parser.parse_args()

    with open(args.creds) as f:
        creds = json.load(f)
        print(
            f"""Authenticating with
username: {creds.get('username', '')}
password: {creds.get('password', '')}
domain: {creds.get('domain', '')}
lmhash: {creds.get('lmhash', '')}
nthash: {creds.get('nthash', '')}
"""
        )
    with open(args.targets) as f:
        targets = [line.strip() for line in f]
    scan = dict()
    with Pool(args.threads) as pool:
        it = pool.imap_unordered(list_shares, [(creds, target) for target in targets])
        for i in range(len(targets)):
            try:
                host, res = it.next(timeout=15)
                scan[host] = res
                print(
                    f'{i}/{len(targets)} scanned {host}, {"error: " + res["errtype"] if res["errtype"] else ""} {"ADMIN" if res.get("admin") else ""}'
                )
            except Exception as e:
                # If you see this, file an issue
                print(
                    f"Error in main loop: '{e}'\n"
                    "writing partial output and exiting..."
                )
                break
    with open(args.output, "w") as f:
        json.dump(scan, f)


if __name__ == "__main__":
    main()
