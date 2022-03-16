#!/usr/bin/env python3

import argparse
import json
import re
from enum import IntFlag
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Tuple

from impacket.dcerpc.v5 import srvs
from impacket.smbconnection import SessionError, SMBConnection
from impacket.nmb import NetBIOSTimeout


# Max time in seconds for each impacket SMB request
REQUEST_TIMEOUT = 5

Creds = Dict[str, str]
Scan = Dict[str, Any]

password_regex = re.compile(r"(?P<domain>[^/:]*)/(?P<username>[^:]*):(?P<password>.*)")
hash_regex = re.compile(
    r"(?P<domain>[^/:]*)/(?P<username>[^#]*)#(?P<lmhash>[a-fA-F0-9]{32}):(?P<nthash>[a-fA-F0-9]{32})"
)


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


def list_shares_multicred(
    argbundle: Tuple[List[Creds], str]
) -> Tuple[str, Dict[str, Scan]]:
    creds_list, host = argbundle
    res = dict()
    timed_out = False
    for creds in creds_list:
        if timed_out:
            res[serialize(creds)] = {
                "errtype": "timeout",
                "error": "timed out on same host with other credentials",
            }
            continue
        res[serialize(creds)] = list_shares(creds, host)
        if res[serialize(creds)]["errtype"] == "timeout":
            timed_out = True

    return host, res


def list_shares(creds: Creds, host: str) -> Scan:
    try:
        smbconn = SMBConnection(host, host, timeout=REQUEST_TIMEOUT)
        smbconn.login(
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("domain", ""),
            creds.get("lmhash", ""),
            creds.get("nthash", ""),
        )

    except OSError as e:
        return {"errtype": "conn", "error": str(e.strerror)}
    except SessionError as e:
        return {"errtype": "auth", "error": str(e)}
    except NetBIOSTimeout:
        return {"errtype": "timeout", "error": "timed out logging in"}
    except Exception as e:
        return {"errtype": "unknown_init", "error": str(e)}
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
        info["getDialect"] = hex(info["getDialect"])

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
            return {"errtype": "shares", "error": str(e)}

        return {
            "errtype": "",
            "error": "",
            "info": info,
            "shares": shares,
            "admin": admin,
        }
    except Exception as e:
        return {"errtype": "unknown", "error": str(type(e)) + str(e)}
    finally:
        smbconn.close()


def parse_credentials(s: str) -> Creds:
    if match := hash_regex.match(s):
        return match.groupdict("")
    elif match := password_regex.match(s):
        return match.groupdict("")
    else:
        raise ValueError("Couldn't parse credentials")


def serialize(creds: Creds) -> str:
    return creds.get("domain", "") + "_" + creds.get("username", "")


def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Create targets file:
$ printf '10.0.0.1\\n10.0.0.2\\n...' > targets.txt
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
""",
    )
    opts_creds = parser.add_mutually_exclusive_group(required=True)
    opts_creds.add_argument(
        "-c",
        dest="creds",
        help="Credentials to test. Format is either domain/user:password or domain/user#lmhash:nthash",
    )
    opts_creds.add_argument(
        "-C",
        dest="creds_file",
        help="File containing credentials to test, one per line",
    )
    opts_output = parser.add_mutually_exclusive_group(required=True)
    opts_output.add_argument(
        "-o",
        dest="out_file",
        help="File to write output to. Can only be used with a single set of credentials (-c)",
    )
    opts_output.add_argument(
        "-O",
        dest="out_dir",
        help="Directory to write output files to. Each set of credentials will be saved in its own file.",
    )
    parser.add_argument(
        dest="targets",
        help="file containing targets, one host per line, or - for stdin",
    )
    parser.add_argument(
        "-j",
        dest="threads",
        type=int,
        default=32,
        help="multiprocessing threads. This is heavily I/O-bound, so high numbers are fine (default: 32)",
    )
    args = parser.parse_args()
    if args.out_file and args.creds_file:
        print("Use out dir (-O) instead of out file (-o) if using a creds file (-C)")
        parser.exit(1)

    if args.creds:
        creds_input = [args.creds]
    elif args.creds_file:
        with open(args.creds_file) as f:
            creds_input = f.readlines()
    else:
        print(
            "Creds must be specified either as an argument (-c) or a creds file (-C). To test for unauthenticated shares, use `-c /:`"
        )
        parser.exit(1)
    creds_list = [parse_credentials(ci) for ci in creds_input]
    if len(set([serialize(creds) for creds in creds_list])) != len(creds_list):
        raise Exception("Duplicated users are not allowed")

    with open("/dev/stdin" if args.targets == "-" else args.targets) as f:
        targets = [line.strip() for line in f]
    scan_res: Dict[str, Dict[str, Scan]] = {
        serialize(creds): dict() for creds in creds_list
    }
    loop_e = None
    with Pool(args.threads) as pool:
        it = pool.imap_unordered(
            list_shares_multicred, [(creds_list, target) for target in targets]
        )
        for i in range(len(targets)):
            try:
                # list_shares sends 3 requests, so allow each of them to almost
                # time out plus a buffer second. This timeout should never
                # trigger unless there's a bug somewhere.
                host, res = it.next(timeout=REQUEST_TIMEOUT * 3 * len(creds_list) + 1)
                for serialized_creds, scan in res.items():
                    scan_res[serialized_creds][host] = scan
                    print(
                        f'{i}/{len(targets)} scanned {host} with {serialized_creds},{" error: " + scan["errtype"] if scan["errtype"] else ""} {"ADMIN" if scan.get("admin") else ""}'
                    )
            except Exception as e:
                # If you see this, please file an issue
                print(
                    f"Error in main loop: '{e}'\n"
                    "writing partial output and exiting..."
                )
                loop_e = e
                break
    if args.out_file:
        with open(args.out_file, "w") as f:
            json.dump(scan_res[serialize(creds_list[0])], f)
    else:
        Path(args.out_dir).mkdir(exist_ok=True)
        for creds in creds_list:
            with Path(args.out_dir, serialize(creds) + ".json").open("w") as f:
                json.dump(scan_res[serialize(creds)], f)
    if loop_e:
        raise loop_e


if __name__ == "__main__":
    main()
