#!/usr/bin/env python3
import argparse
from sys import stderr
import json
from copy import deepcopy
from typing import Any, Dict, Tuple, List

try:
    from .version import __version__
except ImportError:
    print("Warning: not running from module. Can't verify compatibility.")
    __version__ = "fake"

Scan = Dict[str, Any]
ScanData = Dict[str, Any]
HostData = Dict[str, Any]
ShareData = Dict[str, Any]


def dedupe(scan: Scan) -> Scan:
    dupe_data_lookups: Dict[Tuple[Tuple[str, Any], ...], List[str]] = dict()
    scan_data: ScanData = scan["data"]
    for host, host_data in scan_data.items():
        if "errtype" in host_data:
            continue
        dupe_data_entry = list()
        for attr in [
            "getServerDomain",
            "getServerOS",
            "getDialect",
            "isLoginRequired",
            "isSigningRequired",
            "doesSupportNTLMv2",
            "getRemoteName",
            "getServerName",
            "getServerDNSDomainName",
            "getServerDNSHostName",
        ]:
            dupe_data_entry.append((attr, host_data["info"][attr]))
        for share_data in sorted(host_data["shares"], key=lambda sd: sd["name"]):
            for share_key in "name", "type", "remark":
                dupe_data_entry.append((share_key, share_data.get(share_key, "-")))
            if "dacl" in share_data:
                dupe_data_entry.append(("dacl", tuple(share_data["dacl"])))
            if "contents" in share_data:
                dupe_data_entry.append(
                    ("contents", tuple(sorted(share_data["contents"])))
                )
        dupe_data_key = tuple(dupe_data_entry)
        if dupe_data_key in dupe_data_lookups:
            dupe_data_lookups[dupe_data_key].append(host)
        else:
            dupe_data_lookups[dupe_data_key] = [
                host,
            ]

    for key, host_list in dupe_data_lookups.items():
        if len(host_list) == 1:
            continue
        assert len(host_list) > 1
        primary_host = host_list[0]
        scan_data[primary_host]["info"]["duplicate_hosts"] = host_list[1:]
        primary_share_table = {s["name"]: s for s in scan_data[primary_host]["shares"]}
        for host in host_list[1:]:
            for share_data in scan_data[host]["shares"]:
                share_name = share_data["name"]
                if not primary_share_table[share_name].get(
                    "write_access"
                ) and share_data.get("write_access"):
                    print("setting write", share_name)
                    primary_share_table[share_name]["write_access"] = True
            del scan_data[host]
        scan_data[primary_host]["shares"] = list(primary_share_table.values())

    return scan


def postprocess() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="subcommands:\n  dedupe       remove duplicate targets pointing to the same host using a heuristic",
    )
    parser.add_argument(
        "-V",
        action="version",
        version=__version__,
    )
    parser.add_argument(
        "-f",
        dest="file",
        help="load smbls output file",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        dest="command",
        help="do what to the scan output",
        choices=("dedupe",),
    )
    parser.add_argument(
        "-o",
        dest="out_file",
        help="file to write output to. stdout is used if not specified",
    )
    args = parser.parse_args()

    if not args.file:
        stderr.write("error: must pass -f file\n")
        return
    res: Scan = json.load(args.file)
    args.file.close()
    if "version" not in res:
        stderr.write("error: scan data is from before smbls version 2\n")
        exit(1)
    else:
        if res["version"] != __version__ or __version__ == "fake":
            stderr.write(
                f"warning: installed version {__version__}, data version {res['version']}\n"
            )

    processed_res: Scan
    if args.command == "dedupe":
        processed_res = dedupe(deepcopy(res))

    if not args.out_file or args.out_file == "-":
        print(json.dumps(processed_res))
    else:
        with open(args.out_file, "w") as f:
            json.dump(processed_res, f)


if __name__ == "__main__":
    postprocess()
