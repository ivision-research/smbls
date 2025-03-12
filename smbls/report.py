#!/usr/bin/env python3

import argparse
import json
import shlex
from sys import stderr
from typing import Any, Callable, Dict, Tuple, Union

try:
    from .version import __version__
except ImportError:
    print("Warning: not running from module. Can't verify compatibility.")
    __version__ = "fake"

Scan = Dict[str, Any]
ScanData = Dict[str, Any]
HostData = Dict[str, Any]
ShareData = Dict[str, Any]


def pretty_host(host: str, scan_data: ScanData) -> str:
    info = scan_data[host].get("info", {})
    hostname = info.get("getServerName", "")
    if not hostname.strip().strip("\x00"):
        hostname = info.get("getRemoteName", "")
    if not hostname.strip().strip("\x00"):
        hostname = host
    return str(hostname)


def hosts_select_admin(host_data: HostData) -> bool:
    for share in host_data.get("shares", ""):
        # This is just a heuristic, but it's a pretty reliable one
        if (share.get("name") == "C$" or share.get("name") == "ADMIN$") and share.get(
            "read_access"
        ):
            return True
    return False


def hosts_select_error(host_data: HostData) -> bool:
    return "errtype" in host_data


def hosts_print_os(host_data: HostData) -> str:
    return str(host_data.get("info", {}).get("getServerOS", "-"))


def hosts_print_signing(host_data: HostData) -> str:
    return str(host_data.get("info", {}).get("isSigningRequired", "-"))


def hosts_print_smbver(host_data: HostData) -> str:
    return str(host_data.get("info", {}).get("getDialect", "-"))


def hosts_print_error(host_data: HostData) -> str:
    if "errtype" in host_data:
        return f"{host_data['errtype']}: {host_data['error']}"
    else:
        return "-"


def hosts_print_shares(host_data: HostData) -> str:
    return (
        "[" + ", ".join(s.get("name", "-") for s in host_data.get("shares", {})) + "]"
    )


def shares_select_readable(share_data: ShareData) -> bool:
    return bool(share_data.get("read_access", False))


def shares_select_writable(share_data: ShareData) -> bool:
    return bool(share_data.get("write_access", False))


def shares_print_contents(share_data: ShareData) -> str:
    return str(share_data.get("contents", []))


def shares_print_dacl(share_data: ShareData) -> str:
    return str(share_data.get("dacl", "-"))


def shares_print_remark(share_data: ShareData) -> str:
    return str(share_data.get("remark", "-"))


def shares_print_errors(share_data: ShareData) -> str:
    return str(share_data.get("errors", "[]"))


def shares_print_type(share_data: ShareData) -> str:
    return str(share_data.get("type", "-"))


def shares_print_readable(share_data: ShareData) -> str:
    if "read_access" in share_data:
        return str(share_data["read_access"])
    else:
        return "not tested"


def shares_print_writable(share_data: ShareData) -> str:
    if "write_access" in share_data:
        return str(share_data["write_access"])
    else:
        return "not tested"


LOOKUPS: Dict[
    str,
    Dict[
        str, Dict[str, Tuple[Union[Callable[[Any], bool], Callable[[Any], str]], str]]
    ],
] = {
    "metadata": {
        "select": {},
        "print": {},
    },
    "hosts": {
        "select": {
            "admin": (
                hosts_select_admin,
                "hosts where the user the scan ran as had admin",
            ),
            "error": (hosts_select_error, "hosts where there was an error connecting"),
            "noerror": (
                lambda x: not hosts_select_error(x),
                "hosts where there was no error connecting",
            ),
        },
        "print": {
            "error": (hosts_print_error, "the connection error"),
            "os": (hosts_print_os, "OS information"),
            "shares": (hosts_print_shares, "the list of shares"),
            "signing": (hosts_print_signing, "whether SMB signing is required"),
            "smbver": (hosts_print_smbver, "the SMB version used"),
        },
    },
    "shares": {
        "select": {
            "readable": (
                shares_select_readable,
                "shares readable by the scan user",
            ),
            "writable": (
                shares_select_writable,
                "shares writable by the scan user",
            ),
        },
        "print": {
            "contents": (
                shares_print_contents,
                "file listing of the root directory of the share",
            ),
            "dacl": (shares_print_dacl, "permissions list"),
            "remark": (shares_print_remark, "text label added to share"),
            "type": (shares_print_type, "share type"),
            "errors": (
                shares_print_errors,
                "errors raised while gathering information",
            ),
            "readable": (shares_print_readable, "whether share was readable or not"),
            "writable": (shares_print_writable, "whether share was writable or not"),
        },
    },
}


def metadata(scan: Scan) -> None:
    for k, v in scan.items():
        if k == "data":
            continue
        print(k, v)


def hosts(scan: Scan, select_args: list[str], print_args: list[str]) -> None:
    scan_data: ScanData = scan["data"]
    for host, host_data in scan_data.items():
        for sa in select_args:
            if not LOOKUPS["hosts"]["select"][sa][0](host_data):
                break
        else:
            res = [host, pretty_host(host, scan_data)]
            res.extend(
                str(LOOKUPS["hosts"]["print"][pa][0](host_data)) for pa in print_args
            )
            print("\t".join(res))


def shares(scan: Scan, select_args: list[str], print_args: list[str]) -> None:
    scan_data: ScanData = scan["data"]
    for host, host_data in scan_data.items():
        for share_data in host_data.get("shares", {}):
            for sa in select_args:
                if not LOOKUPS["shares"]["select"][sa][0](share_data):
                    break
            else:
                res = [
                    host,
                    pretty_host(host, scan_data),
                    shlex.quote(share_data.get("name", "-")),
                ]
                res.extend(
                    str(LOOKUPS["shares"]["print"][pa][0](share_data))
                    for pa in print_args
                )
                print("\t".join(res))


def report() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Report types:\n"
        + "\n".join(
            f"`{report_type}`:\n"
            + "\n".join(
                f"\t{arg_type} arguments:\n"
                + "\n".join(
                    f"\t\t{arg_name} -- {arg_data[1]}"
                    for arg_name, arg_data in LOOKUPS[report_type][arg_type].items()
                )
                for arg_type in LOOKUPS[report_type]
            )
            for report_type in LOOKUPS
        )
        + """
\nExamples:

To print the name and contents of readable shares:
smblsreport -f out.json shares -s readable -p contents

To print the name, if signing is required, and the SMB version of hosts where
the scanning user has admin access:
smblsreport -f out.json hosts -s admin -p signing,smbver
""",
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
        help="report on this type of data",
        choices=("metadata", "hosts", "shares"),
    )
    parser.add_argument(
        "-s",
        dest="select",
        help="select (filter) data based on these criteria. Format as a comma-separated list. Values depend on the report type; pass 'list' or see below",
    )
    parser.add_argument(
        "-p",
        dest="print",
        help="print selected attributes. Format as a comma-separated list. Values depend on the report type; pass 'list' or see below",
    )
    args = parser.parse_args()

    if args.select == "list":
        if args.print == "list":
            stderr.write("error: pass only one list argument at a time")
            exit(1)
        for sel, o in LOOKUPS[args.command]["select"].items():
            print(f"{sel}: {o[1]}")
        return
    if args.print == "list":
        for sel, o in LOOKUPS[args.command]["print"].items():
            print(f"{sel}: {o[1]}")
        return
    select_args = args.select.split(",") if args.select else []
    print_args = args.print.split(",") if args.print else []
    if not all(sa in LOOKUPS[args.command]["select"] for sa in select_args):
        stderr.write("error: invalid select argument\n")
        return
    if not all(pa in LOOKUPS[args.command]["print"] for pa in print_args):
        stderr.write("error: invalid print argument\n")
        return

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
            # TODO maybe add more logic here
            stderr.write(
                f"warning: installed version {__version__}, data version {res['version']}\n"
            )
    if args.command == "metadata":
        metadata(res)
    elif args.command == "hosts":
        hosts(res, select_args, print_args)
    elif args.command == "shares":
        shares(res, select_args, print_args)


if __name__ == "__main__":
    report()
