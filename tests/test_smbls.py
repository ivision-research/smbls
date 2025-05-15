import json
import unittest
from io import StringIO
from unittest.mock import MagicMock, call, mock_open, patch

from impacket.ldap import ldaptypes
from impacket.nmb import NetBIOSTimeout
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.smb import SharedFile
from impacket.smb3structs import SMB2_DIALECT_311, SMB2TreeConnect_Response, SMB3Packet
from impacket.smbconnection import SessionError

import smbls
from smbls.smbls import (
    parse_credentials,
    normalize_access_mask,
    render_access_mask,
    render_sid,
    serialize,
    connectTree,
    si_share_perms,
    si_dacl,
    si_list,
    si_write,
    share_info,
    list_shares,
    list_shares_multicred,
    main,
)


class TestCredentialParsing(unittest.TestCase):
    def test_hashes(self) -> None:
        self.assertEqual(
            parse_credentials(
                "domain/user#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            {
                "domain": "domain",
                "username": "user",
                "lmhash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "nthash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )
        self.assertEqual(
            parse_credentials(
                "/#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            {
                "domain": "",
                "username": "",
                "lmhash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "nthash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )
        self.assertEqual(
            parse_credentials(
                "/#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
            ),
            {
                "domain": "",
                "username": "#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            },
        )

    def test_hashes_nolmhash(self) -> None:
        # I thought about making hashes optional, but because "user#" is a
        # valid NT username
        # (https://learn.microsoft.com/en-us/previous-versions//cc722458(v=technet.10)?redirectedfrom=MSDN),
        # this would prevent authenticating as accounts ending with a "#" with
        # a password of 32 characters.
        self.assertEqual(
            parse_credentials("/user#:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            {
                "domain": "",
                "username": "user#",
                "password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )

    def test_passwords(self) -> None:
        self.assertEqual(
            parse_credentials("localhost/administrator:Password1!"),
            {
                "domain": "localhost",
                "username": "administrator",
                "password": "Password1!",
            },
        )
        self.assertEqual(
            parse_credentials("/:"),
            {"domain": "", "username": "", "password": ""},
        )
        self.assertEqual(
            parse_credentials("/#:"),
            {"domain": "", "username": "#", "password": ""},
        )
        self.assertEqual(
            parse_credentials(
                "/#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            {
                "domain": "",
                "username": "#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
                "password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        )
        self.assertEqual(
            parse_credentials(
                "/#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax"
            ),
            {
                "domain": "",
                "username": "#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
            },
        )

    def test_invalid(self) -> None:
        with self.assertRaises(ValueError):
            parse_credentials("")
        with self.assertRaises(ValueError):
            parse_credentials("/")
        with self.assertRaises(ValueError):
            parse_credentials(":")
        with self.assertRaises(ValueError):
            parse_credentials(
                "#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )


class TestNormalizingAccessMask(unittest.TestCase):
    def test_directory(self) -> None:
        self.assertEqual(normalize_access_mask(0x0, "DISKTREE"), 0x0)
        self.assertEqual(
            normalize_access_mask(0x10000000, "DISKTREE"),
            0x00000001
            | 0x00000002
            | 0x00000004
            | 0x00000008
            | 0x00000010
            | 0x00000020
            | 0x00000040
            | 0x00000080
            | 0x00000100
            | 0x00010000
            | 0x00020000
            | 0x00040000
            | 0x00080000
            | 0x00100000
            | 0x10000000  # GENERIC_ALL
            | 0x20000000  # GENERIC_EXECUTE
            | 0x40000000  # GENERIC_WRITE
            | 0x80000000,  # GENERIC_READ
        )
        self.assertEqual(
            normalize_access_mask(0x20000000, "DISKTREE"),
            0x00000020 | 0x00000080 | 0x00100000 | 0x00020000 | 0x20000000,
        )
        self.assertEqual(
            normalize_access_mask(0x40000000, "DISKTREE"),
            0x00000002
            | 0x00000004
            | 0x00000100
            | 0x00000010
            | 0x00100000
            | 0x00020000
            | 0x40000000,
        )
        self.assertEqual(
            normalize_access_mask(0x80000000, "DISKTREE"),
            0x00000001 | 0x00000080 | 0x00000008 | 0x00100000 | 0x00020000 | 0x80000000,
        )

        self.assertEqual(
            normalize_access_mask(0x20000000, "other|DISKTREE|other"),
            0x00000020 | 0x00000080 | 0x00100000 | 0x00020000 | 0x20000000,
        )

    def test_filepipeprinter(self) -> None:
        self.assertEqual(normalize_access_mask(0x0, "IPC"), 0x0)
        self.assertEqual(
            normalize_access_mask(0x10000000, "IPC"),
            0x00000001
            | 0x00000002
            | 0x00000004
            | 0x00000008
            | 0x00000010
            | 0x00000020
            | 0x00000040
            | 0x00000080
            | 0x00000100
            | 0x00010000
            | 0x00020000
            | 0x00040000
            | 0x00080000
            | 0x00100000
            | 0x10000000  # GENERIC_ALL
            | 0x20000000  # GENERIC_EXECUTE
            | 0x40000000  # GENERIC_WRITE
            | 0x80000000,  # GENERIC_READ
        )
        self.assertEqual(
            normalize_access_mask(0x20000000, "IPC"),
            0x00000020 | 0x00000080 | 0x00100000 | 0x00020000 | 0x20000000,
        )
        self.assertEqual(
            normalize_access_mask(0x40000000, "IPC"),
            0x00000002
            | 0x00000004
            | 0x00000100
            | 0x00000010
            | 0x00100000
            | 0x00020000
            | 0x40000000,
        )
        self.assertEqual(
            normalize_access_mask(0x80000000, "IPC"),
            0x00000001 | 0x00000080 | 0x00000008 | 0x00100000 | 0x00020000 | 0x80000000,
        )


class TestRenderingAccessMask(unittest.TestCase):
    def test_directory(self) -> None:
        self.assertEqual(render_access_mask(0x0, "DISKTREE"), "")
        self.assertEqual(
            render_access_mask(
                normalize_access_mask(
                    0x00000001 | 0x00000080 | 0x00000008 | 0x00100000 | 0x00020000,
                    "DISKTREE",
                ),
                "DISKTREE",
            ),
            "GENERIC_READ",
        )
        self.assertEqual(render_access_mask(0x80000000, "DISKTREE"), "GENERIC_READ")
        self.assertEqual(
            render_access_mask(
                normalize_access_mask(
                    0x00000001
                    | 0x00000002
                    | 0x00000080
                    | 0x00000008
                    | 0x00100000
                    | 0x00020000,
                    "DISKTREE",
                ),
                "DISKTREE",
            ),
            "GENERIC_READ|FILE_ADD_FILE",
        )
        self.assertEqual(
            render_access_mask(0x80000002, "DISKTREE"), "GENERIC_READ|FILE_ADD_FILE"
        )

    def test_filepipeprinter(self) -> None:
        self.assertEqual(render_access_mask(0x0, "IPC"), "")
        self.assertEqual(
            render_access_mask(
                normalize_access_mask(
                    0x00000001 | 0x00000080 | 0x00000008 | 0x00100000 | 0x00020000,
                    "IPC",
                ),
                "IPC",
            ),
            "GENERIC_READ",
        )
        self.assertEqual(render_access_mask(0x80000000, "IPC"), "GENERIC_READ")
        self.assertEqual(
            render_access_mask(
                normalize_access_mask(
                    0x00000001
                    | 0x00000002
                    | 0x00000080
                    | 0x00000008
                    | 0x00100000
                    | 0x00020000,
                    "IPC",
                ),
                "IPC",
            ),
            "GENERIC_READ|FILE_WRITE_DATA",
        )
        self.assertEqual(
            render_access_mask(0x80000002, "IPC"), "GENERIC_READ|FILE_WRITE_DATA"
        )


class TestRenderingSID(unittest.TestCase):
    def test_sid(self) -> None:
        self.assertEqual(render_sid("S-1-0-0"), "Null SID")
        self.assertEqual(render_sid("S-1-5-32-544"), "Administrators")
        self.assertEqual(render_sid("S-1-5-21-1-2-3-500"), "Administrator (21-1-2-3)")


class TestSerializingCreds(unittest.TestCase):
    def test_serialize(self) -> None:
        self.assertEqual(serialize({}, human=True), "/")
        self.assertEqual(serialize({}, human=False), "_")
        self.assertEqual(serialize({"domain": "", "username": ""}, human=True), "/")
        self.assertEqual(serialize({"domain": "", "username": ""}, human=False), "_")
        self.assertEqual(
            serialize({"domain": "localhost", "username": "administrator"}, human=True),
            "localhost/administrator",
        )
        self.assertEqual(
            serialize(
                {"domain": "localhost", "username": "administrator"}, human=False
            ),
            "localhost_administrator",
        )


def make_acl(access_mask: int, sid: str) -> ldaptypes.ACL:
    nace = ldaptypes.ACE()
    nace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = access_mask
    acedata["Sid"] = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(sid)
    nace["Ace"] = acedata
    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = [
        nace,
    ]
    return acl


def make_smb3conn(
    max_access: int = 0,
    treeid: int = 1,
    denied: bool = False,
    sessionid: int = 0,
    fileid: int = 0,
    dacl: ldaptypes.ACL | bytes = b"",
) -> MagicMock:
    smbconn = MagicMock()
    smbconn._Session = {"TreeConnectTable": dict()}
    smbconn._Connection = {
        "ServerIP": "10.0.0.1",
        "Dialect": SMB2_DIALECT_311,
        "SupportsEncryption": False,
    }
    smbconn.SMB_PACKET = SMB3Packet
    smbconn.sendSMB = MagicMock()
    smbconn.closeFile = MagicMock()

    ret = SMB3Packet()
    if denied:
        ret["Status"] = STATUS_ACCESS_DENIED
    else:
        ret["Status"] = STATUS_SUCCESS
    ret["TreeID"] = treeid
    ret["SessionID"] = sessionid
    ret_packet = SMB2TreeConnect_Response()
    ret_packet["MaximalAccess"] = max_access
    ret["Data"] = ret_packet.getData()
    smbconn.recvSMB = MagicMock(return_value=ret)

    smbconn.openFile = MagicMock(return_value=fileid)

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = dacl
    smbconn.queryInfo = MagicMock(return_value=sd.getData())

    return smbconn


class TestConnectTree(unittest.TestCase):
    def test_connect_basic(self) -> None:
        self.assertEqual(
            connectTree(make_smb3conn(max_access=0, treeid=12345), "sharename"),
            (12345, 0),
        )
        self.assertEqual(
            connectTree(make_smb3conn(max_access=54321, treeid=12345), "sharename"),
            (12345, 54321),
        )

    def test_repeated(self) -> None:
        smbconn = make_smb3conn(max_access=0, treeid=12345)
        self.assertEqual(connectTree(smbconn, "sharename"), (12345, 0))
        self.assertEqual(connectTree(smbconn, "othersharename"), (12345, 0))
        with self.assertRaises(Exception):
            connectTree(smbconn, "sharename")


class TestSharePerms(unittest.TestCase):
    def test_shareperms(self) -> None:
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(max_access=0x100, treeid=12345)
        self.assertEqual(
            si_share_perms(smbconn, "share_name", "DISKTREE"), (True, 12345, 0x100)
        )
        with self.assertRaises(Exception):
            si_share_perms(smbconn, "share_name", "DISKTREE")

    def test_shareperms_fail(self) -> None:
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(denied=True)
        self.assertEqual(
            si_share_perms(smbconn, "share_name", "DISKTREE"), (False, -1, 0)
        )


class TestShareDacls(unittest.TestCase):
    def test_printq(self) -> None:
        self.assertEqual(si_dacl(None, 0, "PRINTQ"), None)

    def test_noaccess(self) -> None:
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(dacl=b"")
        self.assertEqual(si_dacl(smbconn, 12345, "DISKTREE"), None)

    def test_read_single(self) -> None:
        smbconn = MagicMock()
        access_mask = 983551
        sid = "S-1-5-32-544"
        smbconn._SMBConnection = make_smb3conn(
            dacl=make_acl(access_mask=access_mask, sid=sid)
        )
        self.assertEqual(
            si_dacl(smbconn, 12345, "DISKTREE"),
            [("ALLOWED", render_sid(sid), access_mask)],
        )


class TestShareListings(unittest.TestCase):
    def test_noperms(self) -> None:

        smbconn = make_smb3conn()
        smbconn.listPath = MagicMock(side_effect=SessionError(STATUS_ACCESS_DENIED))
        self.assertEqual(si_list(smbconn, "C$", False), (False, []))
        self.assertEqual(si_list(smbconn, "C$", True), (False, []))

    def test_empty(self) -> None:
        smbconn = make_smb3conn()
        smbconn.listPath = MagicMock(return_value=[])
        self.assertEqual(si_list(smbconn, "C$", False), (True, []))
        self.assertEqual(si_list(smbconn, "C$", True), (True, []))

    def test_contents(self) -> None:
        smbconn = make_smb3conn()
        smbconn.listPath = MagicMock(
            return_value=[SharedFile(0, 0, 0, 100, 100, 0, "filename", "filenamee")]
        )
        self.assertEqual(si_list(smbconn, "C$", False), (True, []))
        self.assertEqual(
            si_list(smbconn, "C$", True),
            (True, ["filename"]),
        )


class TestShareWrite(unittest.TestCase):
    def test_noperms(self) -> None:
        smbconn = make_smb3conn()
        smbconn.createDirectory = MagicMock(
            side_effect=SessionError(STATUS_ACCESS_DENIED)
        )
        self.assertEqual(si_write(smbconn, "C$"), False)

    def test_success(self) -> None:
        smbconn = make_smb3conn()
        smbconn.createDirectory = MagicMock()
        smbconn.deleteDirectory = MagicMock()
        self.assertEqual(si_write(smbconn, "C$"), True)


class TestShareInfo(unittest.TestCase):
    def test_authonly(self) -> None:
        share_name = "C$"
        share_remark = "remark"
        self.assertEqual(
            share_info(
                MagicMock(),
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x00000000,
                    "shi1_remark": share_remark + "\0",
                },
                (True, False, False, False),
            ),
            {"name": share_name, "type": "DISKTREE", "remark": share_remark},
        )
        self.assertEqual(
            share_info(
                MagicMock(),
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x80000001,
                    "shi1_remark": share_remark + "\0",
                },
                (True, False, False, False),
            ),
            {"name": share_name, "type": "PRINTQ|SPECIAL", "remark": share_remark},
        )

    def test_noperms(self) -> None:
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(denied=True)
        share_name = "C$"
        share_remark = "remark"
        self.assertEqual(
            share_info(
                smbconn,
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x00000000,
                    "shi1_remark": share_remark + "\0",
                },
                (False, False, False, False),
            ),
            {
                "name": share_name,
                "type": "DISKTREE",
                "remark": share_remark,
                "max_share_perms": "",
                "read_access": False,
            },
        )

    def test_read(self) -> None:
        access_mask = 0x80000000
        sid = "S-1-5-32-544"
        share_name = "C$"
        share_remark = "remark"
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(
            max_access=0x80000000, dacl=make_acl(access_mask=access_mask, sid=sid)
        )
        self.assertEqual(
            share_info(
                smbconn,
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x00000000,
                    "shi1_remark": share_remark + "\0",
                },
                (False, False, False, False),
            ),
            {
                "name": share_name,
                "type": "DISKTREE",
                "remark": share_remark,
                "max_share_perms": "GENERIC_READ",
                "read_access": True,
                "dacl": ["ALLOWED,Administrators,GENERIC_READ"],
            },
        )

    def test_no_write(self) -> None:
        access_mask = 0x80000000
        sid = "S-1-5-32-544"
        share_name = "C$"
        share_remark = "remark"
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(
            max_access=0x80000000, dacl=make_acl(access_mask=access_mask, sid=sid)
        )
        self.assertEqual(
            share_info(
                smbconn,
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x00000000,
                    "shi1_remark": share_remark + "\0",
                },
                (False, True, False, False),
            ),
            {
                "name": share_name,
                "type": "DISKTREE",
                "remark": share_remark,
                "max_share_perms": "GENERIC_READ",
                "read_access": True,
                "write_access": False,
                "dacl": ["ALLOWED,Administrators,GENERIC_READ"],
            },
        )

    def test_ipc(self) -> None:
        access_mask = 0x10000000
        sid = "S-1-5-32-544"
        share_name = "IPC"
        share_remark = "remark"
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(
            max_access=0x10000000, dacl=make_acl(access_mask=access_mask, sid=sid)
        )
        smbconn.listPath = MagicMock(
            return_value=[SharedFile(0, 0, 0, 100, 100, 0, "filename", "filenamee")]
        )
        self.assertEqual(
            share_info(
                smbconn,
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x80000003,
                    "shi1_remark": share_remark + "\0",
                },
                (False, True, True, True),
            ),
            {
                "name": share_name,
                "type": "IPC|SPECIAL",
                "remark": share_remark,
                "max_share_perms": "GENERIC_ALL",
                "read_access": True,
                "write_access": None,
                "dacl": ["ALLOWED,Administrators,GENERIC_ALL"],
                "contents": [
                    "filename",
                ],
            },
        )


class TestListingShares(unittest.TestCase):
    @patch("impacket.smbconnection.SMBConnection")
    def test_conn_errors(self, SMBConnection_mock: MagicMock) -> None:
        SMBConnection_mock.side_effect = OSError()
        self.assertEqual(
            list_shares({}, (False, False, False, False), ""),
            {"errtype": "conn", "error": "None"},
        )
        SMBConnection_mock.side_effect = SessionError(STATUS_ACCESS_DENIED)
        self.assertEqual(
            list_shares({}, (False, False, False, False), ""),
            {"errtype": "auth", "error": "STATUS_ACCESS_DENIED"},
        )
        SMBConnection_mock.side_effect = NetBIOSTimeout
        self.assertEqual(
            list_shares({}, (False, False, False, False), ""),
            {"errtype": "timeout", "error": "timed out logging in"},
        )
        SMBConnection_mock.side_effect = Exception("fail")
        self.assertEqual(
            list_shares({}, (False, False, False, False), ""),
            {"errtype": "unknown_init", "error": "fail"},
        )

    @patch("impacket.smbconnection.SMBConnection")
    def test_no_shares(self, SMBConnection_mock: MagicMock) -> None:
        smbconn = MagicMock()
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
            setattr(smbconn, attr, MagicMock(return_value="x"))
        del smbconn.getServerDomain
        SMBConnection_mock.return_value = smbconn
        self.assertEqual(
            list_shares({}, (False, False, False, False), ""),
            {
                "info": {
                    "doesSupportNTLMv2": "x",
                    "getDialect": "x",
                    "getRemoteHost": "x",
                    "getRemoteName": "x",
                    "getServerDNSDomainName": "x",
                    "getServerDNSHostName": "x",
                    "getServerDomain": "error: getServerDomain",
                    "getServerName": "x",
                    "getServerOS": "x",
                    "isLoginRequired": "x",
                    "isSigningRequired": "x",
                },
                "shares": [],
            },
        )

    @patch("impacket.smbconnection.SMBConnection")
    def test_err_shares(self, SMBConnection_mock: MagicMock) -> None:
        smbconn = MagicMock()
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
            setattr(smbconn, attr, MagicMock(return_value="x"))
        smbconn.listShares = MagicMock(side_effect=Exception())
        SMBConnection_mock.return_value = smbconn
        # Don't hardcode traceback
        res = list_shares({}, (False, False, False, False), "")
        self.assertRegex(res["error"], "Traceback.*")
        self.assertEqual(res["errtype"], "shares")

    @patch("impacket.smbconnection.SMBConnection")
    def test_full(self, SMBConnection_mock: MagicMock) -> None:
        access_mask = 0x10000000
        sid = "S-1-5-32-544"
        share_name = "C$"
        share_remark = "remark"
        smbconn = MagicMock()
        smbconn._SMBConnection = make_smb3conn(
            max_access=0x10000000, dacl=make_acl(access_mask=access_mask, sid=sid)
        )
        smbconn.listPath = MagicMock(
            return_value=[SharedFile(0, 0, 0, 100, 100, 0, "filename", "filenamee")]
        )
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
            setattr(smbconn, attr, MagicMock(return_value="x"))
        share_name = "C$"
        share_remark = "remark"
        smbconn.listShares = MagicMock(
            return_value=[
                {
                    "shi1_netname": share_name + "\0",
                    "shi1_type": 0x00000000,
                    "shi1_remark": share_remark + "\0",
                }
            ]
        )
        SMBConnection_mock.return_value = smbconn
        self.assertEqual(
            list_shares({}, (False, True, True, False), ""),
            {
                "info": {
                    "doesSupportNTLMv2": "x",
                    "getDialect": "x",
                    "getRemoteHost": "x",
                    "getRemoteName": "x",
                    "getServerDNSDomainName": "x",
                    "getServerDNSHostName": "x",
                    "getServerDomain": "x",
                    "getServerName": "x",
                    "getServerOS": "x",
                    "isLoginRequired": "x",
                    "isSigningRequired": "x",
                },
                "shares": [
                    {
                        "name": share_name,
                        "type": "DISKTREE",
                        "remark": share_remark,
                        "max_share_perms": "GENERIC_ALL",
                        "read_access": True,
                        "write_access": True,
                        "dacl": ["ALLOWED,Administrators,GENERIC_ALL"],
                        "contents": [
                            "filename",
                        ],
                    },
                ],
            },
        )


class TestListingSharesMulticred(unittest.TestCase):
    @patch("smbls.smbls.list_shares")
    def test_interface(self, list_shares_mock: MagicMock) -> None:
        hostname = "hostname"
        res = list_shares_multicred(
            (
                (
                    {
                        "domain": "localhost",
                        "username": "administrator",
                        "password": "Password1!",
                    },
                    {
                        "domain": "domain",
                        "username": "user",
                        "password": "Password1!",
                    },
                ),
                (False, False, False, False),
                hostname,
            )
        )
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0], hostname)
        self.assertIn("localhost_administrator", res[1])
        self.assertIn("domain_user", res[1])
        list_shares_mock.assert_has_calls(
            [
                call(
                    {
                        "domain": "localhost",
                        "username": "administrator",
                        "password": "Password1!",
                    },
                    (False, False, False, False),
                    "hostname",
                ),
                call(
                    {
                        "domain": "domain",
                        "username": "user",
                        "password": "Password1!",
                    },
                    (False, False, False, False),
                    "hostname",
                ),
            ],
            any_order=True,
        )


# Library interface
class TestRunScan(unittest.TestCase):
    @patch("multiprocessing.pool.Pool.imap_unordered")
    def test_interface(self, imap: MagicMock) -> None:
        creds_list = [
            {
                "domain": "localhost",
                "username": "Administrator",
                "password": "Password1!",
            },
            {
                "domain": "domain",
                "username": "user",
                "password": "Password1!",
            },
        ]
        list(
            smbls.run_scan(
                targets=["10.0.0.1", "localhost"],
                creds_list=creds_list,
            )
        )
        imap.assert_called_once_with(
            list_shares_multicred,
            [
                (
                    tuple(creds_list),
                    (False, False, True, False),
                    "10.0.0.1",
                ),
                (
                    tuple(creds_list),
                    (False, False, True, False),
                    "localhost",
                ),
            ],
        )


class TestCli(unittest.TestCase):
    fake_scan_admin = {
        "info": {
            "doesSupportNTLMv2": "x",
            "getDialect": "x",
            "getRemoteHost": "x",
            "getRemoteName": "x",
            "getServerDNSDomainName": "x",
            "getServerDNSHostName": "x",
            "getServerDomain": "x",
            "getServerName": "x",
            "getServerOS": "x",
            "isLoginRequired": "x",
            "isSigningRequired": "x",
        },
        "shares": [
            {
                "name": "C$",
                "type": "DISKTREE",
                "remark": "C",
                "max_share_perms": "GENERIC_ALL",
                "read_access": True,
                "write_access": True,
                "dacl": ["ALLOWED,Administrators,GENERIC_ALL"],
                "contents": ["filename"],
            },
        ],
    }
    fake_scan_notadmin = {
        "info": {
            "doesSupportNTLMv2": "x",
            "getDialect": "x",
            "getRemoteHost": "x",
            "getRemoteName": "x",
            "getServerDNSDomainName": "x",
            "getServerDNSHostName": "x",
            "getServerDomain": "x",
            "getServerName": "x",
            "getServerOS": "x",
            "isLoginRequired": "x",
            "isSigningRequired": "x",
        },
        "shares": [
            {
                "name": "C$",
                "type": "DISKTREE",
                "remark": "C",
                "max_share_perms": "",
                "read_access": False,
                "write_access": False,
            },
        ],
    }
    fake_scan_error = {"errtype": "auth", "error": "STATUS_ACCESS_DENIED"}

    @patch("smbls.smbls.run_scan")
    @patch("smbls.smbls.open")
    @patch("sys.stdout", new_callable=StringIO)
    def test_singlecred(
        self, stdout_mock: StringIO, open_mock: MagicMock, run_scan_mock: MagicMock
    ) -> None:
        out_file = "out.json"
        creds = {"domain": "domain", "username": "user", "password": "pass"}
        targets = ["notadminhost", "adminhost", "failhost"]
        run_scan_mock.return_value.__next__.side_effect = iter(
            [
                tuple([targets[0], {serialize(creds): self.fake_scan_notadmin}]),
                tuple([targets[1], {serialize(creds): self.fake_scan_admin}]),
                tuple([targets[2], {serialize(creds): self.fake_scan_error}]),
            ]
        )
        filetype_mock = MagicMock(return_value=mock_open(read_data="\n".join(targets)))
        with patch("argparse.FileType", filetype_mock):
            with patch(
                "sys.argv",
                ["smbls", "-c", "domain/user:pass", "-o", out_file, "targetfile"],
            ):
                main()
        run_scan_mock.assert_has_calls(
            [call(targets, [creds], False, False, False, False, 32)]
            + [call().__next__()] * len(targets)
        )
        open_mock.assert_has_calls([call(out_file, "w"), call().__enter__()])
        json_data = json.loads(
            "".join(
                [
                    c[1][0]
                    for c in open_mock.mock_calls
                    if c[0] == "().__enter__().write"
                ]
            )
        )
        self.assertIn("version", json_data)
        self.assertEqual(json_data["version"], smbls.__version__)
        self.assertIn("version_tuple", json_data)
        self.assertEqual(tuple(json_data["version_tuple"]), smbls.__version_tuple__)
        self.assertIn("start_time", json_data)
        self.assertIn("end_time", json_data)
        self.assertIn("args", json_data)
        self.assertIn("creds", json_data)
        self.assertEqual(json_data["creds"], creds)
        self.assertIn("data", json_data)
        self.assertEqual(
            json_data["data"],
            {
                targets[0]: self.fake_scan_notadmin,
                targets[1]: self.fake_scan_admin,
                targets[2]: self.fake_scan_error,
            },
        )
        self.assertEqual(
            stdout_mock.getvalue(),
            """[host 1/3, creds 1/1][suc] scanned host notadminhost with user domain/user
[host 2/3, creds 1/1][adm] scanned host adminhost with user domain/user, ADMIN
[host 3/3, creds 1/1][err] scanned host failhost with user domain/user, error: auth
""",
        )

    @patch("smbls.smbls.run_scan")
    def test_multicred(self, run_scan_mock: MagicMock) -> None:
        out_dir = "outdir"
        creds_list = [
            {"domain": "domain", "username": "user", "password": "pass"},
            {"domain": "domain", "username": "adminuser", "password": "Password1!"},
        ]
        targets = ["notadminhost", "adminhost", "failhost"]
        run_scan_mock.return_value.__next__.side_effect = iter(
            [
                tuple(
                    [
                        targets[0],
                        {
                            serialize(creds_list[0]): self.fake_scan_notadmin,
                            serialize(creds_list[1]): self.fake_scan_notadmin,
                        },
                    ]
                ),
                tuple(
                    [
                        targets[1],
                        {
                            serialize(creds_list[0]): self.fake_scan_admin,
                            serialize(creds_list[1]): self.fake_scan_admin,
                        },
                    ]
                ),
                tuple(
                    [
                        targets[2],
                        {
                            serialize(creds_list[0]): self.fake_scan_error,
                            serialize(creds_list[1]): self.fake_scan_error,
                        },
                    ]
                ),
            ]
        )
        filetype_mock = MagicMock(return_value=mock_open(read_data="\n".join(targets)))
        open_mock = mock_open(
            read_data="\n".join(
                serialize(creds, human=True) + ":" + creds["password"]
                for creds in creds_list
            )
            + "\n"
        )
        path_mkdir_mock = MagicMock()
        path_open_mock = MagicMock()
        stdout = StringIO()
        with (
            patch("argparse.FileType", filetype_mock),
            patch(
                "sys.argv",
                ["smbls", "-C", "credsfile", "-O", out_dir, "targetfile"],
            ),
            patch("smbls.smbls.open", open_mock),
            patch("sys.stdout", stdout),
        ):
            # It's unclear why this doesn't work
            # with patch("pathlib.Path", path_mock):
            # Interestingly, this seems to patch but then throws an error
            # with patch("pathlib._local.PurePath", path_mock):
            with (
                patch("pathlib.Path.open", path_open_mock),
                patch("pathlib.Path.mkdir", path_mkdir_mock),
            ):
                main()
        run_scan_mock.assert_has_calls(
            [call(targets, creds_list, False, False, False, False, 32)]
            + [call().__next__()] * len(targets)
        )
        path_mkdir_mock.assert_called_once_with(exist_ok=True)
        self.assertEqual(
            stdout.getvalue(),
            """[host 1/3, creds 1/2][suc] scanned host notadminhost with user domain/user
[host 1/3, creds 2/2][suc] scanned host notadminhost with user domain/adminuser
[host 2/3, creds 1/2][adm] scanned host adminhost with user domain/user, ADMIN
[host 2/3, creds 2/2][adm] scanned host adminhost with user domain/adminuser, ADMIN
[host 3/3, creds 1/2][err] scanned host failhost with user domain/user, error: auth
[host 3/3, creds 2/2][err] scanned host failhost with user domain/adminuser, error: auth
""",
        )
        i = 0
        for creds in creds_list:
            self.assertEqual(path_open_mock.mock_calls[i], call("w"))
            i += 1
            self.assertEqual(path_open_mock.mock_calls[i], call().__enter__())
            i += 1
            writes: list[str] = list()
            while path_open_mock.mock_calls[i][0] == "().__enter__().write":
                writes.append(path_open_mock.mock_calls[i][1][0])
                i += 1
            self.assertEqual(
                path_open_mock.mock_calls[i], call().__exit__(None, None, None)
            )
            i += 1
            json_data = json.loads("".join(writes))
            self.assertIn("version", json_data)
            self.assertEqual(json_data["version"], smbls.__version__)
            self.assertIn("version_tuple", json_data)
            self.assertEqual(tuple(json_data["version_tuple"]), smbls.__version_tuple__)
            self.assertIn("start_time", json_data)
            self.assertIn("end_time", json_data)
            self.assertIn("args", json_data)
            self.assertIn("creds", json_data)
            self.assertEqual(json_data["creds"], creds)
            self.assertIn("data", json_data)
            self.assertEqual(
                json_data["data"],
                {
                    targets[0]: self.fake_scan_notadmin,
                    targets[1]: self.fake_scan_admin,
                    targets[2]: self.fake_scan_error,
                },
            )


if __name__ == "__main__":
    unittest.main()
