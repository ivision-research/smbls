#!/usr/bin/env python3

import argparse
import copy
import json
import re
import socket
import traceback
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Generator

from impacket import smb3, smb3structs, smbconnection
from impacket.dcerpc.v5 import srvs
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.nmb import NetBIOSTimeout
from impacket.nt_errors import (
    STATUS_ACCESS_DENIED,
    STATUS_NO_SUCH_FILE,
    STATUS_OBJECT_NAME_COLLISION,
    STATUS_SUCCESS,
    STATUS_LOGON_FAILURE,
)
from impacket.smb3structs import (
    DACL_SECURITY_INFORMATION,
    DELETE,
    FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY,
    FILE_APPEND_DATA,
    FILE_DELETE_CHILD,
    FILE_DIRECTORY_FILE,
    FILE_EXECUTE,
    FILE_LIST_DIRECTORY,
    FILE_OPEN,
    FILE_READ_ATTRIBUTES,
    FILE_READ_DATA,
    FILE_READ_EA,
    FILE_SHARE_READ,
    FILE_TRAVERSE,
    FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA,
    FILE_WRITE_EA,
    GENERIC_ALL,
    GENERIC_EXECUTE,
    GENERIC_READ,
    GENERIC_WRITE,
    READ_CONTROL,
    SMB2_0_INFO_SECURITY,
    SMB2_DIALECT_30,
    SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY,
    SMB2_SHARE_CAP_DFS,
    SMB2_SHARE_CAP_SCALEOUT,
    SMB2_SHAREFLAG_ENCRYPT_DATA,
    SMB2_TREE_CONNECT,
    SYNCHRONIZE,
    WRITE_DAC,
    WRITE_OWNER,
    SMB2TreeConnect,
    SMB2TreeConnect_Response,
)

try:
    from .version import __version__, __version_tuple__
except ImportError:
    print("Warning: not running from module. Using fake version information.")
    __version__ = "fake"
    __version_tuple__ = (-1, -1, -1)


# Max time in seconds for each impacket SMB request
REQUEST_TIMEOUT = 5

Creds = Dict[str, str]
Scan = Dict[str, Any]
ShareOptions = Tuple[bool, bool, bool, bool]

password_regex = re.compile(r"(?P<domain>[^/:]*)/(?P<username>[^:]*):(?P<password>.*)")
hash_regex = re.compile(
    r"(?P<domain>[^/:]*)/(?P<username>[^#]*)#(?P<lmhash>[a-fA-F0-9]{32}):(?P<nthash>[a-fA-F0-9]{32})"
)

GENERIC_ALL_DIR_FLAGS = (
    FILE_LIST_DIRECTORY
    | FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_READ_EA
    | FILE_WRITE_EA
    | FILE_TRAVERSE
    | FILE_DELETE_CHILD
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | SYNCHRONIZE
)
GENERIC_EXECUTE_DIR_FLAGS = (
    FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE | READ_CONTROL
)
GENERIC_WRITE_DIR_FLAGS = (
    FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | SYNCHRONIZE
    | READ_CONTROL
)
GENERIC_READ_DIR_FLAGS = (
    FILE_LIST_DIRECTORY
    | FILE_READ_ATTRIBUTES
    | FILE_READ_EA
    | SYNCHRONIZE
    | READ_CONTROL
)
GENERIC_EXECUTE_FPP_FLAGS = (
    FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE | READ_CONTROL
)
GENERIC_WRITE_FPP_FLAGS = (
    FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | SYNCHRONIZE
    | READ_CONTROL
)
GENERIC_READ_FPP_FLAGS = (
    FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE | READ_CONTROL
)
GENERIC_ALL_FPP_FLAGS = (
    FILE_READ_DATA
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_READ_EA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_EXECUTE
    | FILE_READ_ATTRIBUTES
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | SYNCHRONIZE
)


def normalize_access_mask(access_raw: int, share_type: str) -> int:
    """
    Propagate GENERIC_* flags to granular flags and vice versa.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b3af3aaf-9271-4419-b326-eba0341df7d2
    Servers seem to sometimes respond with the GENERIC_* flags set and
    sometimes respond with only the granular flags set. To simplify things,
    propagate them to each other so we can assume that everything is set that
    should be.
    """
    if "DISKTREE" in share_type:
        GENERIC_ALL_FLAGS = GENERIC_ALL_DIR_FLAGS
        GENERIC_READ_FLAGS = GENERIC_READ_DIR_FLAGS
        GENERIC_EXECUTE_FLAGS = GENERIC_EXECUTE_DIR_FLAGS
        GENERIC_WRITE_FLAGS = GENERIC_WRITE_DIR_FLAGS
    else:
        GENERIC_ALL_FLAGS = GENERIC_ALL_FPP_FLAGS
        GENERIC_READ_FLAGS = GENERIC_READ_FPP_FLAGS
        GENERIC_EXECUTE_FLAGS = GENERIC_EXECUTE_FPP_FLAGS
        GENERIC_WRITE_FLAGS = GENERIC_WRITE_FPP_FLAGS

    if access_raw & GENERIC_ALL:
        access_raw |= GENERIC_ALL_FLAGS
        access_raw |= GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE
    if access_raw & GENERIC_EXECUTE:
        access_raw |= GENERIC_EXECUTE_FLAGS
    if access_raw & GENERIC_READ:
        access_raw |= GENERIC_READ_FLAGS
    if access_raw & GENERIC_WRITE:
        access_raw |= GENERIC_WRITE_FLAGS

    if access_raw & GENERIC_ALL_FLAGS == GENERIC_ALL_FLAGS:
        access_raw |= GENERIC_ALL
    if access_raw & GENERIC_EXECUTE_FLAGS == GENERIC_EXECUTE_FLAGS:
        access_raw |= GENERIC_EXECUTE
    if access_raw & GENERIC_READ_FLAGS == GENERIC_READ_FLAGS:
        access_raw |= GENERIC_READ
    if access_raw & GENERIC_WRITE_FLAGS == GENERIC_WRITE_FLAGS:
        access_raw |= GENERIC_WRITE

    return access_raw


def render_access_mask(access_raw: int, share_type: str) -> str:
    generic: List[str] = list()
    if "DISKTREE" in share_type:
        GENERIC_READ_FLAGS = GENERIC_READ_DIR_FLAGS
        GENERIC_EXECUTE_FLAGS = GENERIC_EXECUTE_DIR_FLAGS
        GENERIC_WRITE_FLAGS = GENERIC_WRITE_DIR_FLAGS
    else:
        GENERIC_READ_FLAGS = GENERIC_READ_FPP_FLAGS
        GENERIC_EXECUTE_FLAGS = GENERIC_EXECUTE_FPP_FLAGS
        GENERIC_WRITE_FLAGS = GENERIC_WRITE_FPP_FLAGS
    if access_raw & GENERIC_ALL:
        return "GENERIC_ALL"
    if access_raw & GENERIC_EXECUTE:
        generic.append("GENERIC_EXECUTE")
        access_raw &= ~GENERIC_EXECUTE_FLAGS
        access_raw &= ~GENERIC_EXECUTE
    if access_raw & GENERIC_WRITE:
        generic.append("GENERIC_WRITE")
        access_raw &= ~GENERIC_WRITE_FLAGS
        access_raw &= ~GENERIC_WRITE
    if access_raw & GENERIC_READ:
        generic.append("GENERIC_READ")
        access_raw &= ~GENERIC_READ_FLAGS
        access_raw &= ~GENERIC_READ
    if access_raw:
        # Leftover standalone permissions not covered by GENERIC_*
        if "DISKTREE" in share_type:
            standalone_flags = (
                "FILE_LIST_DIRECTORY",
                "FILE_ADD_FILE",
                "FILE_ADD_SUBDIRECTORY",
                "FILE_READ_EA",
                "FILE_WRITE_EA",
                "FILE_TRAVERSE",
                "FILE_DELETE_CHILD",
                "FILE_READ_ATTRIBUTES",
                "FILE_WRITE_ATTRIBUTES",
                "DELETE",
                "READ_CONTROL",
                "WRITE_DAC",
                "WRITE_OWNER",
                "SYNCHRONIZE",
            )
        else:
            standalone_flags = (
                "FILE_READ_DATA",
                "FILE_WRITE_DATA",
                "FILE_APPEND_DATA",
                "FILE_READ_EA",
                "FILE_WRITE_EA",
                "FILE_DELETE_CHILD",
                "FILE_EXECUTE",
                "FILE_READ_ATTRIBUTES",
                "FILE_WRITE_ATTRIBUTES",
                "DELETE",
                "READ_CONTROL",
                "WRITE_DAC",
                "WRITE_OWNER",
                "SYNCHRONIZE",
            )
        for perm_flag in standalone_flags:
            if access_raw & getattr(smb3structs, perm_flag):
                generic.append(perm_flag)
    return "|".join(generic)


def render_sid(sid: str) -> str:
    """Pretty-print well-known SIDs.

    Assumes that the sid is already in canonical string form.
    Falls back to returning the input.

    https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    """
    well_known_sids = {
        "S-1-0-0": "Null SID",  # A group with no members. This is often used when a SID value isn't known.
        "S-1-1-0": "World",  # A group that includes all users.
        "S-1-2-0": "Local",  # Users who sign in to terminals that are locally (physically) connected to the system.
        "S-1-2-1": "Console Logon",  # A group that includes users who are signed in to the physical console.
        "S-1-3-0": "Creator Owner ID",  # A security identifier to be replaced by the security identifier of the user who created a new object. This SID is used in inheritable access control entries (ACEs).
        "S-1-3-1": "Creator Group ID",  # A security identifier to be replaced by the primary-group SID of the user who created a new object. Use this SID in inheritable ACEs.
        "S-1-3-2": "Owner Server",  # A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's owner server and stores information about who created a given object or file.
        "S-1-3-3": "Group Server",  # A placeholder in an inheritable ACE. When the ACE is inherited, the system replaces this SID with the SID for the object's group server and stores information about the groups that are allowed to work with the object.
        "S-1-3-4": "Owner Rights",  # A group that represents the current owner of the object. When an ACE that carries this SID is applied to an object, the system ignores the implicit READ_CONTROL and WRITE_DAC permissions for the object owner.
        "S-1-4": "Non-unique Authority",  # A SID that represents an identifier authority.
        "S-1-5": "NT Authority",  # A SID that represents an identifier authority.
        "S-1-5-1": "Dialup",  # A group that includes all users who are signed in to the system via dial-up connection.
        "S-1-5-113": "Local account",  # You can use this SID when you're restricting network sign-in to local accounts instead of "administrator" or equivalent. This SID can be effective in blocking network sign-in for local users and groups by account type regardless of what they're named.
        "S-1-5-114": "Local account and member of Administrators group",  # You can use this SID when you're restricting network sign-in to local accounts instead of "administrator" or equivalent. This SID can be effective in blocking network sign-in for local users and groups by account type regardless of what they're named.
        "S-1-5-2": "Network",  # A group that includes all users who are signed in via a network connection. Access tokens for interactive users don't contain the Network SID.
        "S-1-5-3": "Batch",  # A group that includes all users who have signed in via batch queue facility, such as task scheduler jobs.
        "S-1-5-4": "Interactive",  # A group that includes all users who sign in interactively. A user can start an interactive sign-in session by opening a Remote Desktop Services connection from a remote computer, or by using a remote shell such as Telnet. In each case, the user's access token contains the Interactive SID. If the user signs in by using a Remote Desktop Services connection, the user's access token also contains the Remote Interactive Logon SID.
        "S-1-5-6": "Service",  # A group that includes all security principals that have signed in as a service.
        "S-1-5-7": "Anonymous Logon",  # A user who has connected to the computer without supplying a user name and password. The Anonymous Logon identity is different from the identity that's used by Internet Information Services (IIS) for anonymous web access. IIS uses an actual account--by default, IUSR_ComputerName, for anonymous access to resources on a website. Strictly speaking, such access isn't anonymous, because the security principal is known even though unidentified people are using the account. IUSR_ComputerName (or whatever you name the account) has a password, and IIS signs in to the account when the service starts. As a result, the IIS "anonymous" user is a member of Authenticated Users but Anonymous Logon isn't.
        "S-1-5-8": "Proxy",  # Doesn't currently apply: this SID isn't used.
        "S-1-5-9": "Enterprise Domain Controllers",  # A group that includes all domain controllers in a forest of domains.
        "S-1-5-10": "Self",  # A placeholder in an ACE for a user, group, or computer object in Active Directory. When you grant permissions to Self, you grant them to the security principal that's represented by the object. During an access check, the operating system replaces the SID for Self with the SID for the security principal that's represented by the object.
        "S-1-5-11": "Authenticated Users",  # A group that includes all users and computers with identities that have been authenticated. Authenticated Users doesn't include Guest even if the Guest account has a password. This group includes authenticated security principals from any trusted domain, not only the current domain.
        "S-1-5-12": "Restricted Code",  # An identity that's used by a process that's running in a restricted security context. In Windows and Windows Server operating systems, a software restriction policy can assign one of three security levels to code: Unrestricted Restricted Disallowed When code runs at the restricted security level, the Restricted SID is added to the user's access token.
        "S-1-5-13": "Terminal Server User",  # A group that includes all users who sign in to a server with Remote Desktop Services enabled.
        "S-1-5-14": "Remote Interactive Logon",  # A group that includes all users who sign in to the computer by using a remote desktop connection. This group is a subset of the Interactive group. Access tokens that contain the Remote Interactive Logon SID also contain the Interactive SID.
        "S-1-5-15": "This Organization",  # A group that includes all users from the same organization. Included only with Active Directory accounts and added only by a domain controller.
        "S-1-5-17": "IUSR",  # An account that's used by the default Internet Information Services (IIS) user.
        "S-1-5-18": "System (or LocalSystem)",  # An identity that's used locally by the operating system and by services that are configured to sign in as LocalSystem. System is a hidden member of Administrators. That is, any process running as System has the SID for the built-in Administrators group in its access token. When a process that's running locally as System accesses network resources, it does so by using the computer's domain identity. Its access token on the remote computer includes the SID for the local computer's domain account plus SIDs for security groups that the computer is a member of, such as Domain Computers and Authenticated Users.
        "S-1-5-19": "NT Authority (LocalService)",  # An identity that's used by services that are local to the computer, have no need for extensive local access, and don't need authenticated network access. Services that run as LocalService access local resources as ordinary users, and they access network resources as anonymous users. As a result, a service that runs as LocalService has significantly less authority than a service that runs as LocalSystem locally and on the network.
        "S-1-5-20": "Network Service",  # An identity that's used by services that have no need for extensive local access but do need authenticated network access. Services running as NetworkService access local resources as ordinary users and access network resources by using the computer's identity. As a result, a service that runs as NetworkService has the same network access as a service that runs as LocalSystem, but it has significantly reduced local access.
        "S-1-5-32-544": "Administrators",  # A built-in group. After the initial installation of the operating system, the only member of the group is the Administrator account. When a computer joins a domain, the Domain Admins group is added to the Administrators group. When a server becomes a domain controller, the Enterprise Admins group also is added to the Administrators group.
        "S-1-5-32-545": "Users",  # A built-in group. After the initial installation of the operating system, the only member is the Authenticated Users group.
        "S-1-5-32-546": "Guests",  # A built-in group. By default, the only member is the Guest account. The Guests group allows occasional or one-time users to sign in with limited privileges to a computer's built-in Guest account.
        "S-1-5-32-547": "Power Users",  # A built-in group. By default, the group has no members. Power users can create local users and groups; modify and delete accounts that they have created; and remove users from the Power Users, Users, and Guests groups. Power users also can install programs; create, manage, and delete local printers; and create and delete file shares.
        "S-1-5-32-548": "Account Operators",  # A built-in group that exists only on domain controllers. By default, the group has no members. By default, Account Operators have permission to create, modify, and delete accounts for users, groups, and computers in all containers and organizational units of Active Directory except the Builtin container and the Domain Controllers OU. Account Operators don't have permission to modify the Administrators and Domain Admins groups, nor do they have permission to modify the accounts for members of those groups.
        "S-1-5-32-549": "Server Operators",  # Description: A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can sign in to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.
        "S-1-5-32-550": "Print Operators",  # A built-in group that exists only on domain controllers. By default, the only member is the Domain Users group. Print Operators can manage printers and document queues.
        "S-1-5-32-551": "Backup Operators",  # A built-in group. By default, the group has no members. Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can sign in to the computer and shut it down.
        "S-1-5-32-552": "Replicators",  # A built-in group that's used by the File Replication service on domain controllers. By default, the group has no members. Don't add users to this group.
        "S-1-5-32-554": "Builtin\\Pre-Windows 2000 Compatible Access",  # An alias added by Windows 2000. A backward compatibility group that allows read access on all users and groups in the domain.
        "S-1-5-32-555": "Builtin\\Remote Desktop Users",  # An alias. Members of this group are granted the right to sign in remotely.
        "S-1-5-32-556": "Builtin\\Network Configuration Operators",  # An alias. Members of this group can have some administrative privileges to manage configuration of networking features.
        "S-1-5-32-557": "Builtin\\Incoming Forest Trust Builders",  # An alias. Members of this group can create incoming, one-way trusts to this forest.
        "S-1-5-32-558": "Builtin\\Performance Monitor Users",  # An alias. Members of this group have remote access to monitor this computer.
        "S-1-5-32-559": "Builtin\\Performance Log Users",  # An alias. Members of this group have remote access to schedule logging of performance counters on this computer.
        "S-1-5-32-560": "Builtin\\Windows Authorization Access Group",  # An alias. Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects.
        "S-1-5-32-561": "Builtin\\Terminal Server License Servers",  # An alias. A group for Terminal Server License Servers. When Windows Server 2003 Service Pack 1 is installed, a new local group is created.
        "S-1-5-32-562": "Builtin\\Distributed COM Users",  # An alias. A group for COM to provide computer-wide access controls that govern access to all call, activation, or launch requests on the computer.
        "S-1-5-32-568": "Builtin\\IIS_IUSRS",  # An alias. A built-in group account for IIS users.
        "S-1-5-32-569": "Builtin\\Cryptographic Operators",  # A built-in local group. Members are authorized to perform cryptographic operations.
        "S-1-5-32-573": "Builtin\\Event Log Readers",  # A built-in local group. Members of this group can read event logs from a local computer.
        "S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",  # A built-in local group. Members of this group are allowed to connect to Certification Authorities in the enterprise.
        "S-1-5-32-575": "Builtin\\RDS Remote Access Servers",  # A built-in local group. Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers that are running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
        "S-1-5-32-576": "Builtin\\RDS Endpoint Servers",  # A built-in local group. Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
        "S-1-5-32-577": "Builtin\\RDS Management Servers",  # A built-in local group. Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
        "S-1-5-32-578": "Builtin\\Hyper-V Administrators",  # A built-in local group. Members of this group have complete and unrestricted access to all features of Hyper-V.
        "S-1-5-32-579": "Builtin\\Access Control Assistance Operators",  # A built-in local group. Members of this group can remotely query authorization attributes and permissions for resources on this computer.
        "S-1-5-32-580": "Builtin\\Remote Management Users",  # A built-in local group. Members of this group can access Windows Management Instrumentation (WMI) resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
        "S-1-5-64-10": "NTLM Authentication",  # A SID that's used when the NTLM authentication package authenticates the client.
        "S-1-5-64-14": "SChannel Authentication",  # A SID that's used when the SChannel authentication package authenticates the client.
        "S-1-5-64-21": "Digest Authentication",  # A SID that's used when the Digest authentication package authenticates the client.
        "S-1-5-80": "NT Service",  # A SID that's used as an NT Service account prefix.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "NT SERVICE\\TrustedInstaller",  # Not in MS docs
        "S-1-5-80-0": "All Services",  # A group that includes all service processes that are configured on the system. Membership is controlled by the operating system. SID S-1-5-80-0 equals NT SERVICES\ALL SERVICES. This SID was introduced in Windows Server 2008 R2.
        "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",  # A built-in group. The group is created when the Hyper-V role is installed. Membership in the group is maintained by the Hyper-V Management Service (VMMS). This group requires the Create Symbolic Links right (SeCreateSymbolicLinkPrivilege) and the Log on as a Service right (SeServiceLogonRight).
        "S-1-15-2-1": "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",  # Not in MS docs
        "S-1-15-2-2": "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES",  # Not in MS docs
    }
    res = well_known_sids.get(sid, sid)

    if res == sid and sid.startswith("S-1-5-"):
        well_known_domain_sid_suffixes = {
            "500": "Administrator",  # A user account for the system administrator. Every computer has a local Administrator account and every domain has a domain Administrator account. The Administrator account is the first account created during operating system installation. The account can't be deleted, disabled, or locked out, but it can be renamed. By default, the Administrator account is a member of the Administrators group, and it can't be removed from that group.
            "501": "Guest",  # A user account for people who don't have individual accounts. Every computer has a local Guest account, and every domain has a domain Guest account. By default, Guest is a member of the Everyone and the Guests groups. The domain Guest account is also a member of the Domain Guests and Domain Users groups. Unlike Anonymous Logon, Guest is a real account, and it can be used to sign in interactively. The Guest account doesn't require a password, but it can have one.
            "502": "KRBTGT",  # A user account that's used by the Key Distribution Center (KDC) service. The account exists only on domain controllers.
            "512": "Domain Admins",  # A global group with members that are authorized to administer the domain. By default, the Domain Admins group is a member of the Administrators group on all computers that have joined the domain, including domain controllers. Domain Admins is the default owner of any object that's created in the domain's Active Directory by any member of the group. If members of the group create other objects, such as files, the default owner is the Administrators group.
            "513": "Domain Users",  # A global group that includes all users in a domain. When you create a new User object in Active Directory, the user is automatically added to this group.
            "514": "Domain Guests",  # A global group that, by default, has only one member: the domain's built-in Guest account.
            "515": "Domain Computers",  # A global group that includes all computers that have joined the domain, excluding domain controllers.
            "516": "Domain Controllers",  # A global group that includes all domain controllers in the domain. New domain controllers are added to this group automatically.
            "517": "Cert Publishers",  # A global group that includes all computers that host an enterprise certification authority. Cert Publishers are authorized to publish certificates for User objects in Active Directory.
            "518": "Schema Admins",  # A group that exists only in the forest root domain. It's a universal group if the domain is in native mode, and it's a global group if the domain is in mixed mode. The Schema Admins group is authorized to make schema changes in Active Directory. By default, the only member of the group is the Administrator account for the forest root domain.
            "519": "Enterprise Admins",  # A group that exists only in the forest root domain. It's a universal group if the domain is in native mode, and it's a global group if the domain is in mixed mode. The Enterprise Admins group is authorized to make changes to the forest infrastructure, such as adding child domains, configuring sites, authorizing DHCP servers, and installing enterprise certification authorities. By default, the only member of Enterprise Admins is the Administrator account for the forest root domain. The group is a default member of every Domain Admins group in the forest.
            "520": "Group Policy Creator Owners",  # A global group that's authorized to create new Group Policy Objects in Active Directory. By default, the only member of the group is Administrator. Objects that are created by members of Group Policy Creator Owners are owned by the individual user who creates them. In this way, the Group Policy Creator Owners group is unlike other administrative groups (such as Administrators and Domain Admins). Objects that are created by members of these groups are owned by the group rather than by the individual.
            "521": "Read-only Domain Controllers",  # A global group that includes all read-only domain controllers.
            "522": "Clonable Controllers",  # A global group that includes all domain controllers in the domain that can be cloned.
            "525": "Protected Users",  # A global group that is afforded additional protections against authentication security threats.
            "526": "Key Admins",  # This group is intended for use in scenarios where trusted external authorities are responsible for modifying this attribute. Only trusted administrators should be made a member of this group.
            "527": "Enterprise Key Admins",  # This group is intended for use in scenarios where trusted external authorities are responsible for modifying this attribute. Only trusted enterprise administrators should be made a member of this group.
            "571": "Allowed RODC Password Replication Group",  # Members in this group can have their passwords replicated to all read-only domain controllers in the domain.
            "572": "Denied RODC Password Replication Group",  # Members in this group can't have their passwords replicated to all read-only domain controllers in the domain.
            "553": "RAS and IAS Servers",  # A local domain group. By default, this group has no members. Computers that are running the Routing and Remote Access service are added to the group automatically. Members of this group have access to certain properties of User objects, such as Read Account Restrictions, Read Logon Information, and Read Remote Access Information.
        }
        last_subauthority = sid.split("-")[-1]
        if last_subauthority in well_known_domain_sid_suffixes:
            domain_subauthorities = "-".join(sid.split("-")[3:-1])
            res = f"{well_known_domain_sid_suffixes[last_subauthority]} ({domain_subauthorities})"
    if res == sid and sid.startswith("S-1-5-80"):
        res += " (unknown service)"
    # S-1-15-3- are capability SIDs
    # "S-1-5-5-X-Y": "Logon Session",  # The X and Y values for these SIDs uniquely identify a particular sign-in session.

    # I thought this should work to look up domain SIDs, but it doesn't bind.
    # TODO investigate more later
    # rpctransport = transport.SMBTransport(smbconn.getRemoteName(), smbconn.getRemoteHost(), filename=r'\srvsvc', smb_connection=smbconn)
    # dce = rpctransport.get_dce_rpc()
    # dce.connect()
    # # dce.bind(lsat.MSRPC_UUID_LSAT)
    # dce.bind(samr.MSRPC_UUID_SAMR)
    return res


def list_shares_multicred(
    argbundle: Tuple[Tuple[Creds, ...], ShareOptions, str],
) -> Tuple[str, Dict[str, Scan]]:
    creds_list, share_options, host = argbundle
    res = dict()
    timed_out = False
    for creds in creds_list:
        if timed_out:
            res[serialize(creds)] = {
                "errtype": "timeout",
                "error": "timed out on same host with other credentials",
            }
            continue
        res[serialize(creds)] = list_shares(creds, share_options, host)
        if res[serialize(creds)].get("errtype", "") == "timeout":
            timed_out = True
    return host, res


def connectTree(self: smbconnection.SMBConnection, share: str) -> Tuple[int, int]:
    """
    Modified impacket.smbconnection.SMBConnection.connectTree that returns MaximalAccess field.

    Changes:
    - Return (TreeID, MaximalAccess)
    - Raise Exception on error
    - Format with Black

    The first change is the only functionally important one. In the future I
    hope this field is exposed by Impacket and this function can be removed.

    Original source:
    https://github.com/SecureAuthCorp/impacket/blob/cd4fe47cfcb72d7d35237a99e3df95cedf96e94f/impacket/smb3.py#L1065
    """
    share = share.split("\\")[-1]

    if share in self._Session["TreeConnectTable"]:
        raise Exception("Called connectTree with already connected share")

    try:
        _, _, _, _, sockaddr = socket.getaddrinfo(
            self._Connection["ServerIP"], 80, 0, 0, socket.IPPROTO_TCP
        )[0]
        remoteHost = sockaddr[0]
    except Exception:
        remoteHost = self._Connection["ServerIP"]
    path = "\\\\" + remoteHost + "\\" + share
    treeConnect = SMB2TreeConnect()
    treeConnect["Buffer"] = path.encode("utf-16le")
    treeConnect["PathLength"] = len(path) * 2

    packet = self.SMB_PACKET()
    packet["Command"] = SMB2_TREE_CONNECT
    packet["Data"] = treeConnect
    packetID = self.sendSMB(packet)
    packet = self.recvSMB(packetID)
    if not packet.isValidAnswer(STATUS_SUCCESS):
        raise Exception("TreeConnect call failed")
    treeConnectResponse = SMB2TreeConnect_Response(packet["Data"])
    treeEntry = copy.deepcopy(smb3.TREE_CONNECT)
    treeEntry["ShareName"] = share
    treeEntry["TreeConnectId"] = packet["TreeID"]
    treeEntry["Session"] = packet["SessionID"]
    treeEntry["NumberOfUses"] += 1
    if (treeConnectResponse["Capabilities"] & SMB2_SHARE_CAP_DFS) == SMB2_SHARE_CAP_DFS:
        treeEntry["IsDfsShare"] = True
    if (
        treeConnectResponse["Capabilities"] & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
    ) == SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY:
        treeEntry["IsCAShare"] = True

    if self._Connection["Dialect"] >= SMB2_DIALECT_30:
        if (self._Connection["SupportsEncryption"] is True) and (
            (treeConnectResponse["ShareFlags"] & SMB2_SHAREFLAG_ENCRYPT_DATA)
            == SMB2_SHAREFLAG_ENCRYPT_DATA
        ):
            treeEntry["EncryptData"] = True
            # ToDo: This and what follows
            # If Session.EncryptData is FALSE, the client MUST then generate an encryption key, a
            # decryption key as specified in section 3.1.4.2, by providing the following inputs and store
            # them in Session.EncryptionKey and Session.DecryptionKey:
        if (
            treeConnectResponse["Capabilities"] & SMB2_SHARE_CAP_SCALEOUT
        ) == SMB2_SHARE_CAP_SCALEOUT:
            treeEntry["IsScaleoutShare"] = True

    self._Session["TreeConnectTable"][packet["TreeID"]] = treeEntry
    self._Session["TreeConnectTable"][share] = treeEntry
    # TODO maybe do something with SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM
    return (
        packet["TreeID"],
        treeConnectResponse["MaximalAccess"],
    )


def si_share_perms(
    smbconn: smbconnection.SMBConnection, share_name: str, share_type: str
) -> Tuple[bool, int, int]:
    try:
        treeId, access_raw = connectTree(
            smbconn._SMBConnection, share_name
        )  # Network call
        return True, treeId, normalize_access_mask(access_raw, share_type)
    except smb3.SessionError as e:
        if e.get_error_code() == STATUS_ACCESS_DENIED:
            return False, -1, 0
        raise


def si_dacl(
    smbconn: smbconnection.SMBConnection, treeId: int, share_type: str
) -> Optional[List[Tuple[str, str, int]]]:
    if "PRINTQ" in share_type:
        return None
    try:
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
        fileId = smbconn.openFile(
            treeId=treeId,
            pathName="",
            desiredAccess=READ_CONTROL,
            shareMode=FILE_SHARE_READ,
            creationOption=FILE_DIRECTORY_FILE,
            creationDisposition=FILE_OPEN,
            fileAttributes=0,
        )  # Network call
        res = smbconn._SMBConnection.queryInfo(
            treeId,
            fileId,
            infoType=SMB2_0_INFO_SECURITY,
            fileInfoClass=0,  # MUST be 0 for security queries
            additionalInformation=DACL_SECURITY_INFORMATION,
        )  # Network call
    except smbconnection.SessionError as e:
        if e.getErrorCode() == STATUS_ACCESS_DENIED:
            return None
        raise
    sd = SR_SECURITY_DESCRIPTOR(res)
    dacl = list()
    if not sd["Dacl"]:
        return None
    for ace in sd["Dacl"].aces:
        ace_type = ace["TypeName"].removeprefix("ACCESS_").removesuffix("_ACE")
        sid = render_sid(ace["Ace"]["Sid"].formatCanonical())
        access_mask = normalize_access_mask(ace["Ace"]["Mask"]["Mask"], share_type)
        dacl.append(
            (
                ace_type,
                sid,
                access_mask,
            )
        )

    smbconn.closeFile(treeId, fileId)  # Network call
    return dacl


def si_list(
    smbconn: smbconnection.SMBConnection, share_name: str, list_contents: bool = False
) -> Tuple[bool, List[str]]:
    contents = list()
    try:
        file_listing = smbconn.listPath(share_name, "*")  # Network call
        if list_contents:
            contents = [
                sf.get_shortname()
                for sf in file_listing
                if sf.get_shortname() != ".." and sf.get_shortname() != "."
            ]
        return True, contents
    except smbconnection.SessionError as e:
        if e.getErrorCode() == STATUS_ACCESS_DENIED:
            return False, contents
        if e.getErrorCode() == STATUS_NO_SUCH_FILE:
            return False, contents
        raise


def si_write(smbconn: smbconnection.SMBConnection, share_name: str) -> bool:
    # This ignores the case where a share allows creating or writing to
    # files but not creating a subdirectory.
    try:
        try:
            smbconn.createDirectory(share_name, "smblstest")  # Network call
        except smbconnection.SessionError as e:
            # Delete this file if it was already there
            if e.getErrorCode() != STATUS_OBJECT_NAME_COLLISION:
                raise
        smbconn.deleteDirectory(share_name, "smblstest")  # Network call
        return True
    except smbconnection.SessionError as e:
        if e.getErrorCode() == STATUS_ACCESS_DENIED:
            return False
        raise


def share_info(
    smbconn: smbconnection.SMBConnection,
    share: Dict[Any, Any],
    share_options: ShareOptions,
) -> Dict[str, Any]:
    share_name = share["shi1_netname"][:-1]
    opt_auth_only, opt_write, opt_list, opt_list_ipc = share_options

    if share["shi1_type"] & srvs.STYPE_MASK == srvs.STYPE_DISKTREE:
        share_type = "DISKTREE"
    elif share["shi1_type"] & srvs.STYPE_MASK == srvs.STYPE_PRINTQ:
        share_type = "PRINTQ"
    elif share["shi1_type"] & srvs.STYPE_MASK == srvs.STYPE_DEVICE:
        share_type = "DEVICE"
    elif share["shi1_type"] & srvs.STYPE_MASK == srvs.STYPE_IPC:
        share_type = "IPC"
    else:
        share_type = "error_unknown"
    if share["shi1_type"] & srvs.STYPE_CLUSTER_FS:
        share_type += "|CLUSTER_FS"
    if share["shi1_type"] & srvs.STYPE_CLUSTER_SOFS:
        share_type += "|CLUSTER_SOFS"
    if share["shi1_type"] & srvs.STYPE_CLUSTER_DFS:
        share_type += "|CLUSTER_DFS"
    if share["shi1_type"] & srvs.STYPE_SPECIAL:
        share_type += "|SPECIAL"
    if share["shi1_type"] & srvs.STYPE_TEMPORARY:
        share_type += "|TEMPORARY"

    if opt_auth_only:
        return {
            "name": share_name,
            "type": share_type,
            "remark": share["shi1_remark"][:-1],
        }

    read_access = None
    write_access = None
    errors = list()
    contents = None
    share_perms = 0
    treeId = -1
    dacl = None

    # Test share permissions
    try:
        if share_name == "IPC$":
            # Assume we have IPC permissions because we already successfully
            # connected to host
            read_access = True
            write_access = True
            share_perms = normalize_access_mask(GENERIC_ALL, share_type)
        else:
            connect_success, treeId, share_perms = si_share_perms(
                smbconn, share_name, share_type
            )  # Network call
    except smb3.SessionError as e:
        errors.append("share_perms: " + str(e))
    except Exception:
        errors.append("share_perms: " + traceback.format_exc())

    # Test share DACL
    # Skip attempting to gather DACL from IPC shares because it isn't implemented.
    if share_name != "IPC$":
        try:
            dacl = si_dacl(smbconn, treeId, share_type)  # Network call
            if dacl is None:
                read_access = False
        except smbconnection.SessionError as e:
            read_access = False
            errors.append(f"dacl: {e}")
        except Exception:
            errors.append("dacl: " + traceback.format_exc())
            read_access = False

    # Test listing share contents
    if "DISKTREE" in share_type or (opt_list_ipc and "IPC" in share_type):
        if share_perms & GENERIC_READ:
            try:
                read_access, contents = si_list(
                    smbconn, share_name, opt_list
                )  # Network call
            except NetBIOSTimeout:
                errors.append("contents: timeout")
            except Exception:
                errors.append("contents: " + traceback.format_exc())
                read_access = False
        else:
            read_access = False

    # Test writing to a share
    # Don't try to write to weird things like PRINTQs
    if "DISKTREE" in share_type and opt_write:
        if share_perms & GENERIC_WRITE:
            try:
                write_access = si_write(smbconn, share_name)  # Network call
            except smbconnection.SessionError as e:
                write_access = False
                errors.append(f"write: {e}")
            except Exception:
                errors.append("write: " + traceback.format_exc())
                write_access = False
        else:
            write_access = False

    res = {
        "name": share_name,
        "type": share_type,
        "remark": share["shi1_remark"][:-1],
        "max_share_perms": render_access_mask(share_perms, share_type),
        "read_access": read_access,
    }
    if opt_write:
        res["write_access"] = write_access
    if dacl is not None:
        res["dacl"] = [
            f"{ace[0]},{ace[1]},{render_access_mask(ace[2], 'FILE')}" for ace in dacl
        ]
    if opt_list and read_access and contents is not None:
        res["contents"] = contents
    if errors:
        res["errors"] = errors
    return res


def list_shares(creds: Creds, share_options: ShareOptions, host: str) -> Scan:
    try:
        smbconn = smbconnection.SMBConnection(
            host, host, timeout=REQUEST_TIMEOUT
        )  # Network call
        smbconn.login(
            creds.get("username", ""),
            creds.get("password", ""),
            creds.get("domain", ""),
            creds.get("lmhash", ""),
            creds.get("nthash", ""),
        )  # Network call
    except OSError as e:
        return {"errtype": "conn", "error": str(e.strerror)}
    except smbconnection.SessionError as e:
        if e.getErrorCode() == STATUS_ACCESS_DENIED:
            return {"errtype": "auth", "error": "STATUS_ACCESS_DENIED"}
        elif e.getErrorCode() == STATUS_LOGON_FAILURE:
            return {"errtype": "auth", "error": "STATUS_LOGON_FAILURE"}
        else:
            return {"errtype": "session", "error": str(e)}
    except NetBIOSTimeout:
        return {"errtype": "timeout", "error": "timed out logging in"}
    except Exception as e:
        try:
            str_e = str(e)
        except Exception:
            str_e = "failed to render error"
        return {"errtype": "unknown_init", "error": str_e}
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
        try:
            info["getDialect"] = hex(info["getDialect"])
        except TypeError:
            pass

        # Get shares
        try:
            shares = list()
            for share in smbconn.listShares():  # Network call
                try:
                    si = share_info(smbconn, share, share_options)  # Network calls
                except Exception as e:
                    si = {"error": "share info: " + traceback.format_exc()}
                shares.append(si)
        except Exception as e:
            return {"info": info, "errtype": "shares", "error": traceback.format_exc()}
        return {
            "info": info,
            "shares": shares,
        }
    except Exception as e:
        return {"errtype": "unknown", "error": traceback.format_exc()}
    finally:
        smbconn.close()


def parse_credentials(s: str) -> Creds:
    if match := hash_regex.fullmatch(s):
        return match.groupdict("")
    elif match := password_regex.fullmatch(s):
        return match.groupdict("")
    else:
        raise ValueError("Couldn't parse credentials")


def serialize(creds: Creds, human: bool = False) -> str:
    return creds.get("domain", "") + ("/" if human else "_") + creds.get("username", "")


def run_scan(
    targets: list[str],
    creds_list: list[Creds],
    share_auth_only: bool = False,
    share_write: bool = False,
    share_list: bool = True,
    share_list_ipc: bool = False,
    threads: int = 32,
) -> Generator[Tuple[str, Scan]]:
    """Launches a scan in multiple processes.

    Args:
      targets:
        A list of hostnames, CIDRs, or IPs.
      creds_list:
        A list of Creds objects, which are dicts with string fields for
        "domain", "username", and either "password" or "lmhash and "nthash".
      share_auth_only:
        Determines if information should not be retrieved about individual
        shares.
      share_write:
        Determines if something should be written to shares to test write
        permissions for a set of creds.
      share_list:
        Determines if the contents of directory shares should be returned.
      share_list_ipc:
        Determines if contents of IPC shares should be returned.
      threads:
        The number of processes to spawn.

    Returns:
      A generator of tuples of hosts and Scan result objects.

    Raises:
      multiprocessing.TimeoutError: If a host's full job times out. Rarely
        raised because most timeouts should be caught inside the pool.
    """
    share_options = (share_auth_only, share_write, share_list, share_list_ipc)
    with Pool(threads) as pool:
        it = pool.imap_unordered(
            list_shares_multicred,
            [(tuple(creds_list), share_options, target) for target in targets],
        )
        for _ in range(len(targets)):
            # This is a per-host timeout. Each network call has an
            # individual timeout of 5 seconds, so to reach this, the host
            # would need to be very slow (but not too slow) and have many
            # many shares
            yield it.next(timeout=300)


def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Create targets file:
$ printf '10.0.0.1\\n10.0.0.2\\n...' > targets.txt
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
""",
    )
    parser.add_argument(
        "-V",
        action="version",
        version=__version__,
    )
    opts_creds = parser.add_mutually_exclusive_group(required=True)
    opts_creds.add_argument(
        "-c",
        dest="creds",
        help="credentials to test. Format is either domain/user:password or domain/user#lmhash:nthash. To test for unauthenticated shares, use /:",
    )
    opts_creds.add_argument(
        "-C",
        dest="creds_file",
        help="file containing credentials to test, one per line",
    )
    opts_output = parser.add_mutually_exclusive_group(required=True)
    opts_output.add_argument(
        "-o",
        dest="out_file",
        help="file to write output to. Can only be used with a single set of credentials (-c)",
    )
    opts_output.add_argument(
        "-O",
        dest="out_dir",
        help="directory to write output files to. Each set of credentials will be saved in its own file",
    )
    parser.add_argument(
        dest="targets",
        type=argparse.FileType("r"),
        help="file containing targets, one host per line, or - for stdin",
    )
    parser.add_argument(
        "-j",
        dest="threads",
        type=int,
        default=32,
        help="multiprocessing threads. This is heavily I/O-bound, so high numbers are fine (default: 32)",
    )
    parser.add_argument(
        "-w",
        dest="write",
        action="store_true",
        help="check root directory write permissions. Caution: this modifies the share by writing and then deleting a file",
    )
    parser.add_argument(
        "-l",
        dest="list",
        action="store_true",
        help="list files in the root directory of each share in the output. May significantly slow down scans",
    )
    parser.add_argument(
        "-i",
        dest="list_ipc",
        action="store_true",
        help="list contents of IPC shares in addition to directory shares. This flag only matters if `-l` is also passed",
    )
    parser.add_argument(
        "-a",
        dest="auth_only",
        action="store_true",
        help="skip all share checking. Only return host connection data",
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
    creds_table = {
        serialize(parse_credentials(ci.rstrip("\n"))): parse_credentials(
            ci.rstrip("\n")
        )
        for ci in creds_input
    }
    if len(creds_table.keys()) != len(creds_input):
        raise Exception("Duplicated users are not allowed")
    targets = [line.strip() for line in args.targets]
    if not targets or targets == [""]:
        print("No targets specified.")
        parser.exit(1)
    max_targets, max_creds = len(targets), len(creds_table)
    max_targets_width, max_creds_width = len(str(max_targets)), len(str(max_creds))
    args.targets.close()
    scan_res: Dict[str, Dict[str, Scan]] = {
        serialized_creds: dict() for serialized_creds in creds_table.keys()
    }
    start_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    loop_e = None

    scan_generator = run_scan(
        targets,
        list(creds_table.values()),
        args.auth_only,
        args.write,
        args.list,
        args.list_ipc,
        args.threads,
    )
    for i in range(len(targets)):
        try:
            host, res = next(scan_generator)
            cred_i = 0
            for serialized_creds, scan in res.items():
                scan_res[serialized_creds][host] = scan
                admin = False
                for share in scan.get("shares", {}):
                    # This is just a heuristic, but it's a pretty reliable one
                    if (
                        share.get("name") == "C$" or share.get("name") == "ADMIN$"
                    ) and share.get("read_access"):
                        admin = True
                        break
                print(
                    f'[host {i+1:{max_targets_width}}/{max_targets}, creds {cred_i+1:{max_creds_width}}/{max_creds}][{"err" if "errtype" in scan else "adm" if admin else "suc"}] scanned host {host} with user {serialize(creds_table[serialized_creds], human=True)}{", error: " + scan["errtype"] if "errtype" in scan else ""}{", ADMIN" if admin else ""}'
                )
                cred_i += 1
        except Exception as e:
            # If you see this, please file an issue
            print("Error in main loop. Writing partial output and exiting.")
            loop_e = e
            break

    end_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    json_metadata = {
        "version": __version__,
        "version_tuple": __version_tuple__,
        "start_time": start_time,
        "end_time": end_time,
        "args": str(args),
    }
    if args.out_file:
        with open(args.out_file, "w") as f:
            json.dump(
                json_metadata
                | {
                    "creds": next(iter(creds_table.values())),
                    "data": scan_res[next(iter(creds_table.keys()))],
                },
                f,
            )
    else:
        Path(args.out_dir).mkdir(exist_ok=True)
        for serialized_creds, creds in creds_table.items():
            with Path(args.out_dir, serialized_creds + ".json").open("w") as f:
                json.dump(
                    json_metadata
                    | {"creds": creds, "data": scan_res[serialized_creds]},
                    f,
                )
    if loop_e:
        raise loop_e


if __name__ == "__main__":
    main()
