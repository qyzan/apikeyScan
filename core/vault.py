"""Versioned authenticated credential vault. No plaintext temporary files.

Public header: magic/version, scrypt salt, AES-GCM nonce; fixed KDF parameters.
This module never discovers credentials, sends requests or logs passwords.
"""

import json
import os
import secrets
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AKVAULT\x01"
MAX_SIZE = 16 * 1024 * 1024
HEADER_SIZE = len(MAGIC) + 16 + 12


def _key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


def encrypt(payload: dict[str, Any], password: str) -> bytes:
    """Encrypt in memory, authenticating all public header bytes."""
    plain = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(plain) > MAX_SIZE - HEADER_SIZE - 16:
        raise ValueError("Vault size limit exceeded")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(_key(password, salt)).encrypt(nonce, plain, header)


def decrypt(blob: bytes, password: str) -> dict[str, Any]:
    """Fail atomically with a constant diagnostic; never return partial plaintext."""
    if not HEADER_SIZE + 16 <= len(blob) <= MAX_SIZE or not blob.startswith(MAGIC):
        raise ValueError("Invalid vault or password")
    salt = blob[len(MAGIC) : len(MAGIC) + 16]
    nonce = blob[len(MAGIC) + 16 : HEADER_SIZE]
    try:
        plain = AESGCM(_key(password, salt)).decrypt(nonce, blob[HEADER_SIZE:], blob[:HEADER_SIZE])
        result = json.loads(plain)
        if not isinstance(result, dict):
            raise ValueError("Invalid vault or password")
        return result
    except (InvalidTag, UnicodeError, ValueError) as exc:
        raise ValueError("Invalid vault or password") from exc


def read_vault(path: Path, password: str) -> dict[str, Any]:
    """Bound disk reads before decrypting."""
    with path.open("rb") as stream:
        blob = stream.read(MAX_SIZE + 1)
    return decrypt(blob, password)


def private_directory(path: Path) -> None:
    """Create a NEW directory, set and verify its operator-only permissions."""
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    if sys.platform != "win32":
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise OSError("Vault directory permissions unavailable")
        return
    import csv
    import ctypes
    import subprocess
    from ctypes import wintypes

    # Only the operator SID is queried; no credential/config discovery.
    rows = list(csv.reader(subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True).splitlines()))
    sid = rows[0][1]
    if not sid.startswith("S-1-") or any(c not in "S-0123456789" for c in sid):
        raise OSError("Cannot establish vault operator SID")
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    adv.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    adv.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
    ]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    expected = f"D:P(A;OICI;FA;;;{sid})"
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(expected, 1, ctypes.byref(descriptor), None):
        raise OSError("Cannot construct vault ACL")
    try:
        if not adv.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
            raise OSError("Cannot protect vault ACL")
    finally:
        kernel.LocalFree(descriptor)
    size = wintypes.DWORD()
    adv.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    if not adv.GetFileSecurityW(str(path), 4, buffer, size.value, ctypes.byref(size)):
        raise OSError("Cannot read vault ACL")
    result = wintypes.LPWSTR()
    if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer, 1, 4, ctypes.byref(result), None):
        raise OSError("Cannot verify vault ACL")
    try:
        if result.value != expected:
            raise OSError("Vault ACL verification failed")
    finally:
        kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))


class Vault:
    """One run, atomic encrypted checkpoints; callers stop on every write error."""

    def __init__(self, path: Path, password: str) -> None:
        self.path = path
        self._password = password
        self._payload: dict[str, Any] = {"run_id": path.stem, "records": []}

    @classmethod
    def create(cls, directory: Path, password: str) -> "Vault":
        private_directory(directory)
        store = cls(directory / (uuid.uuid4().hex + ".akv"), password)
        store._checkpoint(store._payload)
        return store

    def _checkpoint(self, payload: dict[str, Any]) -> None:
        blob = encrypt(payload, self._password)
        temp = self.path.with_suffix("." + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(blob)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)

    def add(self, credentials: dict[str, str], provider: str) -> str:
        ref = uuid.uuid4().hex
        payload = {
            **self._payload,
            "records": [*self._payload["records"], {"id": ref, "provider": provider, "credentials": dict(credentials)}],
        }
        self._checkpoint(payload)
        self._payload = payload
        return ref


class Terminal:
    """Dedicated controlling-terminal handles; never stdout/stderr fallback."""

    def __enter__(self):
        self.reader = open("CONIN$" if os.name == "nt" else "/dev/tty", encoding="utf-8")
        try:
            self.writer = open("CONOUT$" if os.name == "nt" else "/dev/tty", "w", encoding="utf-8")
            if not self.reader.isatty() or not self.writer.isatty():
                self.writer.close()
                raise OSError("Interactive terminal required for vault")
        except BaseException:
            self.reader.close()
            raise
        return self

    def __exit__(self, *args):
        self.reader.close()
        self.writer.close()

    def write(self, text: str) -> None:
        self.writer.write(text)
        self.writer.flush()

    def password(self) -> str:
        """Read without echo using the dedicated terminal, not redirected stdin."""
        self.write("Vault password: ")
        if sys.platform == "win32":
            import msvcrt

            chars: list[str] = []
            while True:
                char = msvcrt.getwch()
                if char == "\n" and not chars:
                    continue
                if char in ("\r", "\n"):
                    break
                if char == "\x03":
                    raise KeyboardInterrupt
                if char == "\b":
                    chars = chars[:-1]
                elif char in ("\x00", "\xe0"):
                    msvcrt.getwch()
                else:
                    chars.append(char)
            self.write("\n")
            return "".join(chars)
        import importlib

        termios: Any = importlib.import_module("termios")

        fd = self.reader.fileno()
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ECHO
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            return str(self.reader.readline().rstrip("\r\n"))
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            self.write("\n")


def start_vault(parent: Path) -> Vault:
    """Establish ACL before displaying a fresh one-time run password."""
    with Terminal() as terminal:
        directory = parent / uuid.uuid4().hex
        private_directory(directory)
        password = secrets.token_urlsafe(32)
        terminal.write(
            "Save this password in a separate password manager. It cannot be recovered.\n"
            + password
            + "\nType SAVED to continue: "
        )
        if terminal.reader.readline().strip() != "SAVED":
            raise ValueError("Vault password not acknowledged; scan cancelled")
        store = Vault(directory / (uuid.uuid4().hex + ".akv"), password)
        store._checkpoint(store._payload)
        terminal.write(f"\nVault created: {store.path.resolve()}\nScan ID: {store.path.stem}\n")
        return store


def open_local(path: Path) -> None:
    with Terminal() as terminal:
        payload = read_vault(path, terminal.password())
        terminal.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
