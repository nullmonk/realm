# __builtins__.pyi
#
# Type stub file for Eldritch-specific functions and modules.
# Generated based on the Rust source code in realm/implants/lib/eldritchv2/stdlib.
#
# to improve code, add this to .vscode/settings.json
# {
#     "files.associations": {
#         "*.eldritch": "python",
#         "*.eldr": "python",
#     },
#     "python.analysis.diagnosticSeverityOverrides": {
#         "reportPossiblyUnboundVariable": "none",
#         "reportInvalidStringEscapeSequence": "none",
#     }
# }

from typing import List, Dict, Any, Optional, Callable, Iterable, TypedDict, Literal, Union

# --- Type Definitions ---

class FileStat(TypedDict):
    """
    Represents file status information as returned by file.list.
    """
    file_name: str
    """The name of the file or directory."""
    absolute_path: str
    """The absolute path to the file or directory."""
    size: int
    """The size of the file in bytes."""
    owner: str
    """The owner of the file or directory."""
    group: str
    """The group owner of the file or directory."""
    permissions: str
    """The file permissions in a string format (e.g., 'rwxr-xr-x')."""
    modified: str
    """The last modification timestamp of the file or directory, in 'YYYY-MM-DD HH:MM:SS UTC' format."""
    type: str
    """The type of the file system entry ('Directory' or 'File')."""

class ProcessInfo(TypedDict):
    """
    Detailed information about a process.
    """
    pid: int
    """The process ID."""
    name: str
    """The name of the process."""
    cmd: List[str]
    """The command and arguments used to start the process."""
    exe: str
    """The path to the process executable."""
    environ: List[str]
    """A list of environment variables for the process."""
    cwd: str
    """The current working directory of the process."""
    root: str
    """The root directory of the process."""
    memory_usage: int
    """The resident set size (RSS) memory usage of the process in bytes."""
    virtual_memory_usage: int
    """The virtual memory size (VMS) usage of the process in bytes."""
    ppid: int
    """The parent process ID."""
    status: str
    """The current status of the process (e.g., 'Running', 'Sleeping', 'Stopped')."""
    start_time: int
    """The process start time as a Unix timestamp."""
    run_time: int
    """The total CPU time the process has consumed in seconds."""
    uid: int
    """The real user ID of the process."""
    euid: int
    """The effective user ID of the process."""
    gid: int
    """The real group ID of the process."""
    egid: int
    """The effective group ID of the process."""
    sid: int
    """The session ID of the process."""

class ProcessInfoSimple(TypedDict):
    """
    A simplified view of process information.
    """
    pid: str
    """The process ID as a string."""
    ppid: str
    """The parent process ID as a string."""
    status: str
    """The current status of the process (e.g., 'Sleeping', 'Running')."""
    name: str
    """The name of the process."""
    path: str
    """The path to the process executable."""
    username: str
    """The username of the process owner."""
    command: str
    """The full command line used to start the process."""
    cwd: str
    """The current working directory of the process."""
    environ: str
    """A string containing the environment variables of the process."""

class SocketInfo(TypedDict):
    """
    Information about an open socket.
    """
    socket_type: str
    """The type of socket (e.g., 'TCP', 'UDP')."""
    local_address: str
    """The local IP address the socket is bound to."""
    local_port: int
    """The local port number the socket is using."""
    pid: int
    """The process ID that owns the socket."""

class ARPTableEntry(TypedDict):
    """
    An entry in the ARP table, mapping an IP address to a MAC address.
    """
    ip: str
    """The IP address."""
    mac: str
    """The MAC address."""
    interface: str
    """The network interface associated with this entry."""

class PortScanResult(TypedDict):
    """
    The result of a port scan for a single port.
    """
    ip: str
    """The IP address that was scanned."""
    port: int
    """The port number that was scanned."""
    protocol: str
    """The protocol used for the scan (e.g., 'tcp', 'udp')."""
    status: str
    """The status of the port (e.g., 'open', 'closed', 'timeout')."""

class OSInfo(TypedDict):
    """
    Detailed information about the operating system.
    """
    arch: str
    """The architecture of the operating system (e.g., 'x86_64')."""
    desktop_env: str
    """The desktop environment in use (e.g., 'GNOME', 'KDE', or 'Unknown')."""
    distro: str
    """The distribution of the operating system (e.g., 'Debian GNU/Linux 10 (buster)')."""
    platform: str
    """The general platform of the operating system (e.g., 'PLATFORM_LINUX', 'PLATFORM_WINDOWS')."""

class UserDetail(TypedDict):
    """
    Detailed information about a user.
    """
    uid: int
    """The user ID."""
    name: str
    """The username."""
    gid: int
    """The primary group ID of the user."""
    groups: List[str]
    """A list of groups the user belongs to."""

class UserInfo(TypedDict):
    """
    Information about the current process's running user.
    """
    uid: UserDetail
    """Details for the real user ID."""
    euid: UserDetail
    """Details for the effective user ID."""
    gid: int
    """The real group ID of the process."""
    egid: int
    """The effective group ID of the process."""

class ShellResult(TypedDict):
    """
    The result of a shell command execution.
    """
    stdout: str
    """The standard output from the command."""
    stderr: str
    """The standard error from the command."""
    status: int
    """The exit status code of the command."""

class NetworkInterface(TypedDict):
    """
    Information about a single network interface.
    """
    name: str
    """The name of the network interface (e.g., 'eth0', 'lo')."""
    ips: List[str]
    """A list of IP addresses assigned to the interface."""
    mac: str
    """The MAC address of the network interface."""

class HttpResponse(TypedDict):
    """
    The result of an HTTP request.
    """
    status_code: int
    """HTTP status code."""
    body: List[int]
    """The response body as a list of bytes."""
    headers: Dict[str, str]
    """Response headers."""

# --- Library Classes ---

class Agent:
    """
    Used for meta-style interactions with the agent itself.
    """
    @staticmethod
    def _terminate_this_process_clowntown() -> None:
        """
        **DANGER**: Terminates the agent process immediately.
        This method calls `std::process::exit(0)`, effectively killing the agent.
        """
        ...

    @staticmethod
    def get_config() -> Dict[str, Any]:
        """
        Returns the current configuration of the agent as a dictionary.
        """
        ...

    @staticmethod
    def get_transport() -> str:
        """
        Returns the name of the currently active transport (e.g., "http", "grpc").
        """
        ...

    @staticmethod
    def list_transports() -> List[str]:
        """
        Returns a list of available transport names.
        """
        ...

    @staticmethod
    def get_callback_interval() -> int:
        """
        Returns the current callback interval in seconds.
        """
        ...

    @staticmethod
    def set_callback_interval(interval: int) -> None:
        """
        Sets the callback interval for the agent in seconds.
        This configuration change is typically transient and may not persist across reboots.
        """
        ...


class Assets:
    """
    The `assets` library provides access to files embedded directly within the agent binary.
    """
    @staticmethod
    def read_binary(name: str) -> List[int]:
        """
        Reads the content of an embedded asset as a list of bytes (u8).
        """
        ...

    @staticmethod
    def read(name: str) -> str:
        """
        Reads the content of an embedded asset as a UTF-8 string.
        """
        ...

    @staticmethod
    def copy(src: str, dest: str) -> None:
        """
        Copies an embedded asset to a destination path on the disk.
        """
        ...

    @staticmethod
    def list() -> List[str]:
        """
        Returns a list of all available asset names.
        """
        ...


class Crypto:
    """
    The `crypto` library provides cryptographic primitives, hashing, encoding, and JSON handling utilities.
    """
    @staticmethod
    def aes_decrypt(key: List[int], iv: List[int], data: List[int]) -> List[int]:
        """
        Decrypts data using AES (CBC mode).
        - `key` (Bytes): The decryption key (must be 16, 24, or 32 bytes).
        - `iv` (Bytes): The initialization vector (must be 16 bytes).
        - `data` (Bytes): The encrypted data to decrypt.
        """
        ...

    @staticmethod
    def aes_encrypt(key: List[int], iv: List[int], data: List[int]) -> List[int]:
        """
        Encrypts data using AES (CBC mode).
        - `key` (Bytes): The encryption key (must be 16, 24, or 32 bytes).
        - `iv` (Bytes): The initialization vector (must be 16 bytes).
        - `data` (Bytes): The data to encrypt.
        """
        ...

    @staticmethod
    def aes_decrypt_file(src: str, dst: str, key: str) -> None:
        """
        Decrypts a file using AES.
        """
        ...

    @staticmethod
    def aes_encrypt_file(src: str, dst: str, key: str) -> None:
        """
        Encrypts a file using AES.
        """
        ...

    @staticmethod
    def md5(data: List[int]) -> str:
        """
        Calculates the MD5 hash of the provided data.
        """
        ...

    @staticmethod
    def sha1(data: List[int]) -> str:
        """
        Calculates the SHA1 hash of the provided data.
        """
        ...

    @staticmethod
    def sha256(data: List[int]) -> str:
        """
        Calculates the SHA256 hash of the provided data.
        """
        ...

    @staticmethod
    def hash_file(file: str, algo: Literal["MD5", "SHA1", "SHA256", "SHA512"]) -> str:
        """
        Calculates the hash of a file on disk.
        Algorithms: "MD5", "SHA1", "SHA256", "SHA512".
        """
        ...

    @staticmethod
    def encode_b64(
        content: str,
        encode_type: Optional[Literal["STANDARD", "STANDARD_NO_PAD", "URL_SAFE", "URL_SAFE_NO_PAD"]] = None
    ) -> str:
        """
        Encodes a string to Base64.
        """
        ...

    @staticmethod
    def decode_b64(
        content: str,
        encode_type: Optional[Literal["STANDARD", "STANDARD_NO_PAD", "URL_SAFE", "URL_SAFE_NO_PAD"]] = None
    ) -> str:
        """
        Decodes a Base64 encoded string.
        """
        ...

    @staticmethod
    def is_json(content: str) -> bool:
        """
        Checks if a string is valid JSON.
        """
        ...

    @staticmethod
    def from_json(content: str) -> Any:
        """
        Parses a JSON string into an Eldritch value (Dict, List, etc.).
        """
        ...

    @staticmethod
    def to_json(content: Any) -> str:
        """
        Serializes an Eldritch value into a JSON string.
        """
        ...


class Events:
    """
    The `events` library provides a mechanism for registering callbacks that are executed when specific agent events occur.
    """
    ON_CALLBACK_START: str = "on_callback_start"
    ON_CALLBACK_END: str = "on_callback_end"
    ON_TASK_START: str = "on_task_start"
    ON_TASK_END: str = "on_task_end"

    @staticmethod
    def list() -> List[str]:
        """
        Returns a list of all available events.
        """
        ...

    @staticmethod
    def register(event: str, f: Callable[..., Any]) -> None:
        """
        Registers a callback function for a specific event.
        """
        ...


class File:
    """
    The `file` library provides comprehensive filesystem operations.
    """
    @staticmethod
    def append(path: str, content: str) -> None:
        """
        Appends content to a file. If the file does not exist, it will be created.
        """
        ...

    @staticmethod
    def compress(src: str, dst: str) -> None:
        """
        Compresses a file or directory using GZIP. If `src` is a directory, it will be archived (tar) before compression.
        """
        ...

    @staticmethod
    def copy(src: str, dst: str) -> None:
        """
        Copies a file from source to destination. If the destination exists, it will be overwritten.
        """
        ...

    @staticmethod
    def decompress(src: str, dst: str) -> None:
        """
        Decompresses a GZIP file. If the file is a tar archive, it will be extracted to the destination directory.
        """
        ...

    @staticmethod
    def exists(path: str) -> bool:
        """
        Checks if a file or directory exists at the given path.
        """
        ...

    @staticmethod
    def follow(path: str, fn: Callable[[str], Any]) -> None:
        """
        Follows a file (tail -f) and executes a callback function for each new line.
        """
        ...

    @staticmethod
    def is_dir(path: str) -> bool:
        """
        Checks if the path exists and is a directory.
        """
        ...

    @staticmethod
    def is_file(path: str) -> bool:
        """
        Checks if the path exists and is a file.
        """
        ...

    @staticmethod
    def list(path: Optional[str] = None) -> List[FileStat]:
        """
        Lists files and directories in the specified path. Supports globbing patterns.
        """
        ...

    @staticmethod
    def mkdir(path: str, parent: Optional[bool] = None) -> None:
        """
        Creates a new directory. If `parent` is `True`, creates parent directories as needed.
        """
        ...

    @staticmethod
    def move(src: str, dst: str) -> None:
        """
        Moves or renames a file or directory.
        """
        ...

    @staticmethod
    def parent_dir(path: str) -> str:
        """
        Returns the parent directory of the given path.
        """
        ...

    @staticmethod
    def read(path: str) -> str:
        """
        Reads the entire content of a file as a string.
        """
        ...

    @staticmethod
    def read_binary(path: str) -> List[int]:
        """
        Reads the entire content of a file as binary data.
        """
        ...

    @staticmethod
    def pwd() -> Optional[str]:
        """
        Returns the current working directory of the process.
        """
        ...

    @staticmethod
    def remove(path: str) -> None:
        """
        Deletes a file or directory recursively.
        """
        ...

    @staticmethod
    def replace(path: str, pattern: str, value: str) -> None:
        """
        Replaces the first occurrence of a regex pattern in a file with a replacement string.
        """
        ...

    @staticmethod
    def replace_all(path: str, pattern: str, value: str) -> None:
        """
        Replaces all occurrences of a regex pattern in a file with a replacement string.
        """
        ...

    @staticmethod
    def temp_file(name: Optional[str] = None) -> str:
        """
        Creates a temporary file and returns its path.
        """
        ...

    @staticmethod
    def template(template_path: str, dst: str, args: Dict[str, Any], autoescape: bool) -> None:
        """
        Renders a Jinja2 template file to a destination path.
        """
        ...

    @staticmethod
    def timestomp(
        path: str,
        mtime: Optional[Union[int, str]] = None,
        atime: Optional[Union[int, str]] = None,
        ctime: Optional[Union[int, str]] = None,
        ref_file: Optional[str] = None
    ) -> None:
        """
        Timestomps a file. Modifies the timestamps (modified, access, creation).
        """
        ...

    @staticmethod
    def write(path: str, content: str) -> None:
        """
        Writes content to a file, overwriting it if it exists.
        """
        ...

    @staticmethod
    def find(
        path: str,
        name: Optional[str] = None,
        file_type: Optional[Literal["file", "dir"]] = None,
        permissions: Optional[int] = None,
        modified_time: Optional[int] = None,
        create_time: Optional[int] = None
    ) -> List[str]:
        """
        Finds files matching specific criteria.
        """
        ...


class Http:
    """
    The `http` library enables the agent to make HTTP requests.
    """
    @staticmethod
    def download(uri: str, dst: str, allow_insecure: Optional[bool] = None) -> None:
        """
        Downloads a file from a URL to a local path.
        """
        ...

    @staticmethod
    def get(
        uri: str,
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_insecure: Optional[bool] = None,
    ) -> HttpResponse:
        """
        Performs an HTTP GET request.
        """
        ...

    @staticmethod
    def post(
        uri: str,
        body: Optional[str] = None,
        form: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_insecure: Optional[bool] = None,
    ) -> HttpResponse:
        """
        Performs an HTTP POST request.
        """
        ...


class Pivot:
    """
    The `pivot` library provides tools for lateral movement, scanning, and tunneling.
    """
    @staticmethod
    def reverse_shell_pty(cmd: Optional[str] = None) -> None:
        """
        Spawns a reverse shell with a PTY (Pseudo-Terminal) attached.
        """
        ...

    @staticmethod
    def reverse_shell_repl() -> None:
        """
        Spawns a basic REPL-style reverse shell with an Eldritch interpreter.
        """
        ...

    @staticmethod
    def create_portal() -> None:
        """
        Opens a portal bi-directional stream.
        """
        ...

    @staticmethod
    def ssh_exec(
        target: str,
        port: int,
        command: str,
        username: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        key_password: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ShellResult:
        """
        Executes a command on a remote host via SSH.
        """
        ...

    @staticmethod
    def ssh_copy(
        target: str,
        port: int,
        src: str,
        dst: str,
        username: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        key_password: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> str:
        """
        Copies a file to a remote host via SSH (SCP/SFTP).
        """
        ...

    @staticmethod
    def port_scan(
        target_cidrs: List[str],
        ports: List[int],
        protocol: Literal["tcp", "udp"],
        timeout: int,
        fd_limit: Optional[int] = None,
    ) -> List[PortScanResult]:
        """
        Scans TCP/UDP ports on target hosts.
        """
        ...

    @staticmethod
    def arp_scan(target_cidrs: List[str]) -> List[ARPTableEntry]:
        """
        Performs an ARP scan to discover live hosts on the local network.
        """
        ...

    @staticmethod
    def ncat(address: str, port: int, data: str, protocol: Literal["tcp", "udp"]) -> str:
        """
        Sends arbitrary data to a host via TCP or UDP and waits for a response.
        """
        ...


class Process:
    """
    The `process` library allows interaction with system processes.
    """
    @staticmethod
    def info(pid: Optional[int] = None) -> ProcessInfo:
        """
        Returns detailed information about a specific process.
        """
        ...

    @staticmethod
    def kill(pid: int) -> None:
        """
        Terminates a process by its ID.
        """
        ...

    @staticmethod
    def list() -> List[ProcessInfoSimple]:
        """
        Lists all currently running processes.
        """
        ...

    @staticmethod
    def name(pid: int) -> str:
        """
        Returns the name of a process given its ID.
        """
        ...

    @staticmethod
    def netstat() -> List[SocketInfo]:
        """
        Returns a list of active network connections (TCP/UDP/Unix).
        """
        ...


class Random:
    """
    The `random` library provides cryptographically secure random value generation.
    """
    @staticmethod
    def bool() -> bool:
        """
        Generates a random boolean value.
        """
        ...

    @staticmethod
    def bytes(len: int) -> List[int]:
        """
        Generates a list of random bytes.
        """
        ...

    @staticmethod
    def int(min: int, max: int) -> int:
        """
        Generates a random integer within a range [min, max).
        """
        ...

    @staticmethod
    def string(len: int, charset: Optional[str] = None) -> str:
        """
        Generates a random string.
        """
        ...

    @staticmethod
    def uuid() -> str:
        """
        Generates a random UUID (v4).
        """
        ...


class Regex:
    """
    The `regex` library provides regular expression capabilities using Rust's `regex` crate syntax.
    """
    @staticmethod
    def match_all(haystack: str, pattern: str) -> List[str]:
        """
        Returns all substrings matching the pattern in the haystack.
        """
        ...

    @staticmethod
    def match(haystack: str, pattern: str) -> str:
        """
        Returns the first substring matching the pattern.
        """
        ...

    @staticmethod
    def replace_all(haystack: str, pattern: str, value: str) -> str:
        """
        Replaces all occurrences of the pattern with the value.
        """
        ...

    @staticmethod
    def replace(haystack: str, pattern: str, value: str) -> str:
        """
        Replaces the first occurrence of the pattern with the value.
        """
        ...


class Report:
    """
    The `report` library handles structured data reporting to the C2 server.
    """
    @staticmethod
    def file(path: str) -> None:
        """
        Reports (exfiltrates) a file from the host to the C2 server.
        """
        ...

    @staticmethod
    def process_list(list: List[Dict[str, Any]]) -> None:
        """
        Reports a snapshot of running processes.
        """
        ...

    @staticmethod
    def ssh_key(username: str, key: str) -> None:
        """
        Reports a captured SSH private key.
        """
        ...

    @staticmethod
    def user_password(username: str, password: str) -> None:
        """
        Reports a captured user password.
        """
        ...


class Sys:
    """
    The `sys` library provides general system interaction capabilities.
    """
    @staticmethod
    def dll_inject(dll_path: str, pid: int) -> None:
        """
        Injects a DLL from disk into a remote process.
        """
        ...

    @staticmethod
    def dll_reflect(dll_bytes: List[int], pid: int, function_name: str) -> None:
        """
        Reflectively injects a DLL from memory into a remote process.
        """
        ...

    @staticmethod
    def exec(
        path: str,
        args: List[str],
        disown: Optional[bool] = None,
        env_vars: Optional[Dict[str, str]] = None,
        input: Optional[str] = None,
    ) -> ShellResult:
        """
        Executes a program directly (without a shell).
        """
        ...

    @staticmethod
    def get_env() -> Dict[str, str]:
        """
        Returns the current process's environment variables.
        """
        ...

    @staticmethod
    def get_ip() -> List[NetworkInterface]:
        """
        Returns network interface information.
        """
        ...

    @staticmethod
    def get_os() -> OSInfo:
        """
        Returns information about the operating system.
        """
        ...

    @staticmethod
    def get_pid() -> int:
        """
        Returns the current process ID.
        """
        ...

    @staticmethod
    def get_reg(reghive: str, regpath: str) -> Dict[str, str]:
        """
        Reads values from the Windows Registry.
        """
        ...

    @staticmethod
    def get_user() -> UserInfo:
        """
        Returns information about the current user.
        """
        ...

    @staticmethod
    def hostname() -> str:
        """
        Returns the host's hostname.
        """
        ...

    @staticmethod
    def is_bsd() -> bool:
        """
        Checks if the system is BSD.
        """
        ...

    @staticmethod
    def is_linux() -> bool:
        """
        Checks if the system is Linux.
        """
        ...

    @staticmethod
    def is_macos() -> bool:
        """
        Checks if the system is macOS.
        """
        ...

    @staticmethod
    def is_windows() -> bool:
        """
        Checks if the system is Windows.
        """
        ...

    @staticmethod
    def shell(cmd: str) -> ShellResult:
        """
        Runs a command in the system shell.
        """
        ...

    @staticmethod
    def write_reg_hex(
        reghive: str, regpath: str, regname: str, regtype: str, regvalue: str
    ) -> bool:
        """
        Writes a hex string value to the Windows Registry.
        """
        ...

    @staticmethod
    def write_reg_int(
        reghive: str, regpath: str, regname: str, regtype: str, regvalue: int
    ) -> bool:
        """
        Writes an integer value to the Windows Registry.
        """
        ...

    @staticmethod
    def write_reg_str(
        reghive: str, regpath: str, regname: str, regtype: str, regvalue: str
    ) -> bool:
        """
        Writes a string value to the Windows Registry.
        """
        ...


class Time:
    """
    The `time` library provides time measurement, formatting, and sleep capabilities.
    """
    @staticmethod
    def format_to_epoch(input: str, format: str) -> int:
        """
        Converts a formatted time string to a Unix timestamp (epoch seconds).
        """
        ...

    @staticmethod
    def format_to_readable(input: int, format: str) -> str:
        """
        Converts a Unix timestamp to a readable string.
        """
        ...

    @staticmethod
    def now() -> int:
        """
        Returns the current time as a Unix timestamp.
        """
        ...

    @staticmethod
    def sleep(secs: int) -> None:
        """
        Pauses execution for the specified number of seconds.
        """
        ...


# --- Module Instances ---

agent: Agent = ...
"""Used for meta-style interactions with the agent itself."""
assets: Assets = ...
"""Used to interact with files stored natively in the agent."""
crypto: Crypto = ...
"""Used to encrypt/decrypt, decode, or hash data."""
events: Events = ...
"""Used for registering callbacks for agent events."""
file: File = ...
"""Used to interact with files on the system."""
http: Http = ...
"""Enables the agent to make HTTP requests."""
pivot: Pivot = ...
"""Provides tools for lateral movement, scanning, and tunneling."""
process: Process = ...
"""Allows interaction with system processes."""
random: Random = ...
"""Provides cryptographically secure random value generation."""
regex: Regex = ...
"""Provides regular expression capabilities."""
report: Report = ...
"""Handles structured data reporting to the C2 server."""
sys: Sys = ...
"""Provides general system interaction capabilities."""
time: Time = ...
"""Provides time measurement, formatting, and sleep capabilities."""

# --- Global Starlark Functions (Eldritch Specific) ---

def assert_(condition: bool, message: Optional[Any] = None) -> None:
    """
    Asserts that the condition is true. If not, fails the execution with the optional message.
    Usage: `assert(condition, "message")`
    """
    ...

def assert_eq(left: Any, right: Any, message: Optional[Any] = None) -> None:
    """
    Asserts that `left` and `right` are equal.
    Usage: `assert_eq(a, b, "a should equal b")`
    """
    ...

def builtins() -> List[str]:
    """Returns a list of names of all built-in functions."""
    ...

def dir(obj: Optional[Any] = None) -> List[str]:
    """Returns a list of the names of the attributes of the given object. If no object is provided, returns names in the current scope."""
    ...

def eprint(*values: Any) -> None:
    """Prints values to the standard error stream."""
    ...

def fail(message: Any) -> None:
    """Aborts execution with an error message."""
    ...

def libs() -> List[str]:
    """Returns a list of names of all loaded libraries."""
    ...

def pprint(*values: Any) -> None:
    """Pretty-prints values to the console."""
    ...

def reduce(function: Callable[[Any, Any], Any], iterable: Iterable[Any], initializer: Optional[Any] = None) -> Any:
    """Apply a function of two arguments cumulatively to the items of a sequence, from left to right, so as to reduce the sequence to a single value."""
    ...

def tprint(data: List[Dict[str, Any]]) -> None:
    """Prints a list of dictionaries as a markdown table."""
    ...

input_params: Dict[str, Any] = ...
"""Parameters passed to the tome from the UI."""
