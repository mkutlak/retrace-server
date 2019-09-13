import re

from .config import GZIP_BIN, TAR_BIN, XZ_BIN


GETTEXT_DOMAIN = "retrace-server"

# filename: max_size (<= 0 unlimited)
ALLOWED_FILES = {
    "coredump": 0,
    "executable": 512,
    "package": 128,
    "packages": (1 << 20), # 1MB
    "os_release": 128,
    "os_release_in_rootdir": 128,
    "rootdir": 256,
    "release": 128,
    "vmcore": 0,
}

TASK_RETRACE, TASK_DEBUG, TASK_VMCORE, TASK_RETRACE_INTERACTIVE, \
  TASK_VMCORE_INTERACTIVE = range(5)

TASK_TYPES = [TASK_RETRACE, TASK_DEBUG, TASK_VMCORE,
              TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]

ARCHIVE_UNKNOWN, ARCHIVE_GZ, ARCHIVE_ZIP, \
  ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, \
  ARCHIVE_7Z, ARCHIVE_LZOP = range(8)

REQUIRED_FILES = {
    TASK_RETRACE:             ["coredump", "executable", "package"],
    TASK_DEBUG:               ["coredump", "executable", "package"],
    TASK_VMCORE:              ["vmcore"],
    TASK_RETRACE_INTERACTIVE: ["coredump", "executable", "package"],
    TASK_VMCORE_INTERACTIVE:  ["vmcore"],
}

SUFFIX_MAP = {
    ARCHIVE_GZ: ".gz",
    ARCHIVE_BZ2: ".bz2",
    ARCHIVE_XZ: ".xz",
    ARCHIVE_ZIP: ".zip",
    ARCHIVE_7Z: ".7z",
    ARCHIVE_TAR: ".tar",
    ARCHIVE_LZOP: ".lzop",
    ARCHIVE_UNKNOWN: "",
}

BUGZILLA_STATUS = ["NEW", "ASSIGNED", "ON_DEV", "POST", "MODIFIED", "ON_QA", "VERIFIED",
                   "RELEASE_PENDING", "CLOSED"]

#characters, numbers, dash (utf-8, iso-8859-2 etc.)
INPUT_CHARSET_PARSER = re.compile(r"^([a-zA-Z0-9\-]+)(,.*)?$")
#en_GB, sk-SK, cs, fr etc.
INPUT_LANG_PARSER = re.compile(r"^([a-z]{2}([_\-][A-Z]{2})?)(,.*)?$")
#characters allowed by Fedora Naming Guidelines
INPUT_PACKAGE_PARSER = re.compile(r"^([1-9][0-9]*:)?[a-zA-Z0-9\-\.\_\+\~]+$")
#architecture (i386, x86_64, armv7hl, mips4kec)
INPUT_ARCH_PARSER = re.compile(r"^[a-zA-Z0-9_]+$")
#name-version-arch (fedora-16-x86_64, rhel-6.2-i386, opensuse-12.1-x86_64)
INPUT_RELEASEID_PARSER = re.compile(r"^[a-zA-Z0-9]+\-[0-9a-zA-Z\.]+\-[a-zA-Z0-9_]+$")

CORE_ARCH_PARSER = re.compile(r"core file,? .*(x86-64|80386|ARM|aarch64|IBM S/390|64-bit PowerPC)")
PACKAGE_PARSER = re.compile(r"^(.+)-([0-9]+(\.[0-9]+)*-[0-9]+)\.([^-]+)$")
DF_OUTPUT_PARSER = re.compile(r"^([^ ^\t]*)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+(.*)$")
DU_OUTPUT_PARSER = re.compile(r"^([0-9]+)")
URL_PARSER = re.compile(r"^/([0-9]+)/?")

REPODIR_NAME_PARSER = re.compile(r"^[^\-]+\-[^\-]+\-[^\-]+$")

KO_DEBUG_PARSER = re.compile(r"^.*/([a-zA-Z0-9_\-]+)\.ko\.debug$")

DUMP_LEVEL_PARSER = re.compile(r"^[ \t]*dump_level[ \t]*:[ \t]*([0-9]+).*$")

WORKER_RUNNING_PARSER = re.compile(r"^[ \t]*([0-9]+)[ \t]+[0-9]+[ \t]+([^ ^\t]+)[ \t]"
                                   r"+.*retrace-server-worker ([0-9]+)( .*)?$")

MD5_PARSER = re.compile(r"[a-fA-F0-9]{32}")

UNITS = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]

HANDLE_ARCHIVE = {
    "application/x-xz-compressed-tar": {
        "unpack": [TAR_BIN, "xJf"],
        "size": ([XZ_BIN, "--list", "--robot"],
                 re.compile(r"^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
        "type": ARCHIVE_XZ,
    },

    "application/x-gzip": {
        "unpack": [TAR_BIN, "xzf"],
        "size": ([GZIP_BIN, "--list"], re.compile(r"^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
        "type": ARCHIVE_GZ,
    },

    "application/x-tar": {
        "unpack": [TAR_BIN, "xf"],
        "size": (["ls", "-l"],
                 re.compile(r"^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+([0-9]+).*$")),
        "type": ARCHIVE_TAR,
    },
}

FTP_SUPPORTED_EXTENSIONS = [".tar.gz", ".tgz", ".tarz", ".tar.bz2", ".tar.xz",
                            ".tar", ".gz", ".bz2", ".xz", ".Z", ".zip"]

REPO_PREFIX = "retrace-"
EXPLOITABLE_PLUGIN_PATH = "/usr/libexec/abrt-gdb-exploitable"
EXPLOITABLE_SEPARATOR = "== EXPLOITABLE ==\n"

TASKPASS_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


STATUS_ANALYZE, STATUS_INIT, STATUS_BACKTRACE, STATUS_CLEANUP, \
STATUS_STATS, STATUS_FINISHING, STATUS_SUCCESS, STATUS_FAIL, \
STATUS_DOWNLOADING, STATUS_POSTPROCESS, STATUS_CALCULATING_MD5SUM = range(11)

STATUS = [
    "Analyzing crash data",
    "Preparing environment for backtrace generation",
    "Generating backtrace",
    "Cleaning environment after backtrace generation",
    "Saving crash statistics",
    "Finishing task",
    "Retrace job finished successfully",
    "Retrace job failed",
    "Downloading remote resources",
    "Post-processing downloaded file",
    "Calculating md5sum",
]

ARCHITECTURES = {"src", "noarch", "i386", "i486", "i586", "i686", "x86_64",
                 "s390", "s390x", "ppc", "ppc64", "ppc64le", "ppc64iseries",
                 "armel", "armhfp", "armv5tel", "armv7l", "armv7hl",
                 "armv7hnl", "aarch64", "sparc", "sparc64", "mips4kec",
                 "ia64"}

# armhfp is not correct, but there is no way to distinguish armv5/armv6/armv7 coredumps
# as armhfp (RPM armv7hl) is the only supported now, let's approximate arm = armhfp

# "arm" has been intentionally removed - when guessing architecture, it matches
# "alarm" or "hdparm" and thus leads to wrong results.
# As soon as plain "arm" needs to be supported, this needs to be solved properly.
ARCH_MAP = {
    "i386": {"i386", "i486", "i586", "i686"},
    "armhfp": {"armhfp", "armel", "armv5tel", "armv7l", "armv7hl", "armv7hnl"},
    "x86_64": {"x86_64"},
    "s390x": {"s390x"},
    "ppc64": {"ppc64"},
    "ppc64le": {"ppc64le"},
    "aarch64": {"aarch64"},
}

PYTHON_LABLE_START = "----------PYTHON-START--------"
PYTHON_LABLE_END = "----------PYTHON--END---------"
