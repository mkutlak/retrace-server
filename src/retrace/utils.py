import os
import re
import errno
import magic
import ftplib
import smtplib

from signal import SIG_DFL, SIGPIPE, getsignal, signal
from subprocess import PIPE, STDOUT, call, Popen
from dnf.subject import Subject
from hawkey import FORM_NEVRA

from .common import log_error
from .config import Config, DF_BIN, DU_BIN
from .defs import *

CONFIG = Config()


def lock(lockfile):
    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as ex:
        if ex.errno == errno.EEXIST:
            return False
        else:
            raise ex

    os.close(fd)
    return True

def unlock(lockfile):
    try:
        if os.path.getsize(lockfile) == 0:
            os.unlink(lockfile)
    except:
        return False

    return True

def get_canon_arch(arch):
    for canon_arch, derived_archs in ARCH_MAP.items():
        if arch in derived_archs:
            return canon_arch

    return arch

def free_space(path):
    child = Popen([DF_BIN, "-B", "1", path], stdout=PIPE, encoding='utf-8')
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = DF_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(4))

    return None

def dir_size(path):
    child = Popen([DU_BIN, "-sb", path], stdout=PIPE, encoding='utf-8')
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = DU_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(1))

    return 0

def unpacked_size(archive, mime):
    command, parser = HANDLE_ARCHIVE[mime]["size"]
    child = Popen(command + [archive], stdout=PIPE, encoding='utf-8')
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = parser.match(line)
        if match:
            return int(match.group(1))

    return None

def get_supported_releases():
    result = []
    files = os.listdir(CONFIG["RepoDir"])
    for f in files:
        fullpath = os.path.join(CONFIG["RepoDir"], f)
        if not os.path.isdir(fullpath):
            continue

        if REPODIR_NAME_PARSER.match(f) and \
           os.path.isdir(os.path.join(fullpath, "repodata")):
            result.append(f)

    return result

def parse_http_gettext(lang, charset):
    result = lambda x: x
    lang_match = INPUT_LANG_PARSER.match(lang)
    charset_match = INPUT_CHARSET_PARSER.match(charset)
    if lang_match and charset_match:
        try:
            result = gettext.translation(GETTEXT_DOMAIN,
                                         languages=[lang_match.group(1)],
                                         codeset=charset_match.group(1)).gettext
        except:
            pass

    return result

def guess_arch(coredump_path):
    child = Popen(["file", coredump_path], stdout=PIPE, encoding='utf-8')
    output = child.communicate()[0]
    match = CORE_ARCH_PARSER.search(output)
    if match:
        if match.group(1) == "80386":
            return "i386"
        elif match.group(1) == "x86-64":
            return "x86_64"
        elif match.group(1) == "ARM":
            # hack - There is no reliable way to determine which ARM
            # version the coredump is. At the moment we only support
            # armv7hl / armhfp - let's approximate arm = armhfp
            return "armhfp"
        elif match.group(1) == "aarch64":
            return "aarch64"
        elif match.group(1) == "IBM S/390":
            return "s390x"
        elif match.group(1) == "64-bit PowerPC":
            if "LSB" in output:
                return "ppc64le"

            return "ppc64"

    result = None
    child = Popen(["strings", coredump_path], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    line = child.stdout.readline()
    while line:
        for canon_arch, derived_archs in ARCH_MAP.items():
            if any(arch in line for arch in derived_archs):
                result = canon_arch
                break

        if result is not None:
            break

        line = child.stdout.readline()

    child.kill()
    child.stdout.close()

    # "ppc64le" matches both ppc64 and ppc64le
    # if file magic says little endian, fix it
    if result == "ppc64" and "LSB" in output:
        result = "ppc64le"

    return result

def splitFilename(filename):
    """
    Pass in a standard style rpm fullname

    Return a name, version, release, epoch, arch, e.g.::
        foo-1.0-1.i386.rpm returns foo, 1.0, 1, i386
    """

    if filename[-4:] == '.rpm':
        filename = filename[:-4]

    subject = Subject(filename)
    possible_nevra = list(subject.get_nevra_possibilities(forms=FORM_NEVRA))
    if possible_nevra:
        nevra = possible_nevra[0]
    else:
        return None, None, None, None, None

    return nevra.name, nevra.version, nevra.release, nevra.epoch, nevra.arch

def remove_epoch(nvr):
    pos = nvr.find(":")
    if pos > 0:
        return nvr[pos + 1:]
    return nvr

def is_package_known(package_nvr, arch, releaseid=None):
    if CONFIG["UseFafPackages"]:
        from pyfaf.storage import getDatabase
        from pyfaf.queries import get_package_by_nevra
        db = getDatabase()
        (n, v, r, e, _a) = splitFilename(package_nvr+".mockarch.rpm")
        for derived_archs in ARCH_MAP.values():
            if arch not in derived_archs:
                continue
            for a in derived_archs:
                p = get_package_by_nevra(db, n, e or 0, v, r, a)
                if p is not None:
                    return True
        else:
            # Try with noarch
            p = get_package_by_nevra(db, n, e or 0, v, r, "noarch")
            if p is not None:
                return True

            return False

    if releaseid is None:
        releases = get_supported_releases()
    else:
        releases = [releaseid]

    candidates = []
    package_nvr = remove_epoch(package_nvr)
    for releaseid in releases:
        for derived_archs in ARCH_MAP.values():
            if arch not in derived_archs:
                continue

            for a in derived_archs:
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                               "%s.%s.rpm" % (package_nvr, a)))
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                               "%s.%s.rpm" % (package_nvr, a)))
            break
        else:
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                           "%s.%s.rpm" % (package_nvr, arch)))
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                           "%s.%s.rpm" % (package_nvr, arch)))

    return any([os.path.isfile(f) for f in candidates])


def run_gdb(savedir, plugin):
    #exception is caught on the higher level
    exec_file = open(os.path.join(savedir, "crash", "executable"), "r")
    executable = exec_file.read(ALLOWED_FILES["executable"])
    exec_file.close()

    if '"' in executable or "'" in executable:
        raise Exception("Executable contains forbidden characters")

    with open(os.devnull, "w") as null:
        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls '%s'" % executable],
                      stdout=PIPE, stderr=null, encoding='utf-8')
        output = child.communicate()[0]
        if output.strip() != executable:
            raise Exception("The appropriate package set could not be installed")

        chmod = call(["/usr/bin/mock", "shell", "--configdir", savedir,
                      "--", "/bin/chmod a+r '%s'" % executable],
                     stdout=null, stderr=null)

        if chmod != 0:
            raise Exception("Unable to chmod the executable")

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls '%s'" % EXPLOITABLE_PLUGIN_PATH],
                      stdout=PIPE, stderr=null, encoding='utf-8')
        add_exploitable = child.communicate()[0].strip() == EXPLOITABLE_PLUGIN_PATH

        batfile = os.path.join(savedir, "gdb.sh")
        with open(batfile, "w") as gdbfile:
            gdbfile.write("%s -batch " % plugin.gdb_executable)
            if add_exploitable:
                gdbfile.write("-ex 'python exec(open(\"/usr/libexec/abrt-gdb-exploitable\").read())' ")
            gdbfile.write("-ex 'file %s' "
                          "-ex 'core-file /var/spool/abrt/crash/coredump' "
                          "-ex 'echo %s\n' "
                          "-ex 'py-bt' "
                          "-ex 'py-list' "
                          "-ex 'py-locals' "
                          "-ex 'echo %s\n' "
                          "-ex 'thread apply all -ascending backtrace full 2048' "
                          "-ex 'info sharedlib' "
                          "-ex 'print (char*)__abort_msg' "
                          "-ex 'print (char*)__glib_assert_msg' "
                          "-ex 'info registers' "
                          "-ex 'disassemble' " % (executable, PYTHON_LABLE_START, PYTHON_LABLE_END))
            if add_exploitable:
                gdbfile.write("-ex 'echo %s' "
                              "-ex 'abrt-exploitable'" % EXPLOITABLE_SEPARATOR)

        copyin = call(["/usr/bin/mock", "--configdir", savedir, "--copyin",
                       batfile, "/var/spool/abrt/gdb.sh"],
                      stdout=null, stderr=null)
        if copyin:
            raise Exception("Unable to copy GDB launcher into chroot")

        chmod = call(["/usr/bin/mock", "--configdir", savedir, "shell",
                      "--", "/bin/chmod a+rx /var/spool/abrt/gdb.sh"],
                     stdout=null, stderr=null)
        if chmod:
            raise Exception("Unable to chmod GDB launcher")

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "su mockbuild -c '/bin/sh /var/spool/abrt/gdb.sh'",
                       # redirect GDB's stderr, ignore mock's stderr
                       "2>&1"], stdout=PIPE, stderr=null, encoding='utf-8')

    backtrace = child.communicate()[0].strip()
    if child.wait():
        raise Exception("Running GDB failed")

    exploitable = None
    if EXPLOITABLE_SEPARATOR in backtrace:
        backtrace, exploitable = backtrace.rsplit(EXPLOITABLE_SEPARATOR, 1)

    if not backtrace:
        raise Exception("An unusable backtrace has been generated")

    python_labels = PYTHON_LABLE_START+'\n'+PYTHON_LABLE_END+'\n'
    if python_labels in backtrace:
        backtrace = backtrace.replace(python_labels, "")

    return backtrace, exploitable




#
# In real-world testing, approximately 60% of the time the kernel
# version of a vmcore can be identified with the crash tool.
# In the other 40% of the time, we must use some other method.
#
# The below function contains a couple regex searches that work
# across a wide variety of vmcore formats and kernel versions.
# We do not attempt to identify the file type since this is often not
# reliable, but we assume the version information exists in some form
# in the first portion of the file.  Testing has indicated that we do
# not need to scan the entire file but can rely on a small portion
# at the start of the file, which helps preserve useful pages in the
# OS page cache.
#
# The following regex's are used for the 40% scenario
# 1. Look for 'OSRELEASE='.  For example:
# OSRELEASE=2.6.18-406.el5
# NOTE: We can get "OSRELEASE=%" so we disallow the '%' character after the '='
OSRELEASE_VAR_PARSER = re.compile(b"OSRELEASE=([^%][^\x00\s]+)")
# 2. Look for "Linux version" string.  Note that this was taken from
# CAS 'fingerprint' database code.  For more info, see
# https://bugzilla.redhat.com/show_bug.cgi?id=1535592#c9 and
# https://github.com/battlemidget/core-analysis-system/blob/master/lib/cas/core.py#L96
# For exmaple:
# Linux version 3.10.0-693.11.1.el7.x86_64 (mockbuild@x86-041.build.eng.bos.redhat.com)
# (gcc version 4.8.5 20150623 (Red Hat 4.8.5-16) (GCC) ) #1 SMP Fri Oct 27 05:39:05 EDT 2017
LINUX_VERSION_PARSER = re.compile(b'Linux\sversion\s(\S+)\s+(.*20\d{1,2}|#1\s.*20\d{1,2})')
# 3. Look for the actual kernel release. For example:
# 2.6.32-209.el6.x86_64 | 2.6.18-197.el5
KERNEL_RELEASE_PARSER = re.compile(b'(\d+\.\d+\.\d+)-(\d+\.[^\x00\s]+)')

def get_kernel_release(vmcore, crash_cmd=["crash"]):
    # First use 'crash' to identify the kernel version.
    # set SIGPIPE to default handler for bz 1540253
    save = getsignal(SIGPIPE)
    signal(SIGPIPE, SIG_DFL)
    child = Popen(crash_cmd + ["--osrelease", vmcore], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    release = child.communicate()[0].strip()
    ret = child.wait()
    signal(SIGPIPE, save)

    # If the crash tool fails, we must try some other method.
    # Read the first small portion of the file and use a few different
    # regex searches on the file.
    if ret != 0 or \
       not release or \
       "\n" in release or \
       release == "unknown":
        try:
            fd = open(vmcore)
            fd.seek(0)
            blksize = 64000000
            b = os.read(fd.fileno(), blksize)
        except OSError as e:
            log_error("Failed to get kernel release - failed open/seek/read of file %s with errno(%d - '%s')"
                      % (vmcore, e.errno, e.strerror()))
            if fd:
                fd.close()
            return None
        release = OSRELEASE_VAR_PARSER.search(b)
        if release:
            release = release.group(1)
        if not release:
            release = LINUX_VERSION_PARSER.search(b)
            if release:
                release = release.group(1)
        if not release:
            release = KERNEL_RELEASE_PARSER.search(b)
            if release:
                release = release.group(0)
        if release:
            release = release.decode('utf-8')
        fd.close()

    # Clean up the release before returning or calling KernelVer
    if release is None or release == "unknown":
        log_error("Failed to get kernel release from file %s" % vmcore)
        return None
    else:
        release = release.rstrip('\0 \t\n')

    # check whether architecture is present
    try:
        result = KernelVer(release)
    except Exception as ex:
        log_error("Failed to parse kernel release from file %s, release = %s: %s" % (vmcore, release, str(ex)))
        return None

    if result.arch is None:
        result.arch = guess_arch(vmcore)
        if not result.arch:
            log_error("Unable to determine architecture from file %s, release = %s, arch result = %s"
                      % (vmcore, release, result))
            return None

    return result

def find_kernel_debuginfo(kernelver):
    vers = [kernelver]

    for canon_arch, derived_archs in ARCH_MAP.items():
        if kernelver.arch == canon_arch:
            vers = []
            for arch in derived_archs:
                cand = KernelVer(str(kernelver))
                cand.arch = arch
                vers.append(cand)

    if CONFIG["UseFafPackages"]:
        from pyfaf.storage import getDatabase
        from pyfaf.queries import get_package_by_nevra
        db = getDatabase()
        for ver in vers:
            p = get_package_by_nevra(db, ver.package_name_base(debug=True),
                                     0, ver.version, ver.release, ver._arch)
            if p is None:
                log_debug("FAF package not found for {0}".format(str(ver)))
            else:
                log_debug("FAF package found for {0}".format(str(ver)))
                if p.has_lob("package"):
                    log_debug("LOB location {0}".format(p.get_lob_path("package")))
                    return p.get_lob_path("package")
                else:
                    log_debug("LOB not found {0}".format(p.get_lob_path("package")))

    # search for the debuginfo RPM
    ver = None
    for release in os.listdir(CONFIG["RepoDir"]):
        for ver in vers:
            testfile = os.path.join(CONFIG["RepoDir"], release, "Packages", ver.package_name(debug=True))
            log_debug("Trying debuginfo file: %s" % testfile)
            if os.path.isfile(testfile):
                return testfile

            # should not happen, but anyway...
            testfile = os.path.join(CONFIG["RepoDir"], release, ver.package_name(debug=True))
            log_debug("Trying debuginfo file: %s" % testfile)
            if os.path.isfile(testfile):
                return testfile

    if ver is not None and ver.rt:
        basename = "kernel-rt"
    else:
        basename = "kernel"

    # koji-like root
    for ver in vers:
        testfile = os.path.join(CONFIG["KojiRoot"], "packages", basename, ver.version, ver.release,
                                ver._arch, ver.package_name(debug=True))
        log_debug("Trying debuginfo file: %s" % testfile)
        if os.path.isfile(testfile):
            return testfile

    if CONFIG["WgetKernelDebuginfos"]:
        downloaddir = os.path.join(CONFIG["RepoDir"], "download")
        if not os.path.isdir(downloaddir):
            oldmask = os.umask(0o007)
            os.makedirs(downloaddir)
            os.umask(oldmask)

        for ver in vers:
            pkgname = ver.package_name(debug=True)
            url = CONFIG["KernelDebuginfoURL"].replace("$VERSION", ver.version).replace("$RELEASE", ver.release)\
                  .replace("$ARCH", ver._arch).replace("$BASENAME", basename)
            if not url.endswith("/"):
                url += "/"
            url += pkgname

            log_debug("Trying debuginfo URL: %s" % url)
            with open(os.devnull, "w") as null:
                retcode = call(["wget", "-nv", "-P", downloaddir, url], stdout=null, stderr=null)

            if retcode == 0:
                return os.path.join(downloaddir, pkgname)

    return None

def cache_files_from_debuginfo(debuginfo, basedir, files):
    # important! if empty list is specified, the whole debuginfo would be unpacked
    if not files:
        return

    if not os.path.isfile(debuginfo):
        raise Exception("Given debuginfo file does not exist")

    # prepend absolute path /usr/lib/debug/... with dot, so that cpio can match it
    for i in range(len(files)):
        if files[i][0] == "/":
            files[i] = ".%s" % files[i]

    with open(os.devnull, "w") as null:
        rpm2cpio = Popen(["rpm2cpio", debuginfo], stdout=PIPE, stderr=null, encoding='utf-8')
        cpio = Popen(["cpio", "-id"] + files, stdin=rpm2cpio.stdout, stdout=null, stderr=null, cwd=basedir,
                     encoding='utf-8')
        rpm2cpio.wait()
        cpio.wait()
        rpm2cpio.stdout.close()


def get_vmcore_dump_level(task, vmlinux=None):
    vmcore_path = os.path.join(task.get_savedir(), "crash", "vmcore")
    if not os.path.isfile(vmcore_path):
        return None

    dmesg_path = os.path.join(task.get_savedir(), RetraceTask.MISC_DIR, "dmesg")
    if os.path.isfile(dmesg_path):
        os.unlink(dmesg_path)

    with open(os.devnull, "w") as null:
        cmd = ["makedumpfile", "-D", "--dump-dmesg", vmcore_path, dmesg_path]
        if vmlinux is not None:
            cmd.append("-x")
            cmd.append(vmlinux)

        result = None
        child = Popen(cmd, stdout=PIPE, stderr=null, encoding='utf-8')
        line = child.stdout.readline()
        while line:
            match = DUMP_LEVEL_PARSER.match(line)
            line = child.stdout.readline()
            if match is None:
                continue

            result = int(match.group(1))
            child.terminate()
            break

        child.wait()
        return result

def get_files_sizes(directory):
    result = []

    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath):
            result.append((fullpath, os.path.getsize(fullpath)))
        elif os.path.isdir(fullpath):
            result += get_files_sizes(fullpath)

    return sorted(result, key=lambda f_s: f_s[1], reverse=True)

def get_archive_type(path):
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    filetype = ms.file(path).lower()
    log_debug("File type: %s" % filetype)

    if "bzip2 compressed data" in filetype:
        log_debug("bzip2 detected")
        return ARCHIVE_BZ2
    elif "gzip compressed data" in filetype or \
         "compress'd data" in filetype:
        log_debug("gzip detected")
        return ARCHIVE_GZ
    elif "xz compressed data" in filetype:
        log_debug("xz detected")
        return ARCHIVE_XZ
    elif "7-zip archive data" in filetype:
        log_debug("7-zip detected")
        return ARCHIVE_7Z
    elif "zip archive data" in filetype:
        log_debug("zip detected")
        return ARCHIVE_ZIP
    elif "tar archive" in filetype:
        log_debug("tar detected")
        return ARCHIVE_TAR
    elif "lzop compressed data" in filetype:
        log_debug("lzop detected")
        return ARCHIVE_LZOP

    log_debug("unknown file type, unpacking finished")
    return ARCHIVE_UNKNOWN

def rename_with_suffix(frompath, topath):
    suffix = SUFFIX_MAP[get_archive_type(frompath)]
    if not topath.endswith(suffix):
        topath = "%s%s" % (topath, suffix)

    os.rename(frompath, topath)

    return topath

def unpack_vmcore(path):
    parentdir = os.path.dirname(path)
    archivebase = os.path.join(parentdir, "archive")
    archive = rename_with_suffix(path, archivebase)
    filetype = get_archive_type(archive)
    while filetype != ARCHIVE_UNKNOWN:
        files = set(f for (f, s) in get_files_sizes(parentdir))
        if filetype == ARCHIVE_GZ:
            check_run(["gunzip", archive])
        elif filetype == ARCHIVE_BZ2:
            check_run(["bunzip2", archive])
        elif filetype == ARCHIVE_XZ:
            check_run(["unxz", archive])
        elif filetype == ARCHIVE_ZIP:
            check_run(["unzip", archive, "-d", parentdir])
        elif filetype == ARCHIVE_7Z:
            check_run(["7za", "e", "-o%s" % parentdir, archive])
        elif filetype == ARCHIVE_TAR:
            check_run(["tar", "-C", parentdir, "-xf", archive])
        elif filetype == ARCHIVE_LZOP:
            check_run(["lzop", "-d", archive])
        else:
            raise Exception("Unknown archive type")

        if os.path.isfile(archive):
            os.unlink(archive)

        files_sizes = get_files_sizes(parentdir)
        newfiles = [f for (f, s) in files_sizes]
        diff = set(newfiles) - files
        vmcore_candidate = 0
        while vmcore_candidate < len(newfiles) and \
              not newfiles[vmcore_candidate] in diff:
            vmcore_candidate += 1

        if len(diff) > 1:
            archive = rename_with_suffix(newfiles[vmcore_candidate], archivebase)
            for filename in newfiles:
                if not filename in diff or \
                   filename == newfiles[vmcore_candidate]:
                    continue

                os.unlink(filename)

        elif len(diff) == 1:
            archive = rename_with_suffix(diff.pop(), archivebase)

        # just be explicit here - if no file changed, an archive
        # has most probably been unpacked to a file with same name
        else:
            pass

        for filename in os.listdir(parentdir):
            fullpath = os.path.join(parentdir, filename)
            if os.path.isdir(fullpath):
                shutil.rmtree(fullpath)

        filetype = get_archive_type(archive)

    os.rename(archive, os.path.join(parentdir, "vmcore"))


def unpack_coredump(path):
    processed = set()
    parentdir = os.path.dirname(path)
    files = set(f for (f, s) in get_files_sizes(parentdir))
    # Keep unpacking
    while len(files - processed) > 0:
        archive = list(files - processed)[0]
        filetype = get_archive_type(archive)
        if filetype == ARCHIVE_GZ:
            check_run(["gunzip", archive])
        elif filetype == ARCHIVE_BZ2:
            check_run(["bunzip2", archive])
        elif filetype == ARCHIVE_XZ:
            check_run(["unxz", archive])
        elif filetype == ARCHIVE_ZIP:
            check_run(["unzip", archive, "-d", parentdir])
        elif filetype == ARCHIVE_7Z:
            check_run(["7za", "e", "-o%s" % parentdir, archive])
        elif filetype == ARCHIVE_TAR:
            check_run(["tar", "-C", parentdir, "-xf", archive])
        elif filetype == ARCHIVE_LZOP:
            check_run(["lzop", "-d", archive])

        if os.path.isfile(archive) and filetype != ARCHIVE_UNKNOWN:
            os.unlink(archive)
        processed.add(archive)

        files = set(f for (f, s) in get_files_sizes(parentdir))

    # If coredump is not present, the biggest file becomes it
    if "coredump" not in os.listdir(parentdir):
        os.rename(get_files_sizes(parentdir)[0][0],
                  os.path.join(parentdir, "coredump"))

    for filename in os.listdir(parentdir):
        fullpath = os.path.join(parentdir, filename)
        if os.path.isdir(fullpath):
            shutil.rmtree(fullpath)


def get_task_est_time(taskdir):
    return 180

def unpack(archive, mime, targetdir=None):
    cmd = list(HANDLE_ARCHIVE[mime]["unpack"])
    cmd.append(archive)
    if not targetdir is None:
        cmd.append("--directory")
        cmd.append(targetdir)

    retcode = call(cmd)
    return retcode

def response(start_response, status, body="", extra_headers=[]):
    body = body.encode()
    start_response(status, [("Content-Type", "text/plain"), ("Content-Length", "%d" % len(body))] + extra_headers)
    return [body]

def run_ps():
    child = Popen(["ps", "-eo", "pid,ppid,etime,cmd"], stdout=PIPE, encoding='utf-8')
    lines = child.communicate()[0].split("\n")

    return lines

def get_running_tasks(ps_output=None):
    if not ps_output:
        ps_output = run_ps()

    result = []

    for line in ps_output:
        match = WORKER_RUNNING_PARSER.match(line)
        if match:
            result.append((int(match.group(1)), int(match.group(3)), match.group(2)))

    return result

def get_active_tasks():
    tasks = []

    for filename in os.listdir(CONFIG["SaveDir"]):
        if len(filename) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename))
        except:
            continue

        if CONFIG["AllowTaskManager"] and task.get_managed():
            continue

        if not task.has_log():
            tasks.append(task.get_taskid())

    return tasks

def get_md5_tasks():
    tasks = []

    for filename in os.listdir(CONFIG["SaveDir"]):
        if len(filename) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename))
        except:
            continue

        if not task.has_status():
            continue
        else:
            status = task.get_status()

        if status != STATUS_SUCCESS and status != STATUS_FAIL:
            continue

        if not task.has_finished_time():
            continue

        if not task.has_vmcore() and not task.has_coredump():
            continue

        if not task.has_md5sum():
            continue

        md5 = str.split(task.get_md5sum())[0]
        if not MD5_PARSER.search(md5):
            continue

        tasks.append(task)

    return tasks

def parse_rpm_name(name):
    result = {
        "epoch": 0,
        "name": None,
        "version": "",
        "release": "",
        "arch": "",
    }
    (result["name"],
     result["version"],
     result["release"],
     result["epoch"],
     result["arch"]) = splitFilename(name + ".mockarch.rpm")

    return result

def init_crashstats_db():
    # create the database group-writable and world-readable
    old_umask = os.umask(0o113)
    con = sqlite3.connect(os.path.join(CONFIG["SaveDir"], CONFIG["DBFile"]))
    os.umask(old_umask)

    query = con.cursor()
    query.execute("PRAGMA foreign_keys = ON")
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid, package, version,
      arch, starttime NOT NULL, duration NOT NULL, coresize, status NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      success(taskid REFERENCES tasks(id), pre NOT NULL, post NOT NULL,
              rootsize NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages(id INTEGER PRIMARY KEY AUTOINCREMENT,
               name NOT NULL, version NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages_tasks(pkgid REFERENCES packages(id),
                     taskid REFERENCES tasks(id))
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      buildids(taskid REFERENCES tasks(id), soname, buildid NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      reportfull(requesttime NOT NULL, ip NOT NULL)
    """)
    con.commit()

    return con

def save_crashstats(stats, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO tasks (taskid, package, version, arch,
      starttime, duration, coresize, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      """,
                  (stats["taskid"], stats["package"], stats["version"],
                   stats["arch"], stats["starttime"], stats["duration"],
                   stats["coresize"], stats["status"]))

    con.commit()
    if close:
        con.close()

    return query.lastrowid

def save_crashstats_success(statsid, pre, post, rootsize, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO success (taskid, pre, post, rootsize)
      VALUES (?, ?, ?, ?)
      """,
                  (statsid, pre, post, rootsize))

    con.commit()
    if close:
        con.close()

def save_crashstats_packages(statsid, packages, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for package in packages:
        pkgdata = parse_rpm_name(package)
        if pkgdata["name"] is None:
            continue

        ver = "%s-%s" % (pkgdata["version"], pkgdata["release"])
        query.execute("SELECT id FROM packages WHERE name = ? AND version = ?",
                      (pkgdata["name"], ver))
        row = query.fetchone()
        if row:
            pkgid = row[0]
        else:
            query.execute("INSERT INTO packages (name, version) VALUES (?, ?)",
                          (pkgdata["name"], ver))
            pkgid = query.lastrowid

        query.execute("""
          INSERT INTO packages_tasks (taskid, pkgid) VALUES (?, ?)
          """, (statsid, pkgid))

    con.commit()
    if close:
        con.close()

def save_crashstats_build_ids(statsid, buildids, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for soname, buildid in buildids:
        query.execute("""
          INSERT INTO buildids (taskid, soname, buildid)
          VALUES (?, ?, ?)
          """,
                      (statsid, soname, buildid))

    con.commit()
    if close:
        con.close()

def save_crashstats_reportfull(ip, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO reportfull (requesttime, ip)
      VALUES (?, ?)
      """,
                  (int(time.time()), ip))

    con.commit()
    if close:
        con.close()

def send_email(frm, to, subject, body):
    if isinstance(to, list):
        to = ",".join(to)

    if not isinstance(to, str):
        raise Exception("'to' must be either string or a list of strings")

    msg = "From: %s\n" \
          "To: %s\n" \
          "Subject: %s\n" \
          "\n" \
          "%s" % (frm, to, subject, body)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(frm, to, msg)
    smtp.close()

def ftp_init():
    if CONFIG["FTPSSL"]:
        ftp = ftplib.FTP_SSL(CONFIG["FTPHost"])
        ftp.prot_p()
    else:
        ftp = ftplib.FTP(CONFIG["FTPHost"])

    ftp.login(CONFIG["FTPUser"], CONFIG["FTPPass"])
    ftp.cwd(CONFIG["FTPDir"])

    return ftp

def ftp_close(ftp):
    try:
        ftp.quit()
    except:
        ftp.close()

def ftp_list_dir(ftpdir="/", ftp=None):
    close = False
    if ftp is None:
        ftp = ftp_init()
        close = True

    result = [f.lstrip("/") for f in ftp.nlst(ftpdir)]

    if close:
        ftp_close(ftp)

    return result

def check_run(cmd):
    child = Popen(cmd, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    stdout = child.communicate()[0]
    if child.wait():
        raise Exception("%s exitted with %d: %s" % (cmd[0], child.returncode, stdout))

def move_dir_contents(source, dest):
    for filename in os.listdir(source):
        path = os.path.join(source, filename)
        if os.path.isdir(path):
            move_dir_contents(path, dest)
        elif os.path.isfile(path):
            destfile = os.path.join(dest, filename)
            if os.path.isfile(destfile):
                i = 0
                newdest = "%s.%d" % (destfile, i)
                while os.path.isfile(newdest):
                    i += 1
                    newdest = "%s.%d" % (destfile, i)

                destfile = newdest

# try?
            os.rename(path, destfile)
# except?

    shutil.rmtree(source)

def human_readable_size(bytes):
    size = float(bytes)
    unit = 0
    while size > 1024.0 and unit < len(UNITS) - 1:
        unit += 1
        size /= 1024.0

    return "%.2f %s" % (size, UNITS[unit])
