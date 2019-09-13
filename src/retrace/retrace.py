import errno
import grp
import hashlib
import os
import random
import shutil
import stat
import sys
import time

from subprocess import Popen, PIPE, STDOUT, call, TimeoutExpired
from six.moves import range, urllib, string_types

from .common import log_warn, log_debug, log_info
from .config import Config
from .defs import *
from .utils import (cache_files_from_debuginfo, find_kernel_debuginfo, ftp_close, ftp_init,
                    get_archive_type, get_canon_arch, get_kernel_release, get_running_tasks,
                    get_vmcore_dump_level, guess_arch, human_readable_size, move_dir_contents,
                    unpack_coredump, unpack_vmcore)


class RetraceError(Exception):
    pass


class RetraceWorkerError(RetraceError):
    def __init__(self, message=None, errorcode=1):
        super(RetraceWorkerError, self).__init__(message)
        self.errorcode = errorcode


class KernelVer(object):
    FLAVOUR = ["debug", "highbank", "hugemem",
               "kirkwood", "largesmp", "PAE", "omap",
               "smp", "tegra", "xen", "xenU"]

    ARCH = ARCHITECTURES

    @property
    def arch(self):
        return get_canon_arch(self._arch)

    @arch.setter
    def arch(self, value):
        self._arch = value

    def __init__(self, kernelver_str):
        log_debug("Parsing kernel version '%s'" % kernelver_str)
        self.kernelver_str = kernelver_str
        self.flavour = None
        for kf in KernelVer.FLAVOUR:
            if kernelver_str.endswith(".%s" % kf):
                self.flavour = kf
                kernelver_str = kernelver_str[:-len(kf) - 1]
                break

        self._arch = None
        for ka in KernelVer.ARCH:
            if kernelver_str.endswith(".%s" % ka):
                self._arch = ka
                kernelver_str = kernelver_str[:-len(ka) - 1]
                break

        self.version, self.release = kernelver_str.split("-", 1)

        if self.flavour is None:
            for kf in KernelVer.FLAVOUR:
                if self.release.endswith(kf):
                    self.flavour = kf
                    self.release = self.release[:-len(kf)]
                    break

        self.rt = "rt" in self.release

        log_debug("Version: '%s'; Release: '%s'; Arch: '%s'; Flavour: '%s'; Realtime: %s"
                  % (self.version, self.release, self._arch, self.flavour, self.rt))

    def __str__(self):
        result = "%s-%s" % (self.version, self.release)

        if self._arch:
            result = "%s.%s" % (result, self._arch)

        if self.flavour:
            result = "%s.%s" % (result, self.flavour)

        return result

    def __repr__(self):
        return self.__str__()

    def package_name_base(self, debug=False):
        base = "kernel"
        if self.rt:
            base = "%s-rt" % base

        if self.flavour and not (debug and ".EL" in self.release):
            base = "%s-%s" % (base, self.flavour)

        if debug:
            base = "%s-debuginfo" % base

        return base

    def package_name(self, debug=False):
        if self._arch is None:
            raise Exception("Architecture is required for building package name")

        base = self.package_name_base(debug)

        return "%s-%s-%s.%s.rpm" % (base, self.version, self.release, self._arch)

    def needs_arch(self):
        return self._arch is None

class RetraceTask:
    """Represents Retrace server's task."""

    BACKTRACE_FILE = "retrace_backtrace"
    CASENO_FILE = "caseno"
    BUGZILLANO_FILE = "bugzillano"
    CRASHRC_FILE = "crashrc"
    CRASH_CMD_FILE = "crash_cmd"
    DOWNLOADED_FILE = "downloaded"
    MD5SUM_FILE = "md5sum"
    FINISHED_FILE = "finished_time"
    KERNELVER_FILE = "kernelver"
    LOG_FILE = "retrace_log"
    MANAGED_FILE = "managed"
    MISC_DIR = "misc"
    MOCK_LOG_DIR = "log"
    NOTES_FILE = "notes"
    NOTIFY_FILE = "notify"
    PASSWORD_FILE = "password"
    PROGRESS_FILE = "progress"
    REMOTE_FILE = "remote"
    STARTED_FILE = "started_time"
    STATUS_FILE = "status"
    TYPE_FILE = "type"
    URL_FILE = "url"
    VMLINUX_FILE = "vmlinux"
    VMCORE_FILE = "crash/vmcore"
    COREDUMP_FILE = "crash/coredump"
    MOCK_DEFAULT_CFG = "default.cfg"
    MOCK_SITE_DEFAULTS_CFG = "site-defaults.cfg"
    MOCK_LOGGING_INI = "logging.ini"

    def __init__(self, taskid=None):
        """Creates a new task if taskid is None,
        loads the task with given ID otherwise."""

        self._mock = False
        if taskid is None:
            # create a new task
            # create a retrace-group-writable directory
            oldmask = os.umask(0o007)
            self._taskid = None
            generator = random.SystemRandom()
            for i in range(50):
                taskid = generator.randint(pow(10, CONFIG["TaskIdLength"] - 1),
                                           pow(10, CONFIG["TaskIdLength"]) - 1)
                taskdir = os.path.join(CONFIG["SaveDir"], "%d" % taskid)
                try:
                    os.mkdir(taskdir)
                except OSError as ex:
                    # dir exists, try another taskid
                    if ex.errno == errno.EEXIST:
                        continue
                    # error - re-raise original exception
                    else:
                        raise ex
                # directory created
                else:
                    self._taskid = taskid
                    self._savedir = taskdir
                    break

            if self._taskid is None:
                raise Exception("Unable to create new task")

            pwdfilepath = os.path.join(self._savedir, RetraceTask.PASSWORD_FILE)
            with open(pwdfilepath, "w") as pwdfile:
                for i in range(CONFIG["TaskPassLength"]):
                    pwdfile.write(generator.choice(TASKPASS_ALPHABET))

            self.set_crash_cmd("crash")
            os.makedirs(os.path.join(self._savedir, RetraceTask.MISC_DIR))
            os.umask(oldmask)
        else:
            # existing task
            self._taskid = int(taskid)
            self._savedir = os.path.join(CONFIG["SaveDir"], "%d" % self._taskid)
            if not os.path.isdir(self._savedir):
                raise Exception("The task %d does not exist" % self._taskid)

    def set_mock(self, value):
        self._mock = value

    def get_mock(self):
        return self._mock

    def has_mock(self):
        """Verifies whether MOCK_SITE_DEFAULTS_CFG is present in the task directory."""
        return self.has(RetraceTask.MOCK_SITE_DEFAULTS_CFG)

    def _get_file_path(self, key):
        key_sanitized = key.replace("/", "_").replace(" ", "_")
        return os.path.join(self._savedir, key_sanitized)

    def _start_local(self, debug=False, kernelver=None, arch=None):
        cmdline = ["/usr/bin/retrace-server-worker", "%d" % self._taskid]
        if debug:
            cmdline.append("-v")

        if kernelver is not None:
            cmdline.append("--kernelver")
            cmdline.append(kernelver)

        if arch is not None:
            cmdline.append("--arch")
            cmdline.append(arch)

        return call(cmdline)

    def _start_remote(self, host, debug=False, kernelver=None, arch=None):
        starturl = "%s/%d/start" % (host, self._taskid)
        qs = {}
        if debug:
            qs["debug"] = ""

        if kernelver:
            qs["kernelver"] = kernelver

        if arch:
            qs["arch"] = arch

        qs_text = urllib.parse.urlencode(qs)

        if qs_text:
            starturl = "%s?%s" % (starturl, qs_text)

        url = urllib.request.urlopen(starturl)
        status = url.getcode()
        url.close()

        # 1/0 just to be consitent with call() in _start_local
        if status != 201:
            return 1

        return 0

    def get_taskid(self):
        """Returns task's ID"""
        return self._taskid

    def get_savedir(self):
        """Returns task's savedir"""
        return self._savedir

    def start(self, debug=False, kernelver=None, arch=None):
        crashdir = os.path.join(self._savedir, "crash")
        if arch is None:
            if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                filename = os.path.join(crashdir, "vmcore")
            else:
                filename = os.path.join(crashdir, "coredump")

            task_arch = guess_arch(filename)
        else:
            task_arch = arch

        ARCH_HOSTS = CONFIG.get_arch_hosts()
        if task_arch in ARCH_HOSTS:
            return self._start_remote(ARCH_HOSTS[task_arch], debug=debug,
                                      kernelver=kernelver, arch=arch)

        return self._start_local(debug=debug, kernelver=kernelver, arch=arch)

    def chgrp(self, key):
        gr = grp.getgrnam(CONFIG["AuthGroup"])
        try:
            os.chown(self._get_file_path(key), -1, gr.gr_gid)
        except:
            pass

    def chmod(self, key):
        try:
            os.chmod(self._get_file_path(key), stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IROTH)
        except:
            pass

    def set(self, key, value, mode="w"):
        if mode not in ["w", "a"]:
            raise ValueError("mode must be either 'w' or 'a'")

        with open(self._get_file_path(key), mode) as f:
            f.write(value)
            self.chgrp(key)
            self.chmod(key)

    def set_atomic(self, key, value, mode="w"):
        if mode not in ["w", "a", "wb"]:
            raise ValueError("mode must be 'w', 'a', or 'wb'")

        tmpfilename = self._get_file_path("%s.tmp" % key)
        filename = self._get_file_path(key)
        if mode == "a":
            try:
                shutil.copyfile(filename, tmpfilename)
            except IOError as ex:
                if ex.errno != errno.ENOENT:
                    raise

        with open(tmpfilename, mode) as f:
            f.write(value)

        os.rename(tmpfilename, filename)
        self.chgrp(key)
        self.chmod(key)

    # 256MB should be enough by default
    def get(self, key, maxlen=268435456):
        if not self.has(key):
            return None

        filename = self._get_file_path(key)
        with open(filename, "r") as f:
            result = f.read(maxlen)

        return result

    def has(self, key):
        return os.path.isfile(self._get_file_path(key))

    def touch(self, key):
        open(self._get_file_path(key), "a").close()

    def delete(self, key):
        if self.has(key):
            os.unlink(self._get_file_path(key))

    def get_password(self):
        """Returns task's password"""
        return self.get(RetraceTask.PASSWORD_FILE, maxlen=CONFIG["TaskPassLength"])

    def verify_password(self, password):
        """Verifies if the given password matches task's password."""
        return self.get_password() == password

    def is_running(self, readproc=False):
        """Returns whether the task is running. Reads /proc if readproc=True
        otherwise just reads the STATUS_FILE."""
        if readproc:
            for pid, taskid, ppid in get_running_tasks():
                if taskid == self._taskid:
                    return True

            return False
        else:
            return self.has_status() and self.get_status() not in [STATUS_SUCCESS, STATUS_FAIL]

    def get_age(self):
        """Returns the age of the task in hours."""
        return int(time.time() - os.path.getmtime(self._savedir)) // 3600

    def reset_age(self):
        """Reset the age of the task to the current time."""
        os.utime(self._savedir, None)

    def calculate_md5(self, file_name, chunk_size=65536):
        hash_md5 = hashlib.md5()
        with open(file_name, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def get_type(self):
        """Returns task type. If TYPE_FILE is missing,
        task is considered standard TASK_RETRACE."""
        result = self.get(RetraceTask.TYPE_FILE, maxlen=8)
        if result is None:
            return TASK_RETRACE

        return int(result)

    def set_type(self, newtype):
        """Atomically writes given type into TYPE_FILE."""
        if not newtype in TASK_TYPES:
            newtype = TASK_RETRACE

        self.set_atomic(RetraceTask.TYPE_FILE, str(newtype))

    def has_backtrace(self):
        """Verifies whether BACKTRACE_FILE is present in the task directory."""
        return self.has(RetraceTask.BACKTRACE_FILE)

    def get_backtrace(self):
        """Returns None if there is no BACKTRACE_FILE in the task directory,
        BACKTRACE_FILE's contents otherwise."""
        # max 16 MB
        return self.get(RetraceTask.BACKTRACE_FILE, maxlen=1 << 24)

    def set_backtrace(self, backtrace, mode="w"):
        """Atomically writes given string into BACKTRACE_FILE."""
        self.set_atomic(RetraceTask.BACKTRACE_FILE, backtrace, mode)

    def has_log(self):
        """Verifies whether LOG_FILE is present in the task directory."""
        return self.has(RetraceTask.LOG_FILE)

    def get_log(self):
        """Returns None if there is no LOG_FILE in the task directory,
        LOG_FILE's contents otherwise."""
        return self.get(RetraceTask.LOG_FILE, maxlen=1 << 22)

    def set_log(self, log, append=False):
        """Atomically writes or appends given string into LOG_FILE."""
        mode = "w"
        if append:
            mode = "a"

        self.set_atomic(RetraceTask.LOG_FILE, log, mode=mode)

    def has_status(self):
        """Verifies whether STATUS_FILE is present in the task directory."""
        return self.has(RetraceTask.STATUS_FILE)

    def get_status(self):
        """Returns None if there is no STATUS_FILE in the task directory,
        an integer status code otherwise."""
        result = self.get(RetraceTask.STATUS_FILE, maxlen=8)
        if result is None:
            return None

        return int(result)

    def set_status(self, statuscode):
        """Atomically writes given statuscode into STATUS_FILE."""
        self.set_atomic(RetraceTask.STATUS_FILE, "%d" % statuscode)

    def has_remote(self):
        """Verifies whether REMOTE_FILE is present in the task directory."""
        return self.has(RetraceTask.REMOTE_FILE)

    def add_remote(self, url):
        """Appends a remote resource to REMOTE_FILE."""
        if "\n" in url:
            url = url.split("\n")[0]

        self.set(RetraceTask.REMOTE_FILE, "%s\n" % url, mode="a")

    def get_remote(self):
        """Returns the list of remote resources."""
        result = self.get(RetraceTask.REMOTE_FILE, maxlen=1 << 22)
        if result is None:
            return []

        return result.splitlines()

    def has_kernelver(self):
        """Verifies whether KERNELVER_FILE is present in the task directory."""
        return self.has(RetraceTask.KERNELVER_FILE)

    def get_kernelver(self):
        """Returns None if there is no KERNELVER_FILE in the task directory,
        KERNELVER_FILE's contents otherwise."""
        return self.get(RetraceTask.KERNELVER_FILE, maxlen=1 << 16)

    def set_kernelver(self, value):
        """Atomically writes given value into KERNELVER_FILE."""
        self.set_atomic(RetraceTask.KERNELVER_FILE, str(value))
        # Only use mock if we're cross arch, and there's no arch-specific crash available
        # Set crash_cmd based on arch and any config setting
        hostarch = get_canon_arch(os.uname()[4])
        if value.arch == hostarch:
            self.set_crash_cmd("crash")
            self.set_mock(False)
        elif CONFIG["Crash%s" % value.arch] and os.path.isfile(CONFIG["Crash%s" % value.arch]):
            self.set_mock(False)
            self.set_crash_cmd(CONFIG["Crash%s" % value.arch])
        else:
            self.set_mock(True)
            self.set_crash_cmd("crash")

    def has_notes(self):
        return self.has(RetraceTask.NOTES_FILE)

    def get_notes(self):
        return self.get(RetraceTask.NOTES_FILE, maxlen=1 << 22)

    def set_notes(self, value):
        self.set_atomic(RetraceTask.NOTES_FILE, value)

    def has_notify(self):
        return self.has(RetraceTask.NOTIFY_FILE)

    def get_notify(self):
        result = self.get(RetraceTask.NOTIFY_FILE, maxlen=1 << 16)
        return [email for email in set(n.strip() for n in result.split("\n")) if email]

    def set_notify(self, values):
        if not isinstance(values, list) or not all([isinstance(v, string_types) for v in values]):
            raise Exception("values must be a list of strings")

        self.set_atomic(RetraceTask.NOTIFY_FILE,
                        "%s\n" % "\n".join(filter(None, set(v.strip().replace("\n", " ") for v in values))))

    def has_url(self):
        return self.has(RetraceTask.URL_FILE)

    def get_url(self):
        return self.get(RetraceTask.URL_FILE, maxlen=1 << 14)

    def set_url(self, value):
        self.set(RetraceTask.URL_FILE, value)

    def has_vmlinux(self):
        return self.has(RetraceTask.VMLINUX_FILE)

    def get_vmlinux(self):
        """Gets the contents of VMLINUX_FILE"""
        return self.get(RetraceTask.VMLINUX_FILE, maxlen=1 << 22)

    def set_vmlinux(self, value):
        self.set(RetraceTask.VMLINUX_FILE, value)

    def has_vmcore(self):
        vmcore_path = os.path.join(self._savedir, RetraceTask.VMCORE_FILE)
        return os.path.isfile(vmcore_path)

    def has_coredump(self):
        coredump_path = os.path.join(self._savedir, RetraceTask.COREDUMP_FILE)
        return os.path.isfile(coredump_path)

    def download_block(self, data):
        self._progress_write_func(data)
        self._progress_current += len(data)
        progress = "%d%% (%s / %s)" % ((100 * self._progress_current) // self._progress_total,
                                       human_readable_size(self._progress_current),
                                       self._progress_total_str)
        self.set_atomic(RetraceTask.PROGRESS_FILE, progress)

    def run_crash_cmdline(self, crash_start, crash_cmdline):
        cmd_output = None
        returncode = 0
        try:
            child = Popen(crash_start, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
            t = 3600
            if CONFIG["ProcessCommunicateTimeout"]:
                t = CONFIG["ProcessCommunicateTimeout"]
            cmd_output = child.communicate(crash_cmdline.encode(), timeout=t)[0]
        except OSError as err:
            log_warn("crash command: '%s' triggered OSError " %
                     crash_cmdline.replace('\r', '; ').replace('\n', '; '))
            log_warn("  %s" % err)
        except TimeoutExpired as err:
            child.kill()
            raise Exception("WARNING: crash command: '%s' exceeded " + str(t) +
                            " second timeout - damaged vmcore?" %
                            crash_cmdline.replace('\r', '; ').replace('\n', '; '))
        except:
            log_warn("crash command: '%s' triggered Unknown exception %s" %
                     crash_cmdline.replace('\r', '; ').replace('\n', '; '))
            log_warn("  %s" % sys.exc_info()[0])
        try:
            cmd_output.decode('utf-8')
        except UnicodeDecodeError as err:
            log_warn("crash command: '%s' triggered UnicodeDecodeError " %
                     crash_cmdline.replace('\r', '; ').replace('\n', '; '))
            log_warn("  %s" % err)

        if child.wait():
            log_warn("crash '%s' exitted with %d" % (crash_cmdline.replace('\r', '; ').replace('\n', '; '),
                     child.returncode))
            returncode = child.returncode

        return cmd_output, returncode

    def prepare_debuginfo(self, vmcore, chroot=None, kernelver=None):
        log_info("Calling prepare_debuginfo ")
        if kernelver is None:
            kernelver = get_kernel_release(vmcore)

        if kernelver is None:
            raise Exception("Unable to determine kernel version")

        self.set_kernelver(kernelver)
        # Setting kernelver may reset crash_cmd
        crash_cmd = self.get_crash_cmd().split()

        debugdir_base = os.path.join(CONFIG["RepoDir"], "kernel", kernelver.arch)
        if not os.path.isdir(debugdir_base):
            os.makedirs(debugdir_base)

        # First look in our cache for vmlinux at the "typical" location which is something like
        # CONFIG["RepoDir"]/kernel/x86_64/usr/lib/debug/lib/modules/2.6.32-504.el6.x86_64
        log_info("Version: '%s'; Release: '%s'; Arch: '%s'; _arch: '%s'; Flavour: '%s'; Realtime: %s"
                 % (kernelver.version, kernelver.release, kernelver.arch,
                    kernelver._arch, kernelver.flavour, kernelver.rt))
        kernel_path = ""
        if kernelver.version is not None:
            kernel_path = kernel_path + str(kernelver.version)
        if kernelver.release is not None:
            kernel_path = kernel_path + "-" + str(kernelver.release)
	# Skip the 'arch' on RHEL5 and RHEL4 due to different kernel-debuginfo path to vmlinux
        if kernelver._arch is not None and "EL" not in kernelver.release and "el5" not in kernelver.release:
            kernel_path = kernel_path + "." + str(kernelver._arch)
        if kernelver.flavour is not None:
            # 'debug' flavours on rhel6 and above require a '.' before the 'debug'
            if "EL" not in kernelver.release and "el5" not in kernelver.release:
                kernel_path = kernel_path + "."
            kernel_path = kernel_path + str(kernelver.flavour)

        vmlinux_cache_path = debugdir_base + "/usr/lib/debug/lib/modules/" + kernel_path + "/vmlinux"
        if os.path.isfile(vmlinux_cache_path):
            log_info("Found cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = vmlinux_cache_path
            self.set_vmlinux(vmlinux)
        else:
            log_info("Unable to find cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = None

        # For now, unconditionally search for kernel-debuginfo.  However, if the vmlinux
        # file existed in the cache, don't raise an exception on the task since the vmcore
        # may still be usable, and instead, return early.
        # A second optimization would be to avoid this completely if the modules files
        # all exist in the cache.
        log_info("Searching for kernel-debuginfo package for " + str(kernelver))
        debuginfo = find_kernel_debuginfo(kernelver)
        if not debuginfo:
            if vmlinux is not None:
                return vmlinux
            else:
                raise Exception("Unable to find debuginfo package and no cached vmlinux file")

        # FIXME: Merge kernel_path with this logic
        if "EL" in kernelver.release:
            if kernelver.flavour is None:
                pattern = "EL/vmlinux"
            else:
                pattern = "EL%s/vmlinux" % kernelver.flavour
        else:
            pattern = "/vmlinux"

        # Now open the kernel-debuginfo and get a listing of the files we may need
        vmlinux_path = None
        debugfiles = {}
        child = Popen(["rpm", "-qpl", debuginfo], stdout=PIPE, encoding='utf-8')
        lines = child.communicate()[0].splitlines()
        for line in lines:
            if line.endswith(pattern):
                vmlinux_path = line
                continue

            match = KO_DEBUG_PARSER.match(line)
            if not match:
                continue

            # only pick the correct flavour for el4
            if "EL" in kernelver.release:
                if kernelver.flavour is None:
                    pattern2 = "EL/"
                else:
                    pattern2 = "EL%s/" % kernelver.flavour

                if not pattern2 in os.path.dirname(line):
                    continue

            # '-' in file name is transformed to '_' in module name
            debugfiles[match.group(1).replace("-", "_")] = line

        # Only look for the vmlinux file here if it's not already been found above
        # Note the dependency from this code on the debuginfo file list
        if vmlinux is None:
            vmlinux_debuginfo = os.path.join(debugdir_base, vmlinux_path.lstrip("/"))
            cache_files_from_debuginfo(debuginfo, debugdir_base, [vmlinux_path])
            if os.path.isfile(vmlinux_debuginfo):
                log_info("Found cached vmlinux at new debuginfo location: " + vmlinux_debuginfo)
                vmlinux = vmlinux_debuginfo
                self.set_vmlinux(vmlinux)
            else:
                raise Exception("Failed vmlinux caching from debuginfo at location: " + vmlinux_debuginfo)

        # Obtain the list of modules this vmcore requires
        if chroot:
            with open(os.devnull, "w") as null:
                crash_normal = ["/usr/bin/mock", "--configdir", chroot, "shell",
                                "--", "crash -s %s %s" % (vmcore, vmlinux)]
        else:
            crash_normal = crash_cmd + ["-s", vmcore, vmlinux]
        stdout, returncode = self.run_crash_cmdline(crash_normal, "mod\nquit")
        if returncode == 1 and "el5" in kernelver.release:
            log_info("Unable to list modules but el5 detected, trying crash fixup for vmss files")
            crash_cmd.append("--machdep")
            crash_cmd.append("phys_base=0x200000")
            log_info("trying crash_cmd = " + str(crash_cmd))
            # FIXME: mock
            crash_normal = crash_cmd + ["-s", vmcore, vmlinux]
            stdout, returncode = self.run_crash_cmdline(crash_normal, "mod\nquit")

        # If we fail to get the list of modules, is the vmcore even usable?
        if returncode:
            log_warn("Unable to list modules: crash exited with %d:\n%s" % (returncode, stdout))
            return vmlinux

        modules = []
        for line in stdout.decode('utf-8').splitlines():
            # skip header
            if "NAME" in line:
                continue

            if " " in line:
                modules.append(line.split()[1])

        todo = []
        for module in modules:
            if module in debugfiles and \
               not os.path.isfile(os.path.join(debugdir_base, debugfiles[module].lstrip("/"))):
                todo.append(debugfiles[module])

        cache_files_from_debuginfo(debuginfo, debugdir_base, todo)

        return vmlinux

    def strip_vmcore(self, vmcore, kernelver=None):
        try:
            vmlinux = self.prepare_debuginfo(vmcore, chroot=None, kernelver=kernelver)
        except Exception as ex:
            log_warn("prepare_debuginfo failed: %s" % ex)
            return

        newvmcore = "%s.stripped" % vmcore
        retcode = call(["makedumpfile", "-c", "-d", "%d" % CONFIG["VmcoreDumpLevel"],
                        "-x", vmlinux, "--message-level", "0", vmcore, newvmcore])
        if retcode:
            log_warn("makedumpfile exited with %d" % retcode)
            if os.path.isfile(newvmcore):
                os.unlink(newvmcore)
        else:
            os.rename(newvmcore, vmcore)

    def download_remote(self, unpack=True, timeout=0, kernelver=None):
        """Downloads all remote resources and returns a list of errors."""
        md5sums = []
        downloaded = []
        errors = []

        crashdir = os.path.join(self._savedir, "crash")
        if not os.path.isdir(crashdir):
            oldmask = os.umask(0o007)
            os.makedirs(crashdir)
            os.umask(oldmask)

        for url in self.get_remote():
            self.set_status(STATUS_DOWNLOADING)
            log_info(STATUS[STATUS_DOWNLOADING])

            if url.startswith("FTP "):
                filename = url[4:].strip()
                log_info("Retrieving FTP file '%s'" % filename)

                ftp = None
                try:
                    ftp = ftp_init()
                    with open(os.path.join(crashdir, filename), "wb") as target_file:
                        self._progress_write_func = target_file.write
                        self._progress_total = ftp.size(filename)
                        self._progress_total_str = human_readable_size(self._progress_total)
                        self._progress_current = 0

                        # the files are expected to be huge (even hundreds of gigabytes)
                        # use a larger buffer - 16MB by default
                        ftp.retrbinary("RETR %s" % filename, self.download_block,
                                       CONFIG["FTPBufferSize"] * (1 << 20))

                    downloaded.append(filename)
                except Exception as ex:
                    errors.append((url, str(ex)))
                    continue
                finally:
                    if ftp:
                        ftp_close(ftp)
            elif url.startswith("/") or url.startswith("file:///"):
                if url.startswith("file://"):
                    url = url[7:]

                log_info("Retrieving local file '%s'" % url)

                if not os.path.isfile(url):
                    errors.append((url, "File not found"))
                    continue

                filename = os.path.basename(url)
                targetfile = os.path.join(crashdir, filename)

                copy = True
                if get_archive_type(url) == ARCHIVE_UNKNOWN:
                    try:
                        log_debug("Trying hardlink")
                        os.link(url, targetfile)
                        copy = False
                        log_debug("Succeeded")
                    except:
                        log_debug("Failed")

                if copy:
                    try:
                        log_debug("Copying")
                        shutil.copy(url, targetfile)
                    except Exception as ex:
                        errors.append((url, str(ex)))
                        continue

                downloaded.append(url)
            else:
                log_info("Retrieving remote file '%s'" % url)

                if "/" not in url:
                    errors.append((url, "malformed URL"))
                    continue

                child = Popen(["wget", "-nv", "-P", crashdir, url], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
                stdout = child.communicate()[0]
                if child.wait():
                    errors.append((url, "wget exitted with %d: %s" % (child.returncode, stdout)))
                    continue

                filename = url.rsplit("/", 1)[1]
                downloaded.append(url)

            if self.has_md5sum():
                self.set_status(STATUS_CALCULATING_MD5SUM)
                log_info(STATUS[STATUS_CALCULATING_MD5SUM])
                md5v = self.calculate_md5(os.path.join(crashdir, filename))
                md5sums.append("{0} {1}".format(md5v, downloaded[-1]))
                self.set_md5sum("\n".join(md5sums)+"\n")

            self.set_status(STATUS_POSTPROCESS)
            log_info(STATUS[STATUS_POSTPROCESS])

            if unpack:
                fullpath = os.path.join(crashdir, filename)
                if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                    try:
                        unpack_vmcore(fullpath)
                    except Exception as ex:
                        errors.append((fullpath, str(ex)))
                if self.get_type() in [TASK_RETRACE, TASK_RETRACE_INTERACTIVE]:
                    try:
                        unpack_coredump(fullpath)
                    except Exception as ex:
                        errors.append((fullpath, str(ex)))
                st = os.stat(crashdir)
                if (st.st_mode & stat.S_IRGRP) == 0 or (st.st_mode & stat.S_IXGRP) == 0:
                    try:
                        os.chmod(crashdir, st.st_mode | stat.S_IRGRP | stat.S_IXGRP)
                    except Exception as ex:
                        log_warn("Crashdir '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % crashdir)

        if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
            vmcore = os.path.join(crashdir, "vmcore")
            files = os.listdir(crashdir)
            for filename in files:
                fullpath = os.path.join(crashdir, filename)
                if os.path.isdir(fullpath):
                    move_dir_contents(fullpath, crashdir)

            files = os.listdir(crashdir)
            if len(files) < 1:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != "vmcore":
                    os.rename(os.path.join(crashdir, files[0]), vmcore)
            else:
                vmcores = []
                for filename in files:
                    if "vmcore" in filename:
                        vmcores.append(filename)

                # pick the largest file
                if len(vmcores) < 1:
                    absfiles = [os.path.join(crashdir, f) for f in files]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, vmcore)
                elif len(vmcores) > 1:
                    absfiles = [os.path.join(crashdir, f) for f in vmcores]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, vmcore)
                else:
                    for filename in files:
                        if filename == vmcores[0]:
                            if vmcores[0] != "vmcore":
                                os.rename(os.path.join(crashdir, filename), vmcore)

            files = os.listdir(crashdir)
            for filename in files:
                if filename == "vmcore":
                    continue

                os.unlink(os.path.join(crashdir, filename))

            if os.path.isfile(vmcore):
                oldsize = os.path.getsize(vmcore)
                log_info("Vmcore size: %s" % human_readable_size(oldsize))

                dump_level = get_vmcore_dump_level(self)
                if dump_level is None:
                    log_warn("Unable to determine vmcore dump level")
                else:
                    log_debug("Vmcore dump level is %d" % dump_level)

                skip_makedumpfile = CONFIG["VmcoreDumpLevel"] <= 0 or CONFIG["VmcoreDumpLevel"] >= 32
                if (dump_level is not None and
                        (dump_level & CONFIG["VmcoreDumpLevel"]) == CONFIG["VmcoreDumpLevel"]):
                    log_info("Stripping to %d would have no effect" % CONFIG["VmcoreDumpLevel"])
                    skip_makedumpfile = True

                if not skip_makedumpfile:
                    log_debug("Executing makedumpfile")
                    start = time.time()
                    self.strip_vmcore(vmcore, kernelver)
                    dur = int(time.time() - start)

                st = os.stat(vmcore)
                if (st.st_mode & stat.S_IRGRP) == 0:
                    try:
                        os.chmod(vmcore, st.st_mode | stat.S_IRGRP)
                    except Exception as ex:
                        log_warn("File '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % vmcore)
                if not skip_makedumpfile:
                    log_info("Stripped size: %s" % human_readable_size(st.st_size))
                    log_info("Makedumpfile took %d seconds and saved %s"
                             % (dur, human_readable_size(oldsize - st.st_size)))

        if self.get_type() in [TASK_RETRACE, TASK_RETRACE_INTERACTIVE]:
            coredump = os.path.join(crashdir, "coredump")
            files = os.listdir(crashdir)
            for filename in files:
                fullpath = os.path.join(crashdir, filename)
                if os.path.isdir(fullpath):
                    move_dir_contents(fullpath, crashdir)

            files = os.listdir(crashdir)
            if len(files) < 1:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != "coredump":
                    os.rename(os.path.join(crashdir, files[0]), coredump)
            else:
                coredumps = []
                for filename in files:
                    if "coredump" in filename:
                        coredumps.append(filename)

                # pick the largest file
                if len(coredumps) < 1:
                    absfiles = [os.path.join(crashdir, f) for f in files]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, coredump)
                elif len(coredumps) > 1:
                    absfiles = [os.path.join(crashdir, f) for f in coredumps]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, coredump)
                else:
                    for filename in files:
                        if filename == coredumps[0]:
                            if coredumps[0] != "coredump":
                                os.rename(os.path.join(crashdir, filename), coredump)

            files = os.listdir(crashdir)
            for filename in files:
                if filename in REQUIRED_FILES[self.get_type()]+["release", "os_release"]:
                    continue

                os.unlink(os.path.join(crashdir, filename))

            if os.path.isfile(coredump):
                oldsize = os.path.getsize(coredump)
                log_info("Coredump size: %s" % human_readable_size(oldsize))

                st = os.stat(coredump)
                if (st.st_mode & stat.S_IRGRP) == 0:
                    try:
                        os.chmod(coredump, st.st_mode | stat.S_IRGRP)
                    except Exception as ex:
                        log_warn("File '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % coredump)

        os.unlink(os.path.join(self._savedir, RetraceTask.REMOTE_FILE))
        self.set_downloaded(", ".join(downloaded))

        return errors

    def has_misc(self, name):
        """Verifies whether a file named 'name' is present in MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        miscpath = os.path.join(miscdir, name)

        return os.path.isdir(miscdir) and os.path.isfile(miscpath)

    def get_misc_list(self):
        """Lists all files in MISC_DIR."""
        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        if not os.path.isdir(miscdir):
            return []

        return os.listdir(miscdir)

    def get_misc(self, name, mode="rb"):
        """Gets content of a file named 'name' from MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not self.has_misc(name):
            raise Exception("There is no record with such name")

        miscpath = os.path.join(self._savedir, RetraceTask.MISC_DIR, name)
        with open(miscpath, mode) as misc_file:
            result = misc_file.read(1 << 24) # 16MB

        return result

    def add_misc(self, name, value, overwrite=False, mode="wb"):
        """Adds a file named 'name' into MISC_DIR and writes 'value' into it."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not overwrite and self.has_misc(name):
            raise Exception("The record already exists. Use overwrite=True " \
                             "to force overwrite existing records.")

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        if not os.path.isdir(miscdir):
            oldmask = os.umask(0o007)
            os.makedirs(miscdir)
            os.umask(oldmask)

        miscpath = os.path.join(miscdir, name)
        with open(miscpath, mode) as misc_file:
            misc_file.write(value)

    def del_misc(self, name):
        """Deletes the file named 'name' from MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if self.has_misc(name):
            os.unlink(os.path.join(self._savedir, RetraceTask.MISC_DIR, name))

    def get_managed(self):
        """Verifies whether the task is under task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception("Task management is disabled")

        return self.has(RetraceTask.MANAGED_FILE)

    def set_managed(self, managed):
        """Puts or removes the task from task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception("Task management is disabled")

        # create the file if it does not exist
        if managed and not self.has(RetraceTask.MANAGED_FILE):
            self.touch(RetraceTask.MANAGED_FILE)
        # unlink the file if it exists
        elif not managed and self.has(RetraceTask.MANAGED_FILE):
            self.delete(RetraceTask.MANAGED_FILE)

    def has_downloaded(self):
        """Verifies whether DOWNLOAD_FILE exists"""
        return self.has(RetraceTask.DOWNLOADED_FILE)

    def get_downloaded(self):
        """Gets contents of DOWNLOADED_FILE"""
        return self.get(RetraceTask.DOWNLOADED_FILE, maxlen=1 << 22)

    def set_downloaded(self, value):
        """Writes (not atomically) content to DOWNLOADED_FILE"""
        self.set(RetraceTask.DOWNLOADED_FILE, value)

    def has_md5sum(self):
        """Verifies whether MD5SUM_FILE exists"""
        return self.has(RetraceTask.MD5SUM_FILE)

    def get_md5sum(self):
        """Gets contents of MD5SUM_FILE"""
        return self.get(RetraceTask.MD5SUM_FILE, maxlen=1 << 22)

    def set_md5sum(self, value):
        """Writes (not atomically) content to MD5SUM_FILE"""
        self.set(RetraceTask.MD5SUM_FILE, value)

    def has_crashrc(self):
        """Verifies whether CRASHRC_FILE exists"""
        return self.has(RetraceTask.CRASHRC_FILE)

    def get_crashrc_path(self):
        """Gets the absolute path of CRASHRC_FILE"""
        return self._get_file_path(RetraceTask.CRASHRC_FILE)

    def get_crashrc(self):
        """Gets the contents of CRASHRC_FILE"""
        return self.get(RetraceTask.CRASHRC_FILE, maxlen=1 << 22)

    def set_crashrc(self, data):
        """Writes data to CRASHRC_FILE"""
        self.set(RetraceTask.CRASHRC_FILE, data)

    def get_crash_cmd(self):
        """Gets the contents of CRASH_CMD_FILE"""
        result = self.get(RetraceTask.CRASH_CMD_FILE, maxlen=1 << 22)
        if result is None:
            self.set_crash_cmd("crash")
            return "crash"
        return result

    def set_crash_cmd(self, data):
        """Writes data to CRASH_CMD_FILE"""
        self.set(RetraceTask.CRASH_CMD_FILE, data)
        try:
            os.chmod(self._get_file_path(RetraceTask.CRASH_CMD_FILE),
                     stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH)
        except:
            pass

    def has_started_time(self):
        """Verifies whether STARTED_FILE exists"""
        return self.has(RetraceTask.STARTED_FILE)

    def get_started_time(self):
        """Gets the unix timestamp from STARTED_FILE"""
        result = self.get(RetraceTask.STARTED_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return int(result)

    def set_started_time(self, value):
        """Writes the unix timestamp to STARTED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_start_time requires unix timestamp as parameter")

        self.set(RetraceTask.STARTED_FILE, "%d" % data)

    def has_caseno(self):
        """Verifies whether CASENO_FILE exists"""
        return self.has(RetraceTask.CASENO_FILE)

    def get_caseno(self):
        """Gets the case number from CASENO_FILE"""
        result = self.get(RetraceTask.CASENO_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return int(result)

    def set_caseno(self, value):
        """Writes case number into CASENO_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_caseno requires a number as parameter")

        self.set(RetraceTask.CASENO_FILE, "%d" % data)

    def has_bugzillano(self):
        """Verifies whether BUGZILLANO_FILE exists"""
        return self.has(RetraceTask.BUGZILLANO_FILE)

    def get_bugzillano(self):
        """Gets the bugzilla number from BUGZILLANO_FILE"""
        result = self.get(RetraceTask.BUGZILLANO_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return [bz_number for bz_number in set(n.strip() for n in result.split("\n")) if bz_number]

    def set_bugzillano(self, values):
        """Writes bugzilla numbers into BUGZILLANO_FILE"""
        if not isinstance(values, list) or not all([isinstance(v, str) for v in values]):
            raise Exception("values must be a list of integers")

        self.set_atomic(RetraceTask.BUGZILLANO_FILE,
                        "%s\n" % "\n".join(filter(None, set(v.strip().replace("\n", " ") for v in values))))

    def has_finished_time(self):
        """Verifies whether FINISHED_FILE exists"""
        return self.has(RetraceTask.FINISHED_FILE)

    def get_finished_time(self):
        """Gets the unix timestamp from FINISHED_FILE"""
        result = self.get(RetraceTask.FINISHED_FILE, 1 << 8)
        if result is None:
            return None

        return int(result)

    def set_finished_time(self, value):
        """Writes the unix timestamp to FINISHED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_finished_time requires unix timestamp as parameter")

        self.set(RetraceTask.FINISHED_FILE, "%d" % value)

    def get_default_started_time(self):
        """Get ctime of the task directory"""
        return int(os.path.getctime(self._savedir))

    def get_default_finished_time(self):
        """Get mtime of the task directory"""
        return int(os.path.getmtime(self._savedir))

    def clean(self):
        """Removes all files and directories others than
        results and logs from the task directory."""
        with open(os.devnull, "w") as null:
            if os.path.isfile(os.path.join(self._savedir, "default.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "site-defaults.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "logging.ini")):
                retcode = call(["/usr/bin/mock", "--configdir", self._savedir, "--scrub=all"],
                               stdout=null, stderr=null)

        for f in os.listdir(self._savedir):
            if not f in [RetraceTask.REMOTE_FILE, RetraceTask.CASENO_FILE,
                         RetraceTask.BACKTRACE_FILE, RetraceTask.DOWNLOADED_FILE,
                         RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
                         RetraceTask.MANAGED_FILE, RetraceTask.NOTES_FILE,
                         RetraceTask.NOTIFY_FILE, RetraceTask.PASSWORD_FILE,
                         RetraceTask.STARTED_FILE, RetraceTask.STATUS_FILE,
                         RetraceTask.TYPE_FILE, RetraceTask.MISC_DIR,
                         RetraceTask.CRASHRC_FILE, RetraceTask.CRASH_CMD_FILE,
                         RetraceTask.URL_FILE, RetraceTask.MOCK_LOG_DIR,
                         RetraceTask.VMLINUX_FILE, RetraceTask.BUGZILLANO_FILE]:

                path = os.path.join(self._savedir, f)
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                except:
                    # clean as much as possible
                    # ToDo advanced handling
                    pass

    def reset(self):
        """Remove all generated files and only keep the raw crash data"""
        for filename in [RetraceTask.BACKTRACE_FILE, RetraceTask.CRASHRC_FILE,
                         RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
                         RetraceTask.PROGRESS_FILE, RetraceTask.STARTED_FILE,
                         RetraceTask.STATUS_FILE, RetraceTask.MOCK_DEFAULT_CFG,
                         RetraceTask.MOCK_SITE_DEFAULTS_CFG, RetraceTask.MOCK_LOGGING_INI,
                         RetraceTask.CRASH_CMD_FILE, RetraceTask.MOCK_LOG_DIR,
                         RetraceTask.VMLINUX_FILE]:
            try:
                os.unlink(os.path.join(self._savedir, filename))
            except OSError as ex:
                # ignore 'No such file or directory'
                if ex.errno != errno.ENOENT:
                    raise

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        for filename in os.listdir(miscdir):
            os.unlink(os.path.join(miscdir, filename))

        kerneldir = os.path.join(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if os.path.isdir(kerneldir):
            shutil.rmtree(kerneldir)

    def remove(self):
        """Completely removes the task directory."""
        self.clean()
        kerneldir = os.path.join(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if os.path.isdir(kerneldir):
            shutil.rmtree(kerneldir)

        shutil.rmtree(self._savedir)

    def create_worker(self):
        """Get default worker instance for this task"""
        # TODO: let it be configurable
        from .retrace_worker import RetraceWorker
        return RetraceWorker(self)

### create ConfigClass instance on import ###
CONFIG = Config()
