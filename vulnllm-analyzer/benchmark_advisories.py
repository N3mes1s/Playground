"""
Benchmark: Test VulnLLM-R against 5 real GitHub Security Advisories.

Each snippet is KNOWN VULNERABLE code (pre-fix). We test whether
VulnLLM-R correctly identifies the vulnerability.
"""

import proxy_patch  # noqa: F401
import json
import time
import modal

ADVISORIES = [
    {
        "id": "GHSA-xxjr-mmjv-4gpg",
        "cve": "CVE-2025-13465",
        "package": "lodash",
        "language": "javascript",
        "vuln_type": "Prototype Pollution (CWE-1321)",
        "severity": "Moderate",
        "filename": "lodash.js",
        "code": r'''
/**
 * The base implementation of `_.unset`.
 *
 * @private
 * @param {Object} object The object to modify.
 * @param {Array|string} path The property path to unset.
 * @returns {boolean} Returns `true` if the property is deleted, else `false`.
 */
function baseUnset(object, path) {
    path = castPath(path, object);
    object = parent(object, path);
    return object == null || delete object[toKey(last(path))];
}

function castPath(value, object) {
    if (isArray(value)) {
        return value;
    }
    return isKey(value, object) ? [value] : stringToPath(toString(value));
}

function parent(object, path) {
    return path.length < 2 ? object : baseGet(object, baseSlice(path, 0, -1));
}

function baseGet(object, path) {
    path = castPath(path, object);
    var index = 0,
        length = path.length;
    while (object != null && index < length) {
        object = object[toKey(path[index++])];
    }
    return (index && index == length) ? object : undefined;
}

function toKey(value) {
    if (typeof value == 'string' || isSymbol(value)) {
        return value;
    }
    var result = (value + '');
    return (result == '0' && (1 / value) == -INFINITY) ? '-0' : result;
}
''',
    },
    {
        "id": "GHSA-gjx9-j8f8-7j74",
        "cve": "CVE-2026-25526",
        "package": "jinjava",
        "language": "java",
        "vuln_type": "Sandbox Bypass / Code Injection (CWE-94)",
        "severity": "Critical",
        "filename": "ForTag.java",
        "code": r'''
// From HubSpot/jinjava ForTag.java - renderForCollection method
// This code handles iterating over object properties in a for loop

private void renderForCollection(
    TagNode tagNode, JinjavaInterpreter interpreter,
    Object val, List<String> loopVars
) {
    for (String loopVar : loopVars) {
        try {
            PropertyDescriptor[] valProps = Introspector
                .getBeanInfo(val.getClass())
                .getPropertyDescriptors();
            for (PropertyDescriptor valProp : valProps) {
                if (loopVar.equals(valProp.getName())) {
                    interpreter
                        .getContext()
                        .put(loopVar, valProp.getReadMethod().invoke(val));
                    break;
                }
            }
        } catch (Exception e) {
            throw new InterpretException(
                e.getMessage(),
                e,
                tagNode.getLineNumber(),
                tagNode.getStartPosition()
            );
        }
    }
}
''',
    },
    {
        "id": "GHSA-58pv-8j8x-9vj2",
        "cve": "CVE-2026-23949",
        "package": "jaraco.context",
        "language": "python",
        "vuln_type": "Path Traversal / Zip Slip (CWE-22)",
        "severity": "High",
        "filename": "jaraco/context/__init__.py",
        "code": r'''
import contextlib
import os
import shutil
import tarfile
import urllib.request
from typing import Iterator


def strip_first_component(
    member: tarfile.TarInfo,
    path,
) -> tarfile.TarInfo:
    _, member.name = member.name.split('/', 1)
    return member


@contextlib.contextmanager
def tarball(
    url, target_dir: str | os.PathLike | None = None
) -> Iterator[str | os.PathLike]:
    """
    Get a URL to a tarball, download, extract, yield, then clean up.

    Assumes everything in the tarball is prefixed with a common
    directory. That common path is stripped and the contents
    are extracted to ``target_dir``, similar to passing
    ``-C {target} --strip-components 1`` to the ``tar`` command.
    """
    if target_dir is None:
        target_dir = os.path.basename(url).replace('.tar.gz', '').replace('.tgz', '')
    os.mkdir(target_dir)
    try:
        req = urllib.request.urlopen(url)
        with tarfile.open(fileobj=req, mode='r|*') as tf:
            tf.extractall(path=target_dir, filter=strip_first_component)
        yield target_dir
    finally:
        shutil.rmtree(target_dir)
''',
    },
    {
        "id": "GHSA-qmgc-5h2g-mvrw",
        "cve": "CVE-2026-22701",
        "package": "filelock",
        "language": "python",
        "vuln_type": "TOCTOU Race Condition / Symlink (CWE-367)",
        "severity": "Moderate",
        "filename": "src/filelock/_soft.py",
        "code": r'''
import os
import sys
from contextlib import suppress
from errno import EACCES, EEXIST
from pathlib import Path


class SoftFileLock(BaseFileLock):
    """Simply watches the existence of the lock file."""

    def _acquire(self) -> None:
        raise_on_not_writable_file(self.lock_file)
        ensure_directory_exists(self.lock_file)
        # first check for exists and read-only mode
        flags = (
            os.O_WRONLY       # open for writing only
            | os.O_CREAT
            | os.O_EXCL       # together with above raise EEXIST if the file exists
            | os.O_TRUNC      # truncate the file to zero byte
        )
        try:
            file_handler = os.open(self.lock_file, flags, self._context.mode)
        except OSError as exception:
            if not (
                exception.errno == EEXIST
                or (exception.errno == EACCES and sys.platform == "win32")
            ):
                raise
        else:
            self._context.lock_file_fd = file_handler

    def _release(self) -> None:
        assert self._context.lock_file_fd is not None
        os.close(self._context.lock_file_fd)
        self._context.lock_file_fd = None
        with suppress(OSError):
            Path(self.lock_file).unlink()
''',
    },
    {
        "id": "GHSA-87hc-h4r5-73f7",
        "cve": "CVE-2026-21860",
        "package": "werkzeug",
        "language": "python",
        "vuln_type": "Windows Device Name Bypass (CWE-67)",
        "severity": "Moderate",
        "filename": "src/werkzeug/security.py",
        "code": r'''
import os
import posixpath

_os_alt_seps: list[str] = list(
    sep for sep in [os.sep, os.path.altsep] if sep is not None and sep != "/"
)
_windows_device_files = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(10)),
    *(f"LPT{i}" for i in range(10)),
}


def safe_join(directory: str, *pathnames: str) -> str | None:
    """Safely join zero or more untrusted path components to a base
    directory to avoid escaping the base directory.

    :param directory: The trusted base directory.
    :param pathnames: The untrusted path components relative to the
        base directory.
    :return: A safe path, otherwise ``None``.
    """
    if not directory:
        directory = "."

    parts = [directory]

    for filename in pathnames:
        if filename != "":
            filename = posixpath.normpath(filename)

        if (
            any(sep in filename for sep in _os_alt_seps)
            or (
                os.name == "nt"
                and os.path.splitext(filename)[0].upper() in _windows_device_files
            )
            or os.path.isabs(filename)
            or filename.startswith("/")
            or filename == ".."
            or filename.startswith("../")
        ):
            return None

        parts.append(filename)

    return posixpath.join(*parts)
''',
    },
    # --- 5 NEW ADVISORIES ---
    {
        "id": "GHSA-wphj-fx3q-84ch",
        "package": "systeminformation",
        "language": "javascript",
        "vuln_type": "OS Command Injection (CWE-78)",
        "expected_cwe": "CWE-78",
        "filename": "lib/filesystem.js",
        "code": r'''
function fsSize(drive, callback) {
  if (util.isFunction(drive)) {
    callback = drive;
    drive = '';
  }

  return new Promise((resolve) => {
    process.nextTick(() => {
      let data = [];
      if (_linux || _freebsd || _openbsd || _netbsd || _darwin) {
        let cmd = '';
        if (_darwin) { cmd = 'df -kP'; }
        if (_linux) { cmd = 'export LC_ALL=C; df -lkPTx squashfs; unset LC_ALL'; }
        exec(cmd, { maxBuffer: 1024 * 1024 }, function (error, stdout) {
          let lines = filterLines(stdout);
          data = parseDf(lines);
          if (drive) {
            data = data.filter(item => {
              return item.fs.toLowerCase().indexOf(drive.toLowerCase()) >= 0
                || item.mount.toLowerCase().indexOf(drive.toLowerCase()) >= 0;
            });
          }
          if (callback) { callback(data); }
          resolve(data);
        });
      }
      if (_windows) {
        try {
          const cmd = `Get-WmiObject Win32_logicaldisk | select Access,Caption,FileSystem,FreeSpace,Size ${drive ? '| where -property Caption -eq ' + drive : ''} | fl`;
          util.powerShell(cmd).then((stdout, error) => {
            if (!error) {
              let devices = stdout.toString().split(/\n\s*\n/);
              devices.forEach(function (device) {
                let lines = device.split('\r\n');
                const size = util.toInt(util.getValue(lines, 'size', ':'));
                const free = util.toInt(util.getValue(lines, 'freespace', ':'));
                const caption = util.getValue(lines, 'caption', ':');
                if (size) {
                  data.push({ fs: caption, type: util.getValue(lines, 'filesystem', ':'),
                    size, used: size - free, available: free,
                    use: parseFloat(((100.0 * (size - free)) / size).toFixed(2)),
                    mount: caption });
                }
              });
            }
            if (callback) { callback(data); }
            resolve(data);
          });
        } catch (e) {
          if (callback) { callback(data); }
          resolve(data);
        }
      }
    });
  });
}
''',
    },
    {
        "id": "GHSA-vqfr-h8mv-ghfj",
        "package": "h11",
        "language": "python",
        "vuln_type": "HTTP Request Smuggling (CWE-444)",
        "expected_cwe": "CWE-444",
        "filename": "h11/_readers.py",
        "code": r'''
class ChunkedReader:
    def __init__(self):
        self._bytes_in_chunk = 0
        # After reading a chunk, we have to throw away the trailing \r\n;
        # if this is >0 then we discard that many bytes before resuming
        # regular de-chunkification.
        self._bytes_to_discard = 0
        self._reading_trailer = False

    def __call__(self, buf):
        if self._reading_trailer:
            lines = buf.maybe_extract_lines()
            if lines is None:
                return None
            return EndOfMessage(headers=list(_decode_header_lines(lines)))
        if self._bytes_to_discard > 0:
            data = buf.maybe_extract_at_most(self._bytes_to_discard)
            if data is None:
                return None
            self._bytes_to_discard -= len(data)
            if self._bytes_to_discard > 0:
                return None
            # else, fall through and read some more
        assert self._bytes_to_discard == 0
        if self._bytes_in_chunk == 0:
            # We need to refill our chunk count
            chunk_header = buf.maybe_extract_next_line()
            if chunk_header is None:
                return None
            matches = validate(
                chunk_header_re, chunk_header,
                "illegal chunk header: {!r}", chunk_header,
            )
            self._bytes_in_chunk = int(matches["chunk_size"], base=16)
            if self._bytes_in_chunk == 0:
                self._reading_trailer = True
                return self(buf)
            chunk_start = True
        else:
            chunk_start = False
        assert self._bytes_in_chunk > 0
        data = buf.maybe_extract_at_most(self._bytes_in_chunk)
        if data is None:
            return None
        self._bytes_in_chunk -= len(data)
        if self._bytes_in_chunk == 0:
            self._bytes_to_discard = 2
            chunk_end = True
        else:
            chunk_end = False
        return Data(data=data, chunk_start=chunk_start, chunk_end=chunk_end)
''',
    },
    {
        "id": "GHSA-jcrp-x7w3-ffmg",
        "package": "djl",
        "language": "java",
        "vuln_type": "Path Traversal / Zip Slip (CWE-22)",
        "expected_cwe": "CWE-22",
        "filename": "api/src/main/java/ai/djl/util/ZipUtils.java",
        "code": r'''
public static void unzip(InputStream is, Path dest) throws IOException {
    ZipInputStream zis = new ZipInputStream(new ValidationInputStream(is));
    ZipEntry entry;
    Set<String> set = new HashSet<>();
    while ((entry = zis.getNextEntry()) != null) {
        String name = removeLeadingFileSeparator(entry.getName());
        if (name.contains("..")) {
            throw new IOException("Malicious zip entry: " + name);
        }
        set.add(name);
        Path file = dest.resolve(name).toAbsolutePath();
        if (entry.isDirectory()) {
            Files.createDirectories(file);
        } else {
            Path parentFile = file.getParent();
            if (parentFile == null) {
                throw new AssertionError(
                    "Parent path should never be null: " + file);
            }
            Files.createDirectories(parentFile);
            Files.copy(zis, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}

static String removeLeadingFileSeparator(String name) {
    int index = 0;
    for (; index < name.length(); index++) {
        if (name.charAt(index) != File.separatorChar) {
            break;
        }
    }
    return name.substring(index);
}
''',
    },
    {
        "id": "GHSA-mw26-5g2v-hqw3",
        "package": "deepdiff",
        "language": "python",
        "vuln_type": "Class Pollution via getattr traversal (CWE-915)",
        "expected_cwe": "CWE-915",
        "filename": "deepdiff/path.py",
        "code": r'''
GET = "GET"
GETATTR = "GETATTR"

def _get_nested_obj(obj, elements, next_element=None):
    for (elem, action) in elements:
        if action == GET:
            obj = obj[elem]
        elif action == GETATTR:
            obj = getattr(obj, elem)
    return obj


def _get_nested_obj_and_force(obj, elements, next_element=None):
    prev_elem = None
    prev_action = None
    prev_obj = obj
    for index, (elem, action) in enumerate(elements):
        _prev_obj = obj
        if action == GET:
            try:
                obj = obj[elem]
                prev_obj = _prev_obj
            except KeyError:
                obj[elem] = _guess_type(elements, elem, index, next_element)
                obj = obj[elem]
                prev_obj = _prev_obj
            except IndexError:
                if isinstance(obj, list) and isinstance(elem, int) and elem >= len(obj):
                    obj.extend([None] * (elem - len(obj)))
                    obj.append(_guess_type(elements, elem, index, next_element))
                    obj = obj[-1]
                    prev_obj = _prev_obj
        elif action == GETATTR:
            obj = getattr(obj, elem)
            prev_obj = _prev_obj
        prev_elem = elem
        prev_action = action
    return obj
''',
    },
    {
        "id": "GHSA-5gfm-wpxj-wjgq",
        "package": "node-forge",
        "language": "javascript",
        "vuln_type": "ASN.1 Validation Bypass (CWE-436)",
        "expected_cwe": "CWE-436",
        "filename": "lib/asn1.js",
        "code": r'''
asn1.validate = function(obj, v, capture, errors) {
  var rval = false;

  // ensure tag class and type are the same if specified
  if((obj.tagClass === v.tagClass || typeof(v.tagClass) === 'undefined') &&
    (obj.type === v.type || typeof(v.type) === 'undefined')) {
    // ensure constructed flag is the same if specified
    if(obj.constructed === v.constructed ||
      typeof(v.constructed) === 'undefined') {
      rval = true;

      // handle sub values
      if(v.value && forge.util.isArray(v.value)) {
        var j = 0;
        for(var i = 0; rval && i < v.value.length; ++i) {
          rval = v.value[i].optional || false;
          if(obj.value[j]) {
            rval = asn1.validate(obj.value[j], v.value[i], capture, errors);
            if(rval) {
              ++j;
            } else if(v.value[i].optional) {
              rval = true;
            }
          }
          if(!rval && errors) {
            errors.push(
              '[' + v.name + '] ' +
              'Tag class "' + v.tagClass + '", type "' +
              v.type + '" expected value length "' +
              v.value.length + '", got "' +
              obj.value.length + '"');
          }
        }
      }

      if(rval && capture) {
        if(v.capture) {
          capture[v.capture] = obj.value;
        }
        if(v.captureAsn1) {
          capture[v.captureAsn1] = obj;
        }
      }
    }
  }
  return rval;
};
''',
    },
]


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--multipass", action="store_true", help="Use multi-pass analysis")
    parser.add_argument("--deep", action="store_true", help="Use deep analysis (per-CWE focused + self-critique + voting)")
    args = parser.parse_args()

    VulnLLMModel = modal.Cls.from_name("vulnllm-analyzer", "VulnLLMModel")
    model = VulnLLMModel()

    if args.deep:
        mode = "deep (per-CWE focused + critique + voting)"
    elif args.multipass:
        mode = "multi-pass"
    else:
        mode = "single-pass (CWE-aware)"
    results = []
    total = len(ADVISORIES)

    print(f"\n{'=' * 72}")
    print(f"  VulnLLM-R Benchmark: {total} Real GitHub Security Advisories")
    print(f"  Mode: {mode}")
    print(f"{'=' * 72}\n")

    for i, adv in enumerate(ADVISORIES):
        print(f"  [{i+1}/{total}] {adv['id']} ({adv['package']}, {adv['language']})")
        print(f"         Expected: {adv['vuln_type']}")
        start = time.time()

        if args.deep:
            result = model.analyze_deep.remote(
                code=adv["code"],
                language=adv["language"],
                filename=adv["filename"],
            )
        elif args.multipass:
            result = model.analyze_multipass.remote(
                code=adv["code"],
                language=adv["language"],
                filename=adv["filename"],
                num_passes=4,
            )
        else:
            result = model.analyze.remote(
                code=adv["code"],
                language=adv["language"],
                filename=adv["filename"],
            )
        elapsed = time.time() - start

        detected = result["verdict"] == "VULNERABLE"
        icon = "HIT" if detected else "MISS"
        detected_cwe = result.get("detected_cwe", "N/A")
        print(f"         Verdict:  {result['verdict']} [{icon}] (CWE: {detected_cwe}, {elapsed:.1f}s)")
        if "discovered_cwes" in result:
            print(f"         Discovery pass CWEs: {result['discovered_cwes']}")
        if "flagged_cwes" in result and result["flagged_cwes"]:
            print(f"         Flagged CWEs: {result['flagged_cwes']}")
        if "focused_cwes" in result:
            print(f"         Focused analysis on: {result['focused_cwes']}")
        print()

        results.append({
            **adv,
            "code": "(omitted)",
            "verdict": result["verdict"],
            "detected_cwe": detected_cwe,
            "detected": detected,
            "analysis": result["analysis"],
            "elapsed_seconds": round(elapsed, 1),
        })

    # Summary
    hits = sum(1 for r in results if r["detected"])
    print(f"\n{'=' * 72}")
    print(f"  Results: {hits}/{total} vulnerabilities detected")
    print(f"{'=' * 72}")
    print()
    print(f"  {'Advisory':<26} {'Package':<18} {'Expected CWE':<30} {'Verdict':<16}")
    print(f"  {'-'*26} {'-'*18} {'-'*30} {'-'*16}")
    for r in results:
        icon = "HIT" if r["detected"] else "MISS"
        print(f"  {r['id']:<26} {r['package']:<18} {r['vuln_type'][:30]:<30} {r['verdict']:<12} [{icon}]")

    print()
    for r in results:
        print(f"\n{'─' * 72}")
        print(f"  {r['id']} -- {r['package']} ({r['language']})")
        print(f"  Expected: {r['vuln_type']}")
        print(f"  Verdict:  {r['verdict']} ({'HIT' if r['detected'] else 'MISS'})")
        print(f"{'─' * 72}")
        lines = r["analysis"].strip().split("\n")
        for line in lines[:30]:
            print(f"  {line}")
        if len(lines) > 30:
            print(f"  ... ({len(lines) - 30} more lines)")
        print()

    # Save full report
    report_path = "/tmp/vulnllm-advisory-benchmark.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
