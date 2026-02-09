"""Scan Bottle framework security-sensitive code sections with VulnLLM-R deep analysis."""

import json
import time
import modal

# Extract security-critical sections from bottle.py

SECTIONS = [
    {
        "name": "cookie_decode + get_cookie (pickle deserialization)",
        "filename": "bottle.py:cookie_decode+get_cookie",
        "language": "python",
        "code": r'''
def _lscmp(a, b):
    """ Compares two strings in a cryptographically safe way:
        Runtime is not affected by length of common prefix. """
    return not sum(0 if x == y else 1
                   for x, y in zip(a, b)) and len(a) == len(b)


def cookie_encode(data, key, digestmod=None):
    """ Encode and sign a pickle-able object. Return a (byte) string """
    digestmod = digestmod or hashlib.sha256
    msg = base64.b64encode(pickle.dumps(data, -1))
    sig = base64.b64encode(hmac.new(tob(key), msg, digestmod=digestmod).digest())
    return b'!' + sig + b'?' + msg


def cookie_decode(data, key, digestmod=None):
    """ Verify and decode an encoded string. Return an object or None."""
    data = tob(data)
    if cookie_is_encoded(data):
        sig, msg = data.split(b'?', 1)
        digestmod = digestmod or hashlib.sha256
        hashed = hmac.new(tob(key), msg, digestmod=digestmod).digest()
        if _lscmp(sig[1:], base64.b64encode(hashed)):
            return pickle.loads(base64.b64decode(msg))
    return None


def cookie_is_encoded(data):
    """ Return True if the argument looks like a encoded cookie."""
    return bool(data.startswith(b'!') and b'?' in data)


class BaseRequest:
    def get_cookie(self, key, default=None, secret=None, digestmod=hashlib.sha256):
        """ Return the content of a cookie. To read a Signed Cookie, the
            secret must match the one used to create the cookie."""
        value = self.cookies.get(key)
        if secret:
            if value and value.startswith('!') and '?' in value:
                sig, msg = map(tob, value[1:].split('?', 1))
                hash = hmac.new(tob(secret), msg, digestmod=digestmod).digest()
                if _lscmp(sig, base64.b64encode(hash)):
                    dst = pickle.loads(base64.b64decode(msg))
                    if dst and dst[0] == key:
                        return dst[1]
            return default
        return value or default
''',
    },
    {
        "name": "static_file (path traversal + file serving)",
        "filename": "bottle.py:static_file",
        "language": "python",
        "code": r'''
def static_file(filename, root,
                mimetype=True,
                download=False,
                charset='UTF-8',
                etag=None,
                headers=None):
    """ Open a file in a safe way and return an instance of HTTPResponse
        that can be sent back to the client. """

    root = os.path.join(os.path.abspath(root), '')
    filename = os.path.abspath(os.path.join(root, filename.strip('/\\')))
    headers = headers.copy() if headers else {}

    if not filename.startswith(root):
        return HTTPError(403, "Access denied.")
    if not os.path.isfile(filename):
        return HTTPError(404, "File does not exist.")
    if not os.access(filename, os.R_OK):
        return HTTPError(403, "You do not have permission to access this file.")

    if mimetype is True:
        name = download if isinstance(download, str) else filename
        mimetype, encoding = mimetypes.guess_type(name)
        if encoding == 'gzip':
            mimetype = 'application/gzip'
        elif encoding:
            mimetype = 'application/x-' + encoding

    if charset and mimetype and 'charset=' not in mimetype \
       and (mimetype[:5] == 'text/' or mimetype == 'application/javascript'):
        mimetype += '; charset=%s' % charset

    if mimetype:
        headers['Content-Type'] = mimetype

    if download is True:
        download = os.path.basename(filename)

    if download:
        download = download.replace('"', '')
        headers['Content-Disposition'] = 'attachment; filename="%s"' % download

    stats = os.stat(filename)
    headers['Content-Length'] = clen = stats.st_size
    headers['Last-Modified'] = email.utils.formatdate(stats.st_mtime, usegmt=True)
    headers['Date'] = email.utils.formatdate(time.time(), usegmt=True)

    if etag is None:
        etag = '%d:%d:%d:%d:%s' % (stats.st_dev, stats.st_ino, stats.st_mtime,
                                   clen, filename)
        etag = hashlib.sha1(tob(etag)).hexdigest()

    if etag:
        headers['ETag'] = etag
        check = request.environ.get('HTTP_IF_NONE_MATCH')
        if check and check == etag:
            return HTTPResponse(status=304, **headers)

    body = '' if request.method == 'HEAD' else open(filename, 'rb')

    headers["Accept-Ranges"] = "bytes"
    range_header = request.environ.get('HTTP_RANGE')
    if range_header:
        ranges = list(parse_range_header(range_header, clen))
        if not ranges:
            return HTTPError(416, "Requested Range Not Satisfiable")
        offset, end = ranges[0]
        rlen = end - offset
        headers["Content-Range"] = "bytes %d-%d/%d" % (offset, end - 1, clen)
        headers["Content-Length"] = str(rlen)
        if body: body = _closeiter(_rangeiter(body, offset, rlen), body.close)
        return HTTPResponse(body, status=206, **headers)
    return HTTPResponse(body, **headers)
''',
    },
    {
        "name": "SimpleTemplate (server-side template exec)",
        "filename": "bottle.py:SimpleTemplate",
        "language": "python",
        "code": r'''
class SimpleTemplate(BaseTemplate):
    def prepare(self,
                escape_func=html_escape,
                noescape=False,
                syntax=None, **ka):
        self.cache = {}
        enc = self.encoding
        self._str = lambda x: touni(x, enc)
        self._escape = lambda x: escape_func(touni(x, enc))
        self.syntax = syntax
        if noescape:
            self._str, self._escape = self._escape, self._str

    @cached_property
    def co(self):
        return compile(self.code, self.filename or '<string>', 'exec')

    @cached_property
    def code(self):
        source = self.source
        if not source:
            with open(self.filename, 'rb') as f:
                source = f.read()
        try:
            source, encoding = touni(source), 'utf8'
        except UnicodeError:
            raise depr(0, 11, 'Unsupported template encodings.', 'Use utf-8 for templates.')
        parser = StplParser(source, encoding=encoding, syntax=self.syntax)
        code = parser.translate()
        self.encoding = parser.encoding
        return code

    def _include(self, _env, _name=None, **kwargs):
        env = _env.copy()
        env.update(kwargs)
        if _name not in self.cache:
            self.cache[_name] = self.__class__(name=_name, lookup=self.lookup, syntax=self.syntax)
        return self.cache[_name].execute(env['_stdout'], env)

    def execute(self, _stdout, kwargs):
        env = self.defaults.copy()
        env.update(kwargs)
        env.update({
            '_stdout': _stdout,
            '_printlist': _stdout.extend,
            'include': functools.partial(self._include, env),
            'rebase': functools.partial(self._rebase, env),
            '_rebase': None,
            '_str': self._str,
            '_escape': self._escape,
            'get': env.get,
            'setdefault': env.setdefault,
            'defined': env.__contains__
        })
        exec(self.co, env)
        if env.get('_rebase'):
            subtpl, rargs = env.pop('_rebase')
            rargs['base'] = ''.join(_stdout)
            del _stdout[:]
            return self._include(env, subtpl, **rargs)
        return env

    def render(self, *args, **kwargs):
        """ Render the template using keyword arguments as local variables. """
        env = {}
        stdout = []
        for dictarg in args:
            env.update(dictarg)
        env.update(kwargs)
        self.execute(stdout, env)
        return ''.join(stdout)
''',
    },
    {
        "name": "redirect + set_cookie (header injection)",
        "filename": "bottle.py:redirect+set_cookie",
        "language": "python",
        "code": r'''
def redirect(url, code=None):
    """ Aborts execution and causes a 303 or 302 redirect, depending on
        the HTTP protocol version. """
    if not code:
        code = 303 if request.get('SERVER_PROTOCOL') == "HTTP/1.1" else 302
    res = response.copy(cls=HTTPResponse)
    res.status = code
    res.body = ""
    res.set_header('Location', urljoin(request.url, url))
    raise res


class BaseResponse:
    def set_cookie(self, name, value, secret=None, digestmod=hashlib.sha256, **options):
        """ Create a new cookie or replace an old one. If the `secret` parameter is
            set, create a `Signed Cookie` (described below). """
        if not self._cookies:
            self._cookies = SimpleCookie()

        # Signed cookies are base64 encoded pickled data
        if secret:
            if not isinstance(value, str): depr(0, 13, "Non-string cookies are deprecated.",
                "Pass strings to set_cookie() or use the secret parameter.")
            encoded = base64.b64encode(pickle.dumps([name, value], -1))
            sig = base64.b64encode(hmac.new(tob(secret), encoded,
                                            digestmod=digestmod).digest())
            value = touni(b'!' + sig + b'?' + encoded)

        elif not isinstance(value, str):
            raise TypeError("Cookie value must be a string when no secret is set.")

        if len(value) > 4096:
            raise ValueError("Cookie value to long.")

        self._cookies[name] = value

        if not options.get('expires'):
            options['expires'] = ''

        for key, val in options.items():
            if key in ('secure', 'httponly') and not val:
                continue
            if key == 'max_age':
                if isinstance(val, timedelta):
                    val = int(val.total_seconds())
                if isinstance(val, int) and val < 0:
                    val = 0
            self._cookies[name][key.lower()] = val
''',
    },
    {
        "name": "_parse_qsl + _parse_http_header (input parsing)",
        "filename": "bottle.py:_parse_qsl+_parse_http_header",
        "language": "python",
        "code": r'''
def _parse_http_header(h):
    """ Parses a typical multi-valued and parametrised HTTP header (e.g. Accept headers)
        and returns a list of (value, params) tuples. """
    values = []
    if '"' not in h:
        # Performance shortcut for simple headers
        for value in h.split(','):
            parts = value.split(';')
            values.append((parts[0].strip(), {}))
            for part in parts[1:]:
                nv = part.split('=', 1)
                if len(nv) == 2:
                    values[-1][1][nv[0].strip()] = nv[1].strip()
    else:
        lq = 0
        for token in h.split(','):
            if token.count('"') - token.count('\\"') + lq & 1:
                lq = 1 - lq
                if lq:
                    values.append(token)
                else:
                    values[-1] += ',' + token
                continue
            if lq:
                values[-1] += ',' + token
            else:
                values.append(token)
        values = [v.split(';') for v in values]
        result = []
        for parts in values:
            value = parts[0].strip()
            params = {}
            for part in parts[1:]:
                nv = part.split('=', 1)
                if len(nv) == 2:
                    params[nv[0].strip()] = nv[1].strip()
            result.append((value, params))
        values = result
    return values


def _parse_qsl(qs, encoding="utf8"):
    r = []
    for pair in qs.replace('&', ';').split(';'):
        if not pair: continue
        nv = pair.split('=', 1)
        if len(nv) != 2: nv.append('')
        key = urlunquote(nv[0].replace('+', ' '), encoding)
        value = urlunquote(nv[1].replace('+', ' '), encoding)
        r.append((key, value))
    return r


def html_escape(string):
    """ Escape HTML special characters ``&<>`` and quotes ``'"``. """
    return string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')\
                 .replace('"', '&quot;').replace("'", '&#039;')
''',
    },
]

def main():
    VulnLLMModel = modal.Cls.from_name("vulnllm-analyzer", "VulnLLMModel")
    model = VulnLLMModel()

    print(f"\n{'=' * 72}")
    print(f"  Scanning Bottle Framework (bottle.py) - Deep Analysis")
    print(f"  Target: https://github.com/bottlepy/bottle")
    print(f"  Sections: {len(SECTIONS)}")
    print(f"{'=' * 72}\n")

    all_results = []
    for i, section in enumerate(SECTIONS):
        print(f"  [{i+1}/{len(SECTIONS)}] {section['name']}")
        start = time.time()

        result = model.analyze_deep.remote(
            code=section["code"],
            language=section["language"],
            filename=section["filename"],
        )

        elapsed = time.time() - start
        verdict = result["verdict"]
        cwe = result.get("detected_cwe", "N/A")
        flagged = result.get("flagged_cwes", {})

        icon = "VULN" if verdict == "VULNERABLE" else "CLEAN"
        print(f"         [{icon}] {verdict} (primary: {cwe}, {elapsed:.1f}s)")
        if flagged:
            print(f"         Flagged: {flagged}")
        print()

        all_results.append({
            "section": section["name"],
            "filename": section["filename"],
            "verdict": verdict,
            "detected_cwe": cwe,
            "flagged_cwes": flagged,
            "focused_cwes": result.get("focused_cwes", []),
            "analysis": result.get("analysis", ""),
            "elapsed": round(elapsed, 1),
        })

    # Summary
    vulns = [r for r in all_results if r["verdict"] == "VULNERABLE"]
    print(f"\n{'=' * 72}")
    print(f"  Summary: {len(vulns)}/{len(SECTIONS)} sections flagged")
    print(f"{'=' * 72}\n")

    for r in all_results:
        print(f"  {'[VULN]' if r['verdict'] == 'VULNERABLE' else '[CLEAN]':8s} {r['section']}")
        if r["flagged_cwes"]:
            for cwe_id, source in r["flagged_cwes"].items():
                print(f"           - {cwe_id} (via {source})")
    print()

    # Detailed analysis for flagged sections
    for r in vulns:
        print(f"\n{'─' * 72}")
        print(f"  {r['section']}")
        print(f"  Flagged CWEs: {list(r['flagged_cwes'].keys())}")
        print(f"{'─' * 72}")
        lines = r["analysis"].strip().split("\n")
        for line in lines[:40]:
            print(f"  {line}")
        if len(lines) > 40:
            print(f"  ... ({len(lines) - 40} more lines)")
        print()

    # Save report
    report_path = "/tmp/bottle-scan-report.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"  Full report saved to: {report_path}")


if __name__ == "__main__":
    main()
