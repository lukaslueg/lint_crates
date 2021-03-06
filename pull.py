''' A linter for packages on crates.io

git clone https://github.com/rust-lang/crates.io-index
python3 -c "import pull; pull.sync_db_to_index_dir()"
python3 -c "import pull; pull.report_warnings()" >! report.txt
python3 -c "import pull; pull.report_counts()" < report.txt \
    | discount-makepage >! report.html

'''

import collections
import functools
import gzip
import io
import itertools
import json
import multiprocessing.pool
import os
import pathlib
import re
import sqlite3
import stat
import sys
import tarfile
import unittest
import urllib.request


Pattern = collections.namedtuple('Pattern', ('part', 'matches', 'caption',
                                 'description'))


class Crate(object):
    def __init__(self, id, crate, num, body):
        self.id = id
        self.crate = crate
        self.num = num
        self._body = body

    @property
    def body(self):
        return tarfile.open(fileobj=io.BytesIO(self._body), mode='r|gz',
                            debug=3)


class Warning(object):
    __slots__ = ('crate_name', 'num', 'info', 'member_name')

    def __init__(self, crate_name, num, info=None, member_name=None):
        self.crate_name = crate_name
        self.num = num
        self.info = info
        self.member_name = member_name

    @property
    def reason(self):
        return self.__class__.__name__

    @property
    def member_pure_name(self):
        if self.member_name is not None:
            return os.path.sep.join(pathlib.Path(self.member_name).parts[1:])

    def __str__(self):
        s = self.reason
        if self.member_name is not None:
            s += ' [%s]' % (self.member_name, )
        if self.info is not None:
            s += ' [%s]' % (self.info, )
        return s


class TarError(Warning):
    pass


class NotAFile(Warning):
    pass


class HugeFile(Warning):
    LIMIT = 50*1024**2


class OwnerSet(Warning):
    pass


class Executable(Warning):
    pass


class PathEscape(Warning):
    pass


class AbsolutePath(Warning):
    pass


class CargoConfig(Warning):
    pass


class AWSToken(Warning):
    CLIENT_ID_PATTERN = re.compile('AKIA[0-9A-Z]{16}')


class PrivateKey(Warning):
    PGP_PATTERN = re.compile('-----BEGIN (RSA )?PRIVATE KEY-----')


class CargoToken(Warning):
    pass


class Trash(Warning):
    pass


class HiddenPath(Warning):
    pass


class HiddenFile(Warning):
    pass


class LocalBuildFiles(Warning):
    pass


class SensitiveFile(Warning):
    pass


TRASH_FILENAMES = frozenset(
    ('.DS_Store', '.timestamp', '.lock', '.dirstamp', '.keep', '.version',
     '.HEADER', '.mailmap', '.name'))
LOCAL_BUILD_FILENAMES = frozenset(
    ('.gitignore', '.gitattributes', '.gitted', '.travis.yaml', '.frigg.yml',
     '.frigg.yaml', '.travis.yml', '.gitmodules', '.clog.toml',
     '.bumpversion.cfg', '.coveralls.yml', '.dirstamp', '.travis.sh',
     '.clang-format', '.arcconfig', '.gitconfig', '.gitlab-ci.yml', '.hgtags',
     '.drone.yml', '.kateproject', '.tags', '.editorconfig', '.classpath',
     '.tags1', '.appveyor.yml', '.gitkeep', '.rspec', '.project', '.vimrc',
     '.gdbinit', '.atom-build.json', '.eslintrc', '.npmignore', '.gitauthors',
     '.jshintrc', '.gitattribute', '.projectile', '.travis_after.sh',
     '.travis-update-gh-pages.sh', '.gdb_history', '.sigar_shellrc',
     '.valgrind.supp', '.dockerignore', '.emacs.bmk', '.hgignore',
     '.travis-bench', '.zuul.yml', '.npmrc', '.eslintignore', '.dntrc',
     '.jsbeautifyrc', '.sconsign.dblite', '.jscs.json', '.astylerc',
     '.build.sh', '.buildpack', '.cvsignore', '.bzrignore', '.coveragerc'))
LOCAL_BUILD_DIRS = frozenset(
    ('.git', '.gitreview', '.hg', '.snakemake', '.gitted', '.travis', '.deps',
     '.libs', '.cargo' '.sconf_temp', '.ci', '.fingerprint', '.idea',
     '.settings', '.sconf_temp'))
LOCAL_BUILD_EXTS = frozenset(
    ('.swp', '.swo', '.swn', '.kate-swp', '.swl', '.un~', '.tmp'))


def _false_positive_filters():
    '''Generate an iterable of callables that match a warning against a list
    of known false positives'''

    def _filter(reason, crate_re, member_re, warning):
        return ((reason is None
                 or isinstance(warning, reason))
                and (crate_re is None or crate_re.match(warning.crate_name))
                and (member_re is None
                     or (warning.member_name
                         and member_re.match(warning.member_name))))

    for reason, desc in (
            (SensitiveFile,
             (('openssl', '.*/test/.*'),
              ('tiny-http', '.*/examples/.*'),
              ('curl-sys', '.*/tests/.*'),
              ('pcap', '.*/tests/.*'),
              ('gpgme', '.*/tests/.*'),
              ('xyio', '.*/(examples/.*|password_callback.hpp)'))),
            (PrivateKey,
             (('openssl', '.*/test/.*'),
              ('libssh', '.*/(example.rs|src/ssh_key.rs)'),
              ('libressl-pnacl-sys', '.*/(tests|man)/.*'),
              ('xyio', '.*/src/examples/.*'),
              ('nanny-sys', '.*/http_signing.md'),
              ('libssh2-sys', r'.*/(tests/.*|wincng\.c|libgcrypt\.c)'),
              ('curl-sys', '.*/(tests|docs)/.*'),
              ('tiny_http', '.*/examples/.*'),
              ('security-framework', '.*/test/.*'),
              ('pem-parser', '.*/test_data/.*'),
              ('civet-sys', '.*/(resources/ss_cert.pem|civetweb/.*)'),
              ('cql_bindgen', '.*/cert.key'))),
            (CargoToken,
             (('cargo', '.*/tests/.*'),
              ('cargo', '.*/src/doc/config.md'))),
            (AWSToken,
             (('unicode_names', '.*/src/generated.rs'),
              ('rusoto', '.*/tests/unit/.*')))):
        for crate_pat, member_pat in desc:
            crate_re = re.compile(crate_pat) if crate_pat else None
            member_re = re.compile(member_pat) if member_pat else None
            yield functools.partial(_filter, reason, crate_re, member_re)


def _filter_false_positives(f):
    '''Used to decorate the _check_crate function to filter out known false
    positives'''
    filters = tuple(_false_positive_filters())

    @functools.wraps(f)
    def _filtered_check_crate(crate):
        for warning in f(crate):
            if any(f(warning) for f in filters):
                continue
            yield warning

    return _filtered_check_crate


def _check_pattern(pattern, other):
    return other.find(pattern) >= 0


def _check_re(expr, other):
    return expr.match(other) is not None


def _make_matcher(pattern):
    '''Creates a callable based on a json-derived pattern object that matches a
    string given as the only argument.'''
    if pattern['type'] == 'match':
        return functools.partial(_check_pattern, pattern['pattern'])
    elif pattern['type'] == 'regex':
        return functools.partial(_check_re, re.compile(pattern['pattern']))
    else:
        raise ValueError


def _make_sentinel(matches, sentinels):
    '''Wraps a matcher-fn to exclude false-positives based on the
    json-derived sentinels.'''
    sens_funcs = [functools.partial(_check_re, re.compile(s)) for s in
                  sentinels]

    def _f(o):
        return matches(o) and not any(s(o) for s in sens_funcs)
    return _f


def _load_patterns():
    '''Load the patterns from `git-deny-patterns.json` and build a list of
    useable objects'''
    with open('git-deny-patterns.json') as f:
        deny_pattern_json = f.read()
    for pattern in json.loads(deny_pattern_json):
        matches = _make_matcher(pattern)
        try:
            sentinels = pattern['sentinels']
        except KeyError:
            pass
        else:
            matches = _make_sentinel(matches, sentinels)
        yield Pattern(pattern['part'], matches, pattern['caption'],
                      pattern['description'])


DENY_PATTERNS = tuple(_load_patterns())


def _get_db_connection():
    con = sqlite3.connect('crates.dump', isolation_level=None)
    # I don't care about normalization, muaahahahaha
    sql = '''CREATE TABLE IF NOT EXISTS crates
                (id INT PRIMARY KEY, crate TEXT, num TEXT, body BLOB)
          '''
    con.execute(sql)
    sql = '''CREATE INDEX IF NOT EXISTS crates_idx
                ON crates (crate, num)
          '''
    con.execute(sql)
    return con


def _fetch_json(url):
    '''Make a call to crates.io and return a decoded json-object'''
    with urllib.request.urlopen('https://crates.io' + url) as stream:
        body = stream.read()
    body = json.loads(body.decode('utf-8'))
    try:
        err = body['errors']
    except KeyError:
        return body
    else:
        raise RuntimeError(err[0]['detail'])


def _download_version(version):
    '''Fetch the compressed tarball of a given crate's version'''
    # TODO signature checking anyone?
    url = 'https://crates.io' + version['dl_path']
    with urllib.request.urlopen(url) as stream:
        return stream.read()


def _known_ids(con):
    '''Get an iterator over all version IDs currently in the db.'''
    sql = '''SELECT id
             FROM crates
             ORDER BY crate, num
          '''
    return (r[0] for r in con.execute(sql).fetchall())


def _fetch_and_insert_crate(cursor, version):
    sql = '''INSERT INTO crates (id, crate, num, body)
                VALUES (?, ?, ?, ?)
            '''
    cursor.execute(sql, (version['id'], version['crate'], version['num'],
                         _download_version(version)))


def dump_crate_to_file(id_or_name, num=None):
    '''Get the given crate from the db and write it to disk for further
    inspection'''
    con = _get_db_connection()
    try:
        id = int(id_or_name)
    except ValueError:
        sql = '''SELECT body
                 FROM crates
                 WHERE crate = ?
                 AND num = ?
              '''
        buf, = con.execute(sql, (id_or_name, num)).fetchone()
        crate = id_or_name
    else:
        sql = '''SELECT crate, num, body
                 FROM crates
                 WHERE id = ?
              '''
        buf, num, body = con.execute(sql, (id, )).fetchone()
    with open('%s-%s.tar.gz' % (crate, num), 'wb') as f:
        f.write(buf)


def _fetch_many(cursor, arraysize=None):
    '''Scroll through a cursor's results'''
    if arraysize is None:
        arraysize = cursor.arraysize
    while True:
        results = cursor.fetchmany(arraysize)
        if not results:
            break
        yield from results


def _iter_index_dir(index):
    '''Iterate over all files describing crates in the index'''
    return itertools.chain((index / '1').iterdir(), (index / '2').iterdir(),
                           (index / '3').glob('?/*'), index.glob('??/??/*'))


def _iter_index_dir_crates(index):
    '''Iterate over all crate-names and -versions in the index'''
    for filename in _iter_index_dir(index):
        with filename.open() as f:
            for line in f:
                prop = json.loads(line)
                # TODO checksums anyone?
                yield prop['name'], prop['vers']


def sync_db_to_index_dir(index=pathlib.Path('./crates.io-index')):
    '''Fetch and put crates into the db that the index knows about'''

    assert False, '''Please don't do this. Pulling everything this way from
crates.io places quite an unusual burden on it's S3-account. Contact me on
github to get a dump (~2.6gb) torrented.'''

    con = _get_db_connection()
    cursor = con.cursor()
    sql = '''CREATE TEMP TABLE _known_crates
                (crate TEXT, num TEXT)
            '''
    cursor.execute(sql)
    sql = '''INSERT INTO _known_crates VALUES (?, ?)'''
    cursor.executemany(sql, _iter_index_dir_crates(index))
    sql = '''SELECT crate, num
             FROM _known_crates
             WHERE NOT EXISTS (SELECT 1
                               FROM crates
                               WHERE crates.crate = _known_crates.crate
                               AND crates.num = _known_crates.num)
            '''
    cursor.execute(sql)
    insert_cursor = con.cursor()
    for crate, num in _fetch_many(cursor):
        print((crate, num))
        version = _fetch_json('/api/v1/crates/%s/%s' % (crate, num))['version']
        try:
            _fetch_and_insert_crate(insert_cursor, version)
        except urllib.error.HTTPError as e:
            print(e)


def _iter_crates_from_db(buffersize=10):
    '''Iterate over all crates currently in the db.'''
    cursor = _get_db_connection().cursor()
    sql = '''SELECT id, crate, num, body
             FROM crates
          '''
    cursor.execute(sql)
    return (Crate(*row) for row in _fetch_many(cursor, buffersize))


def _unpacked_size():
    '''Uncompressed size of all crates in the db.'''
    i = 0
    for crate in _iter_crates_from_db():
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(crate._body)) as f:
                i += len(f.read())
        except EOFError:
            print(crate.crate)
    print(i)


@_filter_false_positives
def _check_crate(crate):
    '''Check a given crate and iterate over all warnings related to it'''
    tar = crate.body
    while True:
        try:
            member = tar.next()
        except tarfile.StreamError as e:
            yield TarError(crate.crate, crate.num, str(e))
            break
        if member is None:
            break
        tar.members = []

        def warn(klass, info=None):
            return klass(crate.crate, crate.num, info, member.name)

        if not member.isfile():
            yield warn(NotAFile)
            continue

        if member.size >= HugeFile.LIMIT:
            yield warn(HugeFile, member.size)

        if any((member.uid, member.gid, member.uname, member.gname)):
            yield warn(OwnerSet)

        if member.mode & (stat.S_IXGRP | stat.S_IXUSR | stat.S_IXOTH):
            yield warn(Executable)

        path = pathlib.Path(member.name)
        if path.is_absolute():
            yield warn(AbsolutePath, member.name)

        filename = path.name
        if filename in LOCAL_BUILD_FILENAMES or any(filename.endswith(p) for p
                                                    in LOCAL_BUILD_EXTS):
            yield warn(LocalBuildFiles, filename)
        elif filename in TRASH_FILENAMES:
            yield warn(Trash, filename)
        elif filename.startswith('.'):
            yield warn(HiddenFile, filename)

        member_bytes = tar.extractfile(member).read()
        # assume it's utf8
        try:
            member_str = member_bytes.decode()
        except UnicodeDecodeError:
            member_str = None
        else:
            # TODO It would be better to have one master pattern for all the
            # things so member_str is only scanned once...
            if all(pat in member_str for pat in ('[registry]', 'token')):
                yield warn(CargoToken, member.name)
            for token in AWSToken.CLIENT_ID_PATTERN.findall(member_str):
                if token != 'AKIAIOSFODNN7EXAMPLE':
                    yield warn(AWSToken, member.name)
            if PrivateKey.PGP_PATTERN.search(member_str) is not None:
                yield warn(PrivateKey, member.name)

        parts = path.parts
        if len(parts) > 1 and parts[-2:] == ('.cargo', 'config'):
            yield warn(CargoConfig)
            if member_str is not None and 'token' in member_str:
                yield warn(CargoToken)

        for part in parts[:-1]:
            if part in LOCAL_BUILD_DIRS:
                yield warn(LocalBuildFiles, part)
            elif part == '..':
                yield warn(PathEscape, member.name)
            elif part.startswith('.'):
                yield warn(HiddenPath, part)

        suffix = path.suffix
        for pattern in DENY_PATTERNS:
            if pattern.part == 'filename':
                part = filename
            elif pattern.part == 'extension':
                if suffix and suffix.startswith('.'):
                    part = suffix[1:]
                else:
                    part = suffix
            elif pattern.part == 'path':
                part = member.name
            else:
                raise ValueError(pattern.part)
            if pattern.matches(part):
                yield warn(SensitiveFile, pattern.caption)


def _check_worker(crate):
    return tuple(_check_crate(crate))


def _iter_warnings_async():
    '''Iterate over all warnings for all crates in the db'''
    with multiprocessing.pool.Pool() as pool:
        results = []
        idx = 0
        for crate in _iter_crates_from_db():
            results.append(pool.apply_async(_check_worker, args=(crate, )))
            if len(results) - idx > pool._processes:
                results[idx].wait()
                idx = len(results)
        pool.close()
        pool.join()
    for res in results:
        yield from res.get()


def _unique_warnings():
    '''Create a dictionary of (reason, crate, info)s, pointing to dicionaries
    of affected files, pointing to affected versions'''
    d = {}
    for warning in _iter_warnings_async():
        # Exclude stuff that is mostly uninteresting
        if isinstance(warning, (OwnerSet, Executable, LocalBuildFiles, Trash,
                                TarError)):
            continue
        krate = d.setdefault((warning.reason, warning.crate_name,
                              warning.info), {})
        nums = krate.setdefault(warning.member_pure_name, set())
        nums.add(warning.num)
    return d


def report_warnings():
    '''Print a possibly human readable report of all warnings for all crates'''
    for (reason, crate_name, info), nums_members in _unique_warnings().items():
        for member, nums in nums_members.items():
            print('\t'.join(map(str, (reason, crate_name,
                                      ';'.join(sorted(nums)), info, member))))


def _count_warnings():
    return collections.Counter(((reason, info) for reason, _, _, info, _ in
                                (line.split('\t') for line in sys.stdin)))


def report_counts():
    '''Print a possibly human-readable report of statistics about warnings for
    all crates in the db. Should get piped to a markdown processor'''

    # TODO does it even work? who knows?
    _escape_pattern = re.compile('([\\`\*_\{\}\[\]\(\)#\+-\.\!])')

    def _markdown_escape(particle):
        if particle == 'None':
            return ''
        return _escape_pattern.sub('\\\\\\1', particle)

    print('Reason|Info|Count\n---|---|---')

    for reason, count, info in sorted(((r, c, i) for (r, i), c in
                                       _count_warnings().items()),
                                      reverse=True):
        print('|'.join(map(_markdown_escape, (reason, info, str(count)))))


class TestFalsePositives(unittest.TestCase):

    def setUp(self):
        self.filters = _false_positive_filters()

    def test_private_key(self):
        w = PrivateKey('openssl', None, None, 'foo/test/key.pem')
        self.assertTrue(any((f(w) for f in self.filters)))


class TestFileDetection(unittest.TestCase):

    @staticmethod
    def _create_tarfile(member=None, content=None):
        buf = io.BytesIO()
        tar = tarfile.open(fileobj=buf, mode='w:gz')
        if member is not None:
            info = tarfile.TarInfo(member)
            content_bytes = content.encode()
            info.size = len(content_bytes)
            tar.addfile(info, io.BytesIO(content_bytes))
            tar.close()
            return buf.getvalue()
        else:
            return buf, tar

    @classmethod
    def spawn_crate(cls, member, content=''):
        return Crate(0, 'TEST', '0', cls._create_tarfile(member, content))

    def test_cargo_api_key(self):
        crate = self.spawn_crate('.cargo/config', '[registry]\ntoken = foobar')
        warnings = _check_crate(crate)
        # detects both the filename and the content
        self.assertTrue(isinstance(next(warnings), CargoToken))
        self.assertTrue(isinstance(next(warnings), CargoConfig))
        self.assertTrue(isinstance(next(warnings), CargoToken))
        self.assertTrue(isinstance(next(warnings), HiddenPath))

    def test_private_rsa_key(self):
        crate = self.spawn_crate('my_aws_key',
                                 'foo -----BEGIN RSA PRIVATE KEY----- bar')
        warnings = _check_crate(crate)
        self.assertTrue(isinstance(next(warnings), PrivateKey))
        self.assertRaises(StopIteration, warnings.__next__)

    def test_private_key(self):
        crate = self.spawn_crate('my_aws_key',
                                 'foo -----BEGIN PRIVATE KEY----- bar')
        warnings = _check_crate(crate)
        self.assertTrue(isinstance(next(warnings), PrivateKey))
        self.assertRaises(StopIteration, warnings.__next__)

    def test_aws_api_key(self):
        crate = self.spawn_crate('my_aws_key',
                                 'aws_key = AKIA1111111111111111;')
        warnings = _check_crate(crate)
        self.assertTrue(isinstance(next(warnings), AWSToken))
        self.assertRaises(StopIteration, warnings.__next__)

    def test_aws_api_key_false_positive(self):
        crate = self.spawn_crate('my_aws_key',
                                 'aws_key = AKIAIOSFODNN7EXAMPLE')
        warnings = _check_crate(crate)
        self.assertRaises(StopIteration, warnings.__next__)

    def test_false_positive_asc(self):
        crate = self.spawn_crate('some.javascript')
        self.assertRaises(StopIteration, _check_crate(crate).__next__)

    def test_false_positive_dotenv(self):
        crate = self.spawn_crate('foo.env_curllib')
        self.assertRaises(StopIteration, _check_crate(crate).__next__)

    def test_absolute_path(self):
        crate = self.spawn_crate('/etc/passwd')
        self.assertTrue(isinstance(next(_check_crate(crate)), AbsolutePath))

    def test_pathescape(self):
        crate = self.spawn_crate('src/../../../etc/passwd')
        self.assertTrue(isinstance(next(_check_crate(crate)), PathEscape))

    def test_filename_match(self):
        warn = next(_check_crate(self.spawn_crate('src/otr.private_key')))
        self.assertTrue(isinstance(warn, SensitiveFile))
        self.assertEqual(warn.info, 'Pidgin OTR private key')

    def test_filename_regex(self):
        warn = next(_check_crate(self.spawn_crate('src/secret_dsa')))
        self.assertTrue(isinstance(warn, SensitiveFile))
        self.assertEqual(warn.info, 'Private SSH key')

    def test_extension_match(self):
        warn = next(_check_crate(self.spawn_crate('src/foo.kwallet')))
        self.assertTrue(isinstance(warn, SensitiveFile))
        self.assertEqual(warn.info, 'KDE Wallet Manager database file')

    def test_extension_regex(self):
        warn = next(_check_crate(self.spawn_crate('src/foo.keyring')))
        self.assertTrue(isinstance(warn, SensitiveFile))
        self.assertEqual(warn.info, 'GNOME Keyring database file')

    def test_extension_regex2(self):
        warnings = _check_crate(self.spawn_crate('src/.htpasswd'))
        next(warnings)
        warn = next(warnings)
        self.assertTrue(isinstance(warn, SensitiveFile))
        self.assertEqual(warn.info, 'Apache htpasswd file')
