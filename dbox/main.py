import os
import functools
import pathlib
import click
import hashlib
import datetime
import webbrowser
import unicodedata
import keyring
import fnmatch
from typing import Optional
from enum import Enum, auto
import dropbox
from logging import getLogger
_log = getLogger(__name__)
VERSION = "0.1.dev1"


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=VERSION, prog_name="dbox")
def cli(ctx):
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())


def verbose_option(func):
    @click.option("--verbose/--quiet", default=None)
    @functools.wraps(func)
    def _(verbose, *args, **kwargs):
        from logging import basicConfig
        level = "INFO"
        if verbose:
            level = "DEBUG"
        elif verbose is False:
            level = "WARNING"
        basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
        return func(*args, **kwargs)
    return _


def dropbox_option(func):
    @click.option("--keyring", "keyring_system", envvar="DROPBOX_KEYRING", show_envvar=True)
    @click.option("--refresh-token", envvar="DROPBOX_REFRESH_TOKEN", show_envvar=True)
    @click.option("--app-key", envvar="DROPBOX_APP_KEY", show_envvar=True)
    @click.option("--app-secret", envvar="DROPBOX_APP_SECRET", show_envvar=True)
    @functools.wraps(func)
    def _(refresh_token, app_key, app_secret, keyring_system, *args, **kwargs):
        if keyring_system:
            if not refresh_token:
                refresh_token = keyring.get_password(keyring_system, "refresh_token")
            if not app_key:
                app_key = keyring.get_password(keyring_system, "app_key")
            if not app_secret:
                app_secret = keyring.get_password(keyring_system, "app_secret")
        dbx = dropbox.Dropbox(oauth2_refresh_token=refresh_token, app_key=app_key, app_secret=app_secret)
        dbx.refresh_access_token()
        res = func(dbx=dbx, *args, **kwargs)
        dbx.close()
        return res
    return _


@cli.command()
@verbose_option
@click.option("--keyring", "keyring_system", envvar="DROPBOX_KEYRING", show_envvar=True)
@click.option("--app-key", envvar="DROPBOX_APP_KEY", show_envvar=True)
@click.option("--app-secret", envvar="DROPBOX_APP_SECRET", show_envvar=True)
def auth(keyring_system, app_key, app_secret):
    if keyring_system:
        if app_key:
            keyring.set_password(keyring_system, "app_key", app_key)
        else:
            app_key = keyring.get_password(keyring_system, "app_key")
        if app_secret:
            keyring.set_password(keyring_system, "app_secret", app_secret)
        else:
            app_secret = keyring.get_password(keyring_system, "app_secret")
    auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(
        consumer_key=app_key, consumer_secret=app_secret,
        token_access_type='offline',
        scope=['files.metadata.read', 'files.metadata.write',
               'files.content.read', 'files.content.write',
               'account_info.read'])
    auth_url = auth_flow.start()
    webbrowser.open(auth_url)
    auth_code = input("Enter the authorization code here: ").strip()
    try:
        oauth_result = auth_flow.finish(auth_code)
        _log.info("access token: %s", oauth_result.access_token)
        _log.info("refresh token: %s", oauth_result.refresh_token)
        _log.info("account id: %s", oauth_result.account_id)
        _log.info("user id: %s", oauth_result.user_id)
        _log.info("expire: %s", oauth_result.expires_at)
        _log.info("scope: %s", oauth_result.scope)
        if keyring_system:
            keyring.set_password(keyring_system, "refresh_token", oauth_result.refresh_token)
            click.echo(f"   export DROPBOX_KEYRING={keyring_system}")
        else:
            click.echo(f"   export DROPBOX_REFRESH_TOKEN={oauth_result.refresh_token}")
    except Exception:
        _log.exception("error")


def list_all(dbx: dropbox.Dropbox, remote_dir: str, recursive: bool = False) -> list:
    _log.debug("list all files: %s", remote_dir)
    res = []
    apires = dbx.files_list_folder(remote_dir, recursive=recursive)
    _log.debug("got %s", len(apires.entries))
    res.extend(apires.entries)
    while apires.has_more:
        apires = dbx.files_list_folder_continue(apires.cursor)
        _log.debug("got %s", len(apires.entries))
        res.extend(apires.entries)
    return res


def fix_remote_path(path: str) -> tuple[str, str]:
    if not path:
        return '', '/'
    if not path.startswith('/'):
        return '/'+path, '/'+path
    return path, path


@cli.command()
@verbose_option
@dropbox_option
@click.option("--recursive/--no-recursive", default=False)
@click.argument("directory", default="")
def ls(dbx: dropbox.Dropbox, directory, recursive):
    rdir, relative = fix_remote_path(directory)
    res = list_all(dbx, rdir, recursive=recursive)
    for i in res:
        _log.debug("entry: %s", i)
        path_d = pathlib.Path(i.path_display).relative_to(relative)
        if isinstance(i, dropbox.files.FolderMetadata):
            click.echo("{:10} {}/".format("[DIR]", path_d))
        else:
            click.echo("{:10} {} srv={:20} {}".format(
                i.size, i.client_modified.isoformat(),
                str(i.server_modified-i.client_modified), path_d))


@cli.command()
@verbose_option
@dropbox_option
@click.argument("filename")
def ls_revision(dbx: dropbox.Dropbox, filename):
    res = dbx.files_list_revisions(filename)
    if res.is_deleted:
        click.echo(f"deleted: {filename}")
    if res.server_deleted:
        click.echo(f"server-deleted: {filename}")
    click.echo("{:20}  {:20} {}".format("revision", "modified", "content_hash"))
    for i in res.entries:
        click.echo("{:20} {:20} {}".format(i.rev, i.server_modified.isoformat(), i.content_hash))
        _log.debug("entry: %s", i)


@cli.command()
@verbose_option
@dropbox_option
@click.option("--revision")
@click.option("--output", type=click.Path())
@click.option("--zip/--raw", default=False, show_default=True)
@click.argument("filename")
def download(dbx: dropbox.Dropbox, filename, output, revision, zip):
    if zip and revision:
        _log.error("cannot use --zip and --revision")
        raise click.Abort()
    if zip:
        res: dropbox.files.DownloadZipResult = dbx.files_download_zip_to_file(output, filename)
        _log.debug("result: %s", res)
    else:
        res: dropbox.files.FileMetadata = dbx.files_download_to_file(output, filename, revision)
        _log.debug("result: %s", res)
        ts = res.server_modified.timestamp()
        os.utime(output, (ts, ts))


def get_hash(p: pathlib.Path) -> str:
    hashes = []
    with p.open('rb') as ifp:
        hashes.append(hashlib.sha256(ifp.read(4*1024*1024)).digest())
    return hashlib.sha256(b"".join(hashes)).hexdigest()


@cli.command()
@verbose_option
@click.argument("filename", type=click.Path(exists=True, file_okay=True, dir_okay=False), nargs=-1)
def hash(filename):
    for i in filename:
        click.echo(f"{get_hash(pathlib.Path(i))} {i}")


@cli.command()
@verbose_option
@dropbox_option
def user(dbx: dropbox.Dropbox):
    res = dbx.users_get_current_account()
    click.echo(res)


class Mode(Enum):
    unknown = auto()
    unchanged = auto()
    download = auto()
    upload = auto()


def detect_mode(dbx: dropbox.Dropbox, local_path: pathlib.Path, remote_file: str,
                remote_info: Optional[dropbox.files.FileMetadata] = None,
                error_sec: float = 5.0) -> Mode:
    if remote_info is None:
        try:
            remote_info = dbx.files_get_metadata(remote_file)
            _log.debug("remote_info: %s", remote_info)
        except dropbox.exceptions.ApiError as e:
            if e.error.get_path().is_not_found():
                _log.debug("remote not found: upload")
                if not local_path.exists():
                    _log.debug("local not found: %s", local_path)
                    return Mode.unknown
                return Mode.upload
            raise
    if not isinstance(remote_info, dropbox.files.FileMetadata):
        _log.warning("is not file: %s", remote_file)
        return Mode.unknown
    if not local_path.exists():
        _log.debug("local not found: download")
        return Mode.download
    statval = local_path.stat()
    hashval = get_hash(local_path)
    if hashval == remote_info.content_hash:
        _log.debug("same hashval(%s): unchanged", hashval)
        return Mode.unchanged
    _log.debug("ts: remote=%s/%s vs. local=%s/%s",
               remote_info.server_modified, remote_info.client_modified,
               datetime.datetime.fromtimestamp(statval.st_mtime),
               datetime.datetime.fromtimestamp(statval.st_ctime))
    if remote_info.server_modified.timestamp() < statval.st_mtime-error_sec:
        _log.info("local is newer: upload")
        return Mode.upload
    elif remote_info.server_modified.timestamp() > statval.st_mtime+error_sec:
        _log.info("remote is newer: download")
        return Mode.download
    _log.debug("size: remote=%s vs. local=%s", remote_info.size, statval.st_size)
    if remote_info.size < statval.st_size:
        _log.info("local is larger: upload")
        return Mode.upload
    elif remote_info.size > statval.st_size:
        _log.info("remote is larger: download")
        return Mode.download
    _log.warning("unknown...")
    return Mode.unknown


def sync1(dbx: dropbox.Dropbox, mode: Mode, local_file: str, remote_file: str, dry: bool):
    local_path = pathlib.Path(local_file)
    local_path.parent.mkdir(exist_ok=True, parents=True)
    if mode == Mode.download:
        _log.info("download: %s -> %s", remote_file, local_file)
        if not dry:
            res: dropbox.files.FileMetadata = dbx.files_download_to_file(local_file, remote_file)
            if res:
                ts = res.server_modified.timestamp()
                os.utime(local_path, (ts, ts))
    elif mode == Mode.upload:
        _log.info("upload: %s <- %s", remote_file, local_file)
        if not dry:
            st = local_path.stat()
            ts = datetime.datetime.fromtimestamp(st.st_mtime)
            dbx.files_upload(local_path.read_bytes(), remote_file, dropbox.files.WriteMode.overwrite,
                             client_modified=ts)
    elif mode == Mode.unchanged:
        _log.info("unchanged: %s = %s", remote_file, local_file)
    elif mode == Mode.unknown:
        _log.warning("unknown: %s = %s", remote_file, local_file)


@cli.command()
@verbose_option
@dropbox_option
@click.option("--local-file", type=click.Path())
@click.option("--remote-file", type=click.Path())
@click.option("--dry/--wet", default=False, show_default=True)
def sync_file(dbx, local_file, remote_file, dry):
    rdir, _ = fix_remote_path(remote_file)
    local_path = pathlib.Path(local_file)
    mode = detect_mode(dbx, local_path, rdir)
    sync1(dbx, mode, local_file, remote_file, dry)


def is_ignore(fname: str, ignore: list[str]) -> bool:
    for i in ignore:
        if fnmatch.fnmatch(fname, i):
            return True
    return False


@cli.command()
@verbose_option
@dropbox_option
@click.option("--local-dir", type=click.Path())
@click.option("--remote-dir", type=click.Path())
@click.option("--ignore", multiple=True)
@click.option("--dry/--wet", default=False, show_default=True)
def sync_dir(dbx: dropbox.Dropbox, local_dir, remote_dir, ignore, dry):
    rdir, relative = fix_remote_path(remote_dir)
    local_path = pathlib.Path(local_dir)
    list_res = list_all(dbx, rdir, recursive=True)
    remote_files = [x for x in list_res if isinstance(x, dropbox.files.FileMetadata)]
    remote_files = [x for x in remote_files if not is_ignore(x.path_display, ignore)]
    remote_names = {pathlib.Path(x.path_display).relative_to(relative).as_posix() for x in remote_files}
    local_names: set[str] = set()
    for root, _, files in local_path.walk():
        for f in files:
            local_names.add((root / f).relative_to(local_path).as_posix())

    local_names = {x for x in local_names if not is_ignore(x, ignore)}

    _log.info("remote: %s", remote_names)
    _log.info("local: %s", local_names)
    remote_normalized = {unicodedata.normalize('NFC', x) for x in remote_names}
    local_normalized = {unicodedata.normalize('NFC', x) for x in local_names}
    _log.info("remote-local: %s", remote_normalized-local_normalized)
    _log.info("local-remote: %s", local_normalized-remote_normalized)
    done: set[str] = set()
    for remote_file_info in remote_files:
        remote_file = remote_file_info.path_display
        dpath = pathlib.Path(remote_file).relative_to(relative).as_posix()
        local_file = local_path / dpath
        mode = detect_mode(dbx, local_file, remote_file, remote_file_info)
        sync1(dbx, mode, local_file, remote_file, dry)
        done.add(dpath)
    for local_file in local_names:
        normalized = unicodedata.normalize('NFC', local_file)
        if normalized in done:
            continue
        remote_file = (pathlib.Path(rdir) / normalized).as_posix()
        mode = detect_mode(dbx, local_path / local_file, remote_file)
        sync1(dbx, mode, local_path / local_file, remote_file, dry)
        done.add(normalized)


@cli.command()
@verbose_option
@dropbox_option
@click.option("--local-dir", type=click.Path())
@click.option("--remote-dir", type=click.Path())
@click.option("--dry/--wet", default=False, show_default=True)
@click.argument("fnames", nargs=-1)
def rm_both(dbx: dropbox.Dropbox, local_dir, remote_dir, dry, fnames):
    rdir, relative = fix_remote_path(remote_dir)
    local_path = pathlib.Path(local_dir)
    list_res = list_all(dbx, rdir, recursive=True)
    remote_files = [x for x in list_res if isinstance(x, dropbox.files.FileMetadata)]
    remote_names = {pathlib.Path(x.path_display).relative_to(relative).as_posix() for x in remote_files}
    remote_to_del = remote_names & set(fnames)
    local_names: set[str] = set()
    for root, _, files in local_path.walk():
        for f in files:
            local_names.add((root / f).relative_to(local_path).as_posix())
    local_to_del = local_names & set(fnames)

    _log.info("remote: %s", remote_to_del)
    _log.info("local: %s", local_to_del)
    for i in remote_to_del:
        _log.info("delete(remote): %s", i)
        if not dry:
            dbx.files_delete((pathlib.Path(relative) / i).as_posix())
    for i in local_to_del:
        _log.info("delete(local): %s", i)
        if not dry:
            (local_path / i).unlink()


if __name__ == "__main__":
    cli()
