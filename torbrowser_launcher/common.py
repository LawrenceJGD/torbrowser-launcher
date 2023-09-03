"""
Tor Browser Launcher
https://github.com/micahflee/torbrowser-launcher/

Copyright (c) 2013-2021 Micah Lee <micah@micahflee.com>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

import gettext
import json
import os
import pickle
import platform
import re
import shutil
import sys
from pathlib import Path

import gpg
import requests

SHARE = Path(
    os.getenv("TBL_SHARE", Path(sys.prefix, "share")),
    "torbrowser-launcher",
)

gettext.install("torbrowser-launcher")

# We're looking for output which:
#
#  1. The first portion must be `[GNUPG:] IMPORT_OK`
#  2. The second must be an integer between [0, 15], inclusive
#  3. The third must be an uppercased hex-encoded 160-bit fingerprint
gnupg_import_ok_pattern = re.compile(
    rb"(\[GNUPG\:\]) (IMPORT_OK) ([0-9]|[1]?[0-5]) ([A-F0-9]{40})"
)


class Common(object):
    def __init__(self, tbl_version):
        self.tbl_version = tbl_version

        # initialize the app
        self.architecture = "x86_64" if "64" in platform.architecture()[0] else "i686"
        self.default_mirror = "https://dist.torproject.org/"
        self.build_paths()
        self.torbrowser12_rename_old_tbb()
        for d in self.paths["dirs"].values():
            mkdir_(d)
        self.load_mirrors()
        self.load_settings()
        self.build_paths()
        mkdir_(self.paths["download_dir"])
        mkdir_(self.paths["tbb"]["dir"])
        self.init_gnupg()

    # build all relevant paths
    def build_paths(self, tbb_version=None):
        try:
            homedir = Path.home()
        except RuntimeError:
            homedir = Path("/tmp", ".torbrowser-" + os.getenv("USER", ""))
            try:
                homedir.mkdir(0o700, exist_ok=True)
            except OSError:
                self.set_gui(
                    "error", _("Error creating {0}").format(homedir), [], False
                )

        tbb_config = Path(
            os.getenv("XDG_CONFIG_HOME", homedir / ".config"),
            "torbrowser",
        )
        tbb_cache = Path(
            os.getenv("XDG_CACHE_HOME", homedir / ".cache"),
            "torbrowser",
        )
        tbb_local = Path(
            os.getenv("XDG_DATA_HOME", homedir / ".local" / "share"), "torbrowser"
        )
        old_tbb_data = homedir / "torbrowser"

        if tbb_version:
            # tarball filename
            arch = "linux64" if self.architecture == "x86_64" else "linux32"
            tarball_filename = f"tor-browser-{arch}-{tbb_version}_ALL.tar.xz"

            # tarball
            self.paths["tarball_url"] = f"torbrowser/{tbb_version}/{tarball_filename}"
            self.paths["tarball_file"] = Path(tbb_cache, "download", tarball_filename)
            self.paths["tarball_filename"] = tarball_filename

            # sig
            self.paths["sig_url"] = f"torbrowser/{tbb_version}/{tarball_filename}.asc"
            self.paths["sig_filename"] = f"{tarball_filename}.asc"
            self.paths["sig_file"] = Path(
                tbb_cache, "download", self.paths["sig_filename"]
            )
        else:
            self.paths = {
                "dirs": {
                    "config": tbb_config,
                    "cache": tbb_cache,
                    "local": tbb_local,
                },
                "old_data_dir": old_tbb_data,
                "tbl_bin": Path(sys.argv[0]),
                "icon_file": SHARE.parent / "pixmaps/torbrowser.png",
                "torproject_pem": SHARE / "torproject.pem",
                "signing_keys": {
                    "tor_browser_developers": SHARE / "tor-browser-developers.asc",
                    "wkd_tmp": tbb_cache / "torbrowser.gpg",
                },
                "mirrors_txt": [
                    SHARE / "mirrors.txt",
                    tbb_config / "mirrors.txt",
                ],
                "download_dir": tbb_cache / "download",
                "gnupg_homedir": tbb_local / "gnupg_homedir",
                "settings_file": tbb_config / "settings.json",
                "settings_file_pickle": tbb_config / "settings",
                "version_check_url": "https://aus1.torproject.org/torbrowser/"
                "update_3/release/Linux_x86_64-gcc3/x/ALL",
                "version_check_file": tbb_cache / "download/release.xml",
                "tbb": {
                    "changelog": tbb_local
                    / "tbb"
                    / self.architecture
                    / "tor-browser/Browser/TorBrowser/Docs/ChangeLog.txt",
                    "dir": tbb_local / "tbb" / self.architecture,
                    "dir_tbb": tbb_local / "tbb" / self.architecture / "tor-browser",
                    "start": tbb_local
                    / "tbb"
                    / self.architecture
                    / "tor-browser/start-tor-browser.desktop",
                },
            }

        # Add the expected fingerprint for imported keys:
        tor_browser_developers_fingerprint = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
        self.fingerprints = {
            "tor_browser_developers": tor_browser_developers_fingerprint,
            "wkd_tmp": tor_browser_developers_fingerprint,
        }

    # Tor Browser 12.0 no longer has locales. If an old TBB folder exists with
    # locales, rename it to just tor_browser
    def torbrowser12_rename_old_tbb(self):
        if not self.paths["tbb"]["dir"].exists():
            return
        for path in self.paths["tbb"]["dir"].glob("tor-browser_*"):
            if not path.is_dir():
                continue
            if self.paths["tbb"]["dir_tbb"].exists():
                try:
                    # Tries to remove the locale directory if tor_browser
                    # folder already exists
                    shutil.rmtree(path)
                    print(_("Deleted {0}").format(path))
                    continue
                except OSError as err:
                    print(
                        _("Could not remove {0} due a system error: {1}").format(
                            path, err
                        )
                    )
                    continue

            try:
                path.rename(self.paths["tbb"]["dir_tbb"])
            except OSError as err:
                print(
                    _("Could not move {0} to {1} due an error: {2}").format(
                        path, self.paths["tbb"]["dir_tbb"], err
                    )
                )
                continue

            print(_("Renamed {0} to {1}").format(path, self.paths["tbb"]["dir_tbb"]))

    # if gnupg_homedir isn't set up, set it up
    def init_gnupg(self):
        if not self.paths["gnupg_homedir"].exists():
            print(_("Creating GnuPG homedir"), self.paths["gnupg_homedir"])
            mkdir_(self.paths["gnupg_homedir"])
        self.import_keys()

    def proxies(self):
        # Use tor socks5 proxy, if enabled
        if self.settings["download_over_tor"]:
            socks5_address = f"socks5h://{self.settings['tor_socks_address']}"
            return {"https": socks5_address, "http": socks5_address}
        return None

    def refresh_keyring(self):
        print("Downloading latest Tor Browser signing key...")

        # Fetch key from wkd, as per https://support.torproject.org/tbb/how-to-verify-signature/
        # Sometimes GPG throws errors, so comment this out and download it directly
        # p = subprocess.Popen(
        #     [
        #         "gpg",
        #         "--status-fd",
        #         "2",
        #         "--homedir",
        #         self.paths["gnupg_homedir"],
        #         "--auto-key-locate",
        #         "nodefault,wkd",
        #         "--locate-keys",
        #         "torbrowser@torproject.org",
        #     ],
        #     stderr=subprocess.PIPE,
        # )
        # p.wait()

        # Download the key from WKD directly
        r = requests.get(
            "https://torproject.org/.well-known/openpgpkey/hu/"
            "kounek7zrdx745qydx6p59t9mqjpuhdf?l=torbrowser",
            proxies=self.proxies(),
        )
        if r.status_code != 200:
            print(f"Error fetching key, status code = {r.status_code}")
            return

        with open(self.paths["signing_keys"]["wkd_tmp"], "wb") as f:
            f.write(r.content)
        print(
            "Key imported successfully"
            if self.import_key_and_check_status("wkd_tmp")
            else "Key failed to import"
        )
        return

    def import_key_and_check_status(self, key):
        """Import a GnuPG key and check that the operation was successful.
        :param str key: A string specifying the key's filepath from
            ``Common.paths``
        :rtype: bool
        :returns: ``True`` if the key is now within the keyring (or was
            previously and hasn't changed). ``False`` otherwise.
        """
        with gpg.Context() as c:
            c.set_engine_info(
                gpg.constants.protocol.OpenPGP,
                home_dir=str(self.paths["gnupg_homedir"]),
            )

            impkey = self.paths["signing_keys"][key]
            try:
                c.op_import(gpg.Data(file=str(impkey)))
            except:
                return False
            result = c.op_import_result()
            if result and self.fingerprints[key] in result.imports[0].fpr:
                return True
            return False

    # import gpg keys
    def import_keys(self):
        """Import all GnuPG keys.
        :rtype: bool
        :returns: ``True`` if all keys were successfully imported; ``False``
            otherwise.
        """
        keys = [
            "tor_browser_developers",
        ]
        all_imports_succeeded = True

        for key in keys:
            imported = self.import_key_and_check_status(key)
            if imported:
                continue
            print(
                _("Could not import key with fingerprint: %s.") % self.fingerprints[key]
            )
            all_imports_succeeded = False

        if not all_imports_succeeded:
            print(_("Not all keys were imported successfully!"))

        return all_imports_succeeded

    # load mirrors
    def load_mirrors(self):
        self.mirrors = []
        for srcfile in self.paths["mirrors_txt"]:
            try:
                with open(srcfile, "r", encoding="utf-8") as f:
                    for mirror in f:
                        mirror = mirror.strip()
                        if mirror not in self.mirrors:
                            self.mirrors.append(mirror)
            except FileNotFoundError:
                pass

    # load settings
    def load_settings(self):
        default_settings = {
            "tbl_version": self.tbl_version,
            "installed": False,
            "download_over_tor": False,
            "tor_socks_address": "127.0.0.1:9050",
            "mirror": self.default_mirror,
        }

        try:
            with open(self.paths["settings_file"], encoding="utf-8") as f:
                settings = json.load(f)
        except (FileNotFoundError, IsADirectoryError):
            pass
        else:
            resave = False

            # detect installed
            settings["installed"] = self.paths["tbb"]["start"].is_file()

            # make sure settings file is up-to-date
            for setting in default_settings.keys() - settings.keys():
                settings[setting] = default_settings[setting]
                resave = True

            # make sure tor_socks_address doesn't start with 'tcp:'
            if settings["tor_socks_address"].startswith("tcp:"):
                settings["tor_socks_address"] = settings["tor_socks_address"][4:]
                resave = True

            # make sure the version is current
            if settings["tbl_version"] != self.tbl_version:
                settings["tbl_version"] = self.tbl_version
                resave = True

            self.settings = settings
            if resave:
                self.save_settings()
            return

        # if settings file is still using old pickle format, convert to json
        try:
            with open(self.paths["settings_file_pickle"], "rb") as f:
                self.settings = pickle.load(f)
        except (FileNotFoundError, IsADirectoryError):
            pass
        else:
            self.save_settings()
            self.paths["settings_file_pickle"].unlink()
            self.load_settings()
            return

        self.settings = default_settings
        self.save_settings()
        return

    # save settings
    def save_settings(self):
        with open(self.paths["settings_file"], "w", encoding="utf-8") as f:
            json.dump(self.settings, f)
        return True


def mkdir_(path):
    """Creates a directory."""
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except:
        print(_("Cannot create directory {0}").format(path))
        return False
    if not os.access(path, os.W_OK):
        print(_("{0} is not writable").format(path))
        return False
    return True
