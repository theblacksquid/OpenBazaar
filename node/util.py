import os
import sys
import webbrowser
import platform


def is_mac():
    os_name = platform.uname()[0]
    return os_name == 'Darwin'


def open_default_webbrowser(url, protocol="http"):
    """
    Open URL at the default browser.

    @param url: The URL to open.
    @type url: str

    @param protocol: The internet protocol to use.
    @type protocol: str

    @return: True on success, False on failure.
    @rtype: bool
    """
    if not url.startswith(protocol):
        # If protocol is absent from the url, attach it, otherwise
        # the file `url` will be opened in Linux flavors.
        full_url = "%s://%s" % (protocol, url)
    else:
        full_url = url

    try:
        success = webbrowser.open(full_url)
    except webbrowser.Error:
        success = False
        print "[openbazaar:%s.%s] Could not open default web browser at %s" % (
            "util",
            "open_default_webbrowser",
            url
        )
    return success


def osx_check_dyld_library_path():
    """This is a necessary workaround as you cannot set the DYLD_LIBRARY_PATH
    by the time python has started."""
    if not os.environ.get('DYLD_LIBRARY_PATH'):
        print (
            'WARNING: DYLD_LIBRARY_PATH not set, this might cause issues'
            '\nwith openssl elliptic curve cryptography and other libraries.'
            '\nIt is recommended that you stop OpenBazaar and set your'
            '\nDYLD_LIBRARY_PATH environment variable as follows:'
            '\n    export DYLD_LIBRARY_PATH=$(brew --prefix openssl)/'
            'lib:${DYLD_LIBRARY_PATH}'
            '\nthen restart OpenBazaar.'
        )
        sys.exit(1)
