# pylint: disable=import-error
from distutils.core import setup
# pylint: enable=import-error
import os
import sys

# pylint: disable=import-error
# pylint: disable=unused-import
import py2exe
# pylint: enable=unused-import
# pylint: enable=import-error
import zmq


def tree(root_dir, dest):
    """
    Create a list with all files root_dir and its subfolders in an
    appropriate format for distutils data_files.
    """
    prefix = os.path.dirname(root_dir)
    data_files = [
        (dest+root[len(prefix):], [os.path.join(root, f) for f in files])
        for root, _, files in os.walk(os.path.normpath(root_dir))
    ]
    return data_files


def main():
    setup_dir = os.path.dirname(os.path.realpath(__file__))
    root_dir = os.path.dirname(os.path.dirname(setup_dir))
    zmq_dir = os.path.dirname(zmq.__file__)

    # py2exe depedency detection is quite problematic
    sys.path.insert(0, zmq_dir)    # for libzmq.pyd
    sys.path.insert(0, root_dir)   # for node
    sys.path.insert(0, setup_dir)  # for local openbazaar.py

    data_files = tree(os.path.join(root_dir, "html"), ".")
    data_files.append(
        (".", [os.path.join(root_dir, "pycountry-1.8-py2.7.egg")])
    )

    setup(
        console=[
            {
                'script': 'openbazaar.py',
                'icon_resources': [(1, 'icon.ico')]
            },
            {
                'script': 'stop.py'
            }
        ],
        options={
            "py2exe":
            {
                'dist_dir': 'dist_exe',
                'bundle_files': 3,
                'compressed': 2,
                'optimize': 2,
                'includes': [
                    "pkg_resources",
                    "zmq.utils",
                    "zmq.utils.jsonapi",
                    "zmq.utils.strtypes",
                    "zmq.backend.cython"
                ],
                # NOTE: py2exe copies libzmq.pyd with the wrong name
                # zmq.libzmq.pyd. Manually excluding zmq.libzmq.pyd
                # copies it with the right name.
                'excludes': ['zmq.libzmq', 'pycountry'],
                'dll_excludes': [
                    'IPHLPAPI.DLL',
                    'PSAPI.DLL',
                    'WTSAPI32.dll',
                    'w9xpopen.exe'
                ]
            }
        },
        data_files=data_files
    )

if __name__ == '__main__':
    main()
