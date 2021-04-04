"""
    pyznap.clean
    ~~~~~~~~~~~~~~

    Clean snapshots.

    :copyright: (c) 2018-2019 by Yannick Boetzel.
    :license: GPLv3, see LICENSE for more details.
"""

import logging
from datetime import datetime
from subprocess import CalledProcessError
from .ssh import SSH, SSHException
from .utils import SNAPSHOT_TYPES, parse_name
import pyznap.pyzfs as zfs
from .process import DatasetBusyError, DatasetNotFoundError


def clean_snap(snap):
    """Deletes a snapshot

    Parameters
    ----------
    snap : {ZFSSnapshot}
        Snapshot to destroy
    """

    logger = logging.getLogger(__name__)

    logger.info('Deleting snapshot {}...'.format(snap))
    try:
        snap.destroy()
    except DatasetBusyError as err:
        logger.error(err)
    except CalledProcessError as err:
        logger.error('Error while deleting snapshot {}: \'{:s}\'...'
                     .format(snap, err.stderr.rstrip()))
    except KeyboardInterrupt:
        logger.error('KeyboardInterrupt while cleaning snapshot {}...'
                     .format(snap))
        raise


def clean_filesystem(filesystem, conf):
    """Deletes snapshots of a single filesystem according to conf.

    Parameters:
    ----------
    filesystem : {ZFSFilesystem}
        Filesystem to clean
    conf : {dict}
        Config entry with snapshot strategy
    """

    logger = logging.getLogger(__name__)
    logger.debug('Cleaning snapshots on {}...'.format(filesystem))

    snapshots = {t: [] for t in SNAPSHOT_TYPES}
    # catch exception if dataset was destroyed since pyznap was started
    try:
        fs_snapshots = filesystem.snapshots()
    except (DatasetNotFoundError, DatasetBusyError) as err:
        logger.error('Error while opening {}: {}...'.format(filesystem, err))
        return 1
    # categorize snapshots
    for snap in fs_snapshots:
        # Ignore snapshots not taken with pyznap or sanoid
        if not snap.name.split('@')[1].startswith(('pyznap', 'autosnap')):
            continue
        try:
            snap_type = snap.name.split('_')[-1]
            snapshots[snap_type].append(snap)
        except (ValueError, KeyError):
            continue

    # Reverse sort by time taken
    for snaps in snapshots.values():
        snaps.reverse()

    for stype in reversed(SNAPSHOT_TYPES):
        for snap in snapshots[stype][conf[stype]:]:
            clean_snap(snap)


def clean_config(config):
    """Deletes old snapshots according to strategies given in config. Goes through each config,
    opens up ssh connection if necessary and then recursively calls clean_filesystem.

    Parameters:
    ----------
    config : {list of dict}
        Full config list containing all strategies for different filesystems
    """

    logger = logging.getLogger(__name__)
    logger.info('Cleaning snapshots...')

    for conf in config:
        if not conf.get('clean', None):
            logger.debug('Ignore config from clean {}...'.format(conf['name']))
            continue
        logger.debug('Process config {}...'.format(conf['name']))

        name = conf['name']
        try:
            _type, fsname, user, host, port = parse_name(name)
        except ValueError as err:
            logger.error('Could not parse {:s}: {}...'.format(name, err))
            continue

        if _type == 'ssh':
            try:
                ssh = SSH(user, host, port=port, key=conf['key'])
            except (FileNotFoundError, SSHException):
                continue
            name_log = '{:s}@{:s}:{:s}'.format(user, host, fsname)
        else:
            ssh = None
            name_log = fsname

        snap_exclude_property = conf['snap_exclude_property']

        try:
            # Children includes the base filesystem (named 'fsname')
            children = zfs.find_exclude(conf, config)
        except DatasetNotFoundError as err:
            if conf['ignore_not_existing']:
                logger.warning('Dataset {:s} does not exist...'.format(name_log))
            else:
                logger.error('Dataset {:s} does not exist...'.format(name_log))
            continue
        except ValueError as err:
            logger.error(err)
            continue
        except CalledProcessError as err:
            logger.error('Error while opening {:s}: \'{:s}\'...'
                         .format(name_log, err.stderr.rstrip()))
        else:
            # Clean snapshots of parent filesystem - ignore exclude property for top fs
            clean_filesystem(children[0], conf)
            # Clean snapshots of all children that don't have a seperate config entry
            for child in children[1:]:
                if snap_exclude_property and child.ispropval(snap_exclude_property, check='false'):
                    logger.debug('Ignore dataset {:s}, have property {:s}=false'.format(child.name, snap_exclude_property))
                else:
                    clean_filesystem(child, conf)
        finally:
            if ssh:
                ssh.close()
