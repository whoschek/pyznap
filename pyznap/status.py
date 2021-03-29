"""
    pyznap.status
    ~~~~~~~~~~~~~~

    Status filesystem snapshots.

    :copyright: (c) 2018-2019 by Yannick Boetzel.
    :license: GPLv3, see LICENSE for more details.
"""

import logging
from datetime import datetime
from fnmatch import fnmatch
from subprocess import CalledProcessError
from .ssh import SSH, SSHException
from .utils import parse_name
import pyznap.pyzfs as zfs
from .process import DatasetBusyError, DatasetNotFoundError


def status_filesystem(filesystem, conf):
    """Deletes snapshots of a single filesystem according to conf.

    Parameters:
    ----------
    filesystem : {ZFSFilesystem}
        Filesystem to status
    conf : {dict}
        Config entry with snapshot strategy
    """

    logger = logging.getLogger(__name__)
    logger.debug('Checking snapshots on {}...'.format(filesystem))

    snapshots = {'frequent': [], 'hourly': [], 'daily': [], 'weekly': [], 'monthly': [], 'yearly': []}
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

    level = logging.INFO

    # prepare data for status
    counts = {}
    for s in snapshots.keys():
        counts[s] = conf.get(s, 0) or 0
    pyznap_snapshots = sum(len(s) for s in snapshots.values())

    # increate stats count and check excludes in send
    zfs.STATS.add('checked_count')
    if conf.get('snap', False):
        zfs.STATS.add('snap_count')
    if conf.get('clean', False):
        zfs.STATS.add('clean_count')
    send = conf.get('dest', False)
    if send:
        # check excluded
        sending = []
        for exclude, dst in zip(conf['exclude'], send):
            if exclude and any(fnmatch(filesystem.name, pattern) for pattern in exclude):
                logger.debug('Exluded from send {} -> {}...'.format(filesystem, dst))
                sending.append(False)
            else:
                sending.append(dst)
        send = sending
    if send:
        zfs.STATS.add('send_count')

    # make status data
    status = {
        'name': str(filesystem),
        'snap': conf.get('snap', False),
        'clean': conf.get('clean', False),
        'send': send,
        'snapshots': len(fs_snapshots),
        'pyznap_snapshots': pyznap_snapshots,
        'yearly': str(len(snapshots['yearly']))+'/'+str(counts['yearly']),
        'monthly': str(len(snapshots['monthly']))+'/'+str(counts['monthly']),
        'weekly': str(len(snapshots['weekly']))+'/'+str(counts['weekly']),
        'daily': str(len(snapshots['daily']))+'/'+str(counts['daily']),
        'hourly': str(len(snapshots['hourly']))+'/'+str(counts['hourly']),
        'frequent': str(len(snapshots['frequent']))+'/'+str(counts['frequent']),
        }

    # check needed snapshots count
    if (
        len(snapshots['yearly']) < counts['yearly'] or
        len(snapshots['monthly']) < counts['monthly'] or
        len(snapshots['weekly']) < counts['weekly'] or
        len(snapshots['daily']) < counts['daily'] or
        len(snapshots['hourly']) < counts['hourly'] or
        len(snapshots['frequent']) < counts['frequent']
    ):
        level = logging.WARNING

    # TODO: last/first snapshot timestamp
    # TODO: remote uptodate check

    logger.log(level, 'STATUS: '+str(status))


def status_config(config):
    """Check snapshots status according to strategies given in config. Goes through each config,
    opens up ssh connection if necessary and then recursively calls status_filesystem.

    Parameters:
    ----------
    config : {list of dict}
        Full config list containing all strategies for different filesystems
    """

    logger = logging.getLogger(__name__)
    logger.info('Checking snapshots...')

    for conf in config:

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
            children = zfs.find(path=fsname, types=['filesystem', 'volume'], ssh=ssh)
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
            # status snapshots of parent filesystem
            if snap_exclude_property and children[0].ispropval(snap_exclude_property, check='false'):
                logger.debug('Ignore dataset {:s}, have property {:s}=false'.format(name_log, snap_exclude_property))
            else:
                status_filesystem(children[0], conf)
            # status snapshots of all children that don't have a seperate config entry
            for child in children[1:]:
                # Check if any of the parents (but child of base filesystem) have a config entry
                for parent in children[1:]:
                    if ssh:
                        child_name = 'ssh:{:d}:{:s}@{:s}:{:s}'.format(port, user, host, child.name)
                        parent_name = 'ssh:{:d}:{:s}@{:s}:{:s}'.format(port, user, host, parent.name)
                    else:
                        child_name = child.name
                        parent_name = parent.name
                    # Skip if child has an entry or if any parent entry already in config
                    child_parent = '/'.join(child_name.split('/')[:-1]) # get parent of child filesystem
                    if ((child_name == parent_name or child_parent.startswith(parent_name)) and
                        (parent_name in [entry['name'] for entry in config])):
                        break
                else:
                    if snap_exclude_property and child.ispropval(snap_exclude_property, check='false'):
                        logger.debug('Ignore dataset {:s}, have property {:s}=false'.format(child_name, snap_exclude_property))
                    else:
                        status_filesystem(child, conf)
        finally:
            if ssh:
                ssh.close()
