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


def status_filesystem(filesystem, conf, filter_snap=None, filter_clean=None, filter_send=None):
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
    zfs.STATS.add('checked_count')

    snap = conf.get('snap', False)
    clean = conf.get('clean', False)
    send = bool(conf.get('dest', False))
    snap_exclude_property = conf['snap_exclude_property']
    if snap_exclude_property and filesystem.ispropval(snap_exclude_property, check='false'):
        zfs.STATS.add('snap_excluded_count')
        logger.debug('Ignore dataset fron snap {:s}, have property {:s}=false'.format(filesystem.name, snap_exclude_property))
        snap = False
        clean = False
    send_exclude_property = conf['send_exclude_property']
    if send_exclude_property and filesystem.ispropval(send_exclude_property, check='false'):
        zfs.STATS.add('send_excluded_count')
        logger.debug('Ignore dataset fron send {:s}, have property {:s}=false'.format(filesystem.name, snap_exclude_property))
        send = False
    if not (snap or clean or send):
        return

    if filter_snap is not None and snap != filter_snap:
        return
    if filter_clean is not None and clean != filter_clean:
        return

    # increase stats count and check excludes in send
    if snap:
        zfs.STATS.add('snap_count')
    if clean:
        zfs.STATS.add('clean_count')
    if send:
        dest = conf.get('dest', False)
        if dest and conf['exclude']:
            # check excluded
            sending = []
            for exclude, dst in zip(conf['exclude'], dest):
                if exclude and any(fnmatch(filesystem.name, pattern) for pattern in exclude):
                    zfs.STATS.add('dest_excluded_count')
                    logger.debug('Excluded from send {} -> {}...'.format(filesystem, dst))
                    sending.append(False)
                else:
                    sending.append(dst)
            dest = sending
        send = send and dest and any(filter(lambda x: bool(x), dest))
    else:
        dest = None

    if filter_send is not None and send != filter_send:
        return

    if send:
        zfs.STATS.add('send_count')


    snapshots = {'frequent': [], 'hourly': [], 'daily': [], 'weekly': [], 'monthly': [], 'yearly': []}
    # catch exception if dataset was destroyed since pyznap was started
    try:
        fs_snapshots = filesystem.snapshots()
    except (DatasetNotFoundError, DatasetBusyError) as err:
        logger.error('Error while opening {}: {}...'.format(filesystem, err))
        return 1
    # categorize snapshots
    for snaps in fs_snapshots:
        # Ignore snapshots not taken with pyznap
        if not snaps.name.split('@')[1].startswith('pyznap'):
            continue
        try:
            snap_type = snaps.name.split('_')[-1]
            snapshots[snap_type].append(snaps)
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

    # make status data
    status = {
        'name': str(filesystem),
        'snap': snap,
        'clean': clean,
        'send': send,
        'dest': dest,
        'snapshots': len(fs_snapshots),
        'pyznap_snapshots': pyznap_snapshots,
        'yearly': str(len(snapshots['yearly']))+'/'+str(counts['yearly']),
        'monthly': str(len(snapshots['monthly']))+'/'+str(counts['monthly']),
        'weekly': str(len(snapshots['weekly']))+'/'+str(counts['weekly']),
        'daily': str(len(snapshots['daily']))+'/'+str(counts['daily']),
        'hourly': str(len(snapshots['hourly']))+'/'+str(counts['hourly']),
        'frequent': str(len(snapshots['frequent']))+'/'+str(counts['frequent']),
        'snap_exclude_property': snap_exclude_property,
        'send_exclude_property': send_exclude_property,
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


def status_config(config, filter_snap=None, filter_clean=None, filter_send=None):
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
            # status snapshots of parent filesystem - ignore exclude property for top fs
            status_filesystem(children[0], conf, filter_snap=filter_snap, filter_clean=filter_clean, filter_send=filter_send)
            # status snapshots of all children that don't have a separate config entry
            for child in children[1:]:
                status_filesystem(child, conf, filter_snap=filter_snap, filter_clean=filter_clean, filter_send=filter_send)
        finally:
            if ssh:
                ssh.close()
