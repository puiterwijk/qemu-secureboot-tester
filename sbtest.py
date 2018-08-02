#!/bin/python3
# Copyright (C) 2018 Red Hat
# Authors:
# - Patrick Uiterwijk <puiterwijk@redhat.com>
# - Kashyap Chamarthy <kchamart@redhat.com>
#
# Licensed under MIT License, for full text see LICENSE

from __future__ import print_function

import argparse
import glob
import os
import logging
import tempfile
import time
import shutil
import string
import subprocess
import uuid


def strip_special(line):
    return ''.join([c for c in str(line) if c in string.printable])


def run_command(cmd, stdin=None, sudo=False, **kwargs):
    logging.debug('Running command: %s', cmd)
    if sudo:
        logging.info('Sudo command running')
        cmd = ['sudo'] + cmd
    logging.debug('Stdin: %s', stdin)
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         **kwargs)
    stdout, stderr = p.communicate(stdin)
    rc = p.wait()

    logging.debug('Return code: %s', rc)
    logging.debug('Stdout: %s', stdout)
    logging.debug('Stderr: %s', stderr)

    if rc != 0:
        raise Exception('Command failed, status: %s, out: %s, err: %s'
                        % (rc, stdout, stderr))

    return stdout.decode('utf-8'), stderr.decode('utf-8')


class LoopDiskManager(object):
    numbytes = None
    dest = None
    devpath = None
    mountpath = None
    f = None

    def __init__(self, numbytes, dest):
        self.numbytes = numbytes
        self.dest = dest

    def __enter__(self):
        self.f = tempfile.NamedTemporaryFile(
                dir=os.path.dirname(self.dest),
                suffix='_hlimg',
                delete=True)
        self.f.seek(self.numbytes - 1)
        self.f.write(b'\0')
        self.f.seek(0)

        devpath, err = run_command([
                'losetup',
                '--find',
                '--show',
                self.f.name,
            ],
            sudo=True)
        self.devpath = devpath.strip()

        run_command([
                'mkfs.vfat',
                self.devpath,
            ],
            sudo=True)

        mountpath = tempfile.mkdtemp(prefix='sb_test_mnt_')
        run_command([
                'mount',
                self.devpath,
                mountpath,
            ],
            sudo=True)
        self.mountpath = mountpath

        return mountpath

    def __exit__(self, exc_type, exc_value, traceback):
        if self.mountpath:
            run_command([
                    'umount',
                    self.mountpath,
                ],
                sudo=True)
            os.rmdir(self.mountpath)

        if self.devpath is not None:
            run_command([
                    'losetup',
                    '--detach',
                    self.devpath,
                ],
                sudo=True)

        if exc_type is None:
            os.link(self.f.name, self.dest)
        self.f.close()


def generate_qemu_cmd(args):
    machinetype = 'q35'
    machinetype += ',accel=%s' % ('kvm' if args.enable_kvm else 'tcg')
    return [
        args.qemu_binary,
        '-machine', machinetype,
        '-display', 'none',
        '-no-user-config',
        '-nodefaults',
        '-m', '256',
        '-nic', 'none',
        '-smp', '2,sockets=2,cores=1,threads=1',
        '-chardev', 'pty,id=charserial1',
        '-device', 'isa-serial,chardev=charserial1,id=serial1',
        '-global', 'driver=cfi.pflash01,property=secure,value=off',
        '-drive',
        'file=%s,if=pflash,format=raw,unit=0,readonly=on' % (
            args.ovmf_binary),
        '-drive',
        'file=%s,if=pflash,format=raw,unit=1,readonly=off' % (
            os.path.join(args.workdir, 'ovmf_vars.fd')),
        '-serial', 'stdio',
        '-hda', os.path.join(args.workdir, 'test.img'),
        '-boot', 'menu=on,order=c,strict=on']


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workdir', help='Working directory. Default: temporary')
    parser.add_argument('--print-output', help='Print the QEMU guest output',
                        action='store_true')
    parser.add_argument('--verbose', '-v', help='Increase verbosity',
                        action='count')
    parser.add_argument('--quiet', '-q', help='Decrease verbosity',
                        action='count')
    parser.add_argument('--qemu-binary', help='QEMU binary path',
                        default='/usr/bin/qemu-system-x86_64')
    parser.add_argument('--enable-kvm', help='Enable KVM acceleration',
                        action='store_true')
    parser.add_argument('--ovmf-binary', help='OVMF secureboot code file',
                        default='/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd')
    parser.add_argument('--ovmf-template-vars', help='OVMF empty vars file',
                        default='/usr/share/edk2/ovmf/OVMF_VARS.fd')
    parser.add_argument('--ovmf-really-secboot',
                        help='Assume the OVMF binary is secureboot capable',
                        action='store_true')
    parser.add_argument('--ovmf-vars-really-secboot',
                        help='Assume the OVMF vars is secureboot capable',
                        action='store_true')

    parser.add_argument('--cert-to-efi-sig-list', help='c-to-esl binary',
                        default='cert-to-efi-sig-list')
    parser.add_argument('--sign-efi-sig-list', help='esl-sign binary',
                        default='sign-efi-sig-list')

    parser.add_argument('--test-signed',
                        help='Ensure the shim is trusted by pre-enrolled vars',
                        action='store_true')
    parser.add_argument('shim_path', metavar='shim-path',
                        help='Specify a shim binary to test')
    parser.add_argument('grub2_path', metavar='grub2-path',
                        help='Specify a grub2 efi binary to test')
    parser.add_argument('kernel_path', metavar='kernel-path',
                        help='Specify a kernel efi binary to test')
    args = parser.parse_args()
    validate_args(args)
    return args


def validate_args(args):
    if not os.path.exists(args.shim_path):
        raise Exception('Shim path invalid')
    if not os.path.exists(args.grub2_path):
        raise Exception('Grub2 path invalid')
    if not os.path.exists(args.kernel_path):
        raise Exception('Kernel path invalid')
    if not os.path.exists(args.qemu_binary):
        raise Exception('Qemu path invalid')
    if not os.path.exists(args.ovmf_binary):
        raise Exception('OVMF code path invalid')
    if 'secboot' not in args.ovmf_binary and not args.ovmf_really_secboot:
        raise Exception('OVMF binary is likely not secureboot enabled')
    if not args.test_signed:
        if 'secboot' in args.ovmf_template_vars:
            raise Exception('OVMF template vars likely pre-enrolled. Use empty vars')
    else:
        if 'secboot' not in args.ovmf_template_vars and not args.ovmf_vars_really_secboot:
            raise Exception('OVMF vars file is likely not secureboot enrolled')

    verbosity = (args.verbose or 1) - (args.quiet or 0)
    level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity < 0:
        level = logging.ERROR
    logging.basicConfig(level=level)


def generate_keys(args):
    keyuuid = uuid.uuid1().hex
    keygeneration = time.time()
    keytypes = {'PK': 'Platform Key',
                'KEK': 'Key Exchange Key',
                'db': 'Database Key'}

    logging.debug('Generating keys')
    for keytype in keytypes:
        keyname = keytypes[keytype]
        run_command([
                'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', '%s.key' % keytype,
                '-new',
                '-x509',
                '-sha256',
                '-days', '2',
                '-subj', '/CN=SBTEST %d %s/' % (keygeneration, keyname),
                '-out', '%s.crt' % keytype],
            cwd=args.workdir)

    logging.debug('Converting certs to ESLs')
    for keytype in keytypes:
        run_command([
                args.cert_to_efi_sig_list, '-g', keyuuid, '-k',
                '%s.crt' % keytype,
                '%s.esl' % keytype],
            cwd=args.workdir)


    logging.debug('Converting certs to DER')
    for keytype in keytypes:
        run_command([
                'openssl',
                'x509',
                '-outform', 'DER',
                '-inform', 'PEM',
                '-in', '%s.crt' % keytype,
                '-out', '%s.der' % keytype],
            cwd=args.workdir)

    logging.debug('Generating db P12 file')
    run_command([
            'openssl', 'pkcs12', '-export', '-out', 'db.p12',
            '-inkey', 'db.key', '-in', 'db.crt',
            '-passout', 'pass:test',
            '-name', 'dbkey'],
        cwd=args.workdir)

    logging.debug('Generating NSS database')
    run_command(['modutil',
        '-create', '-dbdir', 'sql:%s' % args.workdir,
        '-force'])
    run_command([
        'pk12util',
        '-i', '%s/db.p12' % args.workdir,
        '-d', 'sql:%s' % args.workdir,
        '-W', 'test'])


def sign_shim(args):
    out, _ = run_command(['pesign', '-S', '-i', args.shim_path])
    if 'No signatures found.' not in out:
        raise Exception('Shim binary was pre-signed')
    run_command([
        'pesign', '--sign', '-c', 'dbkey', '-n', 'sql:%s' % args.workdir,
        '-i', args.shim_path,
        '-o', os.path.join(args.workdir,
                           'shimx64.signed.efi')])


def test_shim_signature(args):
    out, _ = run_command([
        'pesign', '-S',
        '-i', os.path.join(args.workdir, 'shimx64.signed.efi')])
    if 'No signatures found.' in out:
        raise Exception('Shim binary was not signed')


def generate_disk(args):
    with LoopDiskManager(20*1024*1024,
                         os.path.join(args.workdir, 'test.img')) as disk:
        logging.debug('Generated loopback disk at: %s', disk)
        tocopy = []
        for fname in os.listdir(args.workdir):
            if fname.endswith('.der'):
                tocopy.append((os.path.join(args.workdir, fname),
                               os.path.join(disk, fname)))

        tocopy.append((os.path.join(args.workdir, 'shimx64.signed.efi'),
                       os.path.join(disk, 'shimx64.signed.efi')))
        tocopy.append((args.grub2_path,
                       os.path.join(disk, 'grubx64.efi')))
        tocopy.append((args.kernel_path,
                       os.path.join(disk, 'kernelx64.efi')))

        for copy in tocopy:
            # This copy must run as root, because vfat does not have
            # permissions
            run_command(['cp', *copy], sudo=True)

        logging.debug('Files on test disk: %s', os.listdir(disk))


def enroll_keys(args):
    shutil.copy(args.ovmf_template_vars,
                os.path.join(args.workdir, 'ovmf_vars.fd'))
    if args.test_signed:
        logging.debug('Assuming OVMF vars are enrolled')
    else:
        logging.debug("Starting VM to process enrollment")
        cmd = generate_qemu_cmd(args)
        p = subprocess.Popen(cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        read = p.stdout.readline()
        if b'char device redirected' in read:
            read = p.stdout.readline()


        # Actions:
        # 1. Wait for "BdsDxe: Press any key..."
        # 2. Press any key
        # 3. Wait for "Select Language"
        # 4. Press down 1 times (Device Manager), press enter
        # 5. Wait for "iSCSI Configuration"
        # 6. Press down 2 times (Secure Boot Configuration), press enter
        # 7. Wait for "Secure Boot Mode"
        # 8. Press down 1 times (Standard Mode), press enter, press down (Custom mode), press enter
        # 9. Press down (Custom Secure Boot Options), press enter
        # 10. Wait for "DBT Options"
        # 11. Press down 2 times ("DB Options"), press enter
        # 12. Wait for "Enroll Signature"
        # 13. Press enter
        # 14. Wait for "Enroll Signature Using File"
        # 15. Press enter
        # 16. Wait for "NO VOLUME LABEL"
        # 17. Press enter
        # 18. Wait for "db.der"
        # 19. Press down 3 times ("db.der"), press enter
        # 20. Wait for "Commit Changes"
        # 21. Press down 2 times ("Commit Changes"), press enter
        # 22. Wait for "DBT Options"
        # 23. Press up 1 times ("KEK Options"), press enter
        # 24. Wait for "Enroll KEK"
        # 25. Press enter
        # 26. Wait for "Enroll KEK using File"
        # 27. Press enter
        # 28. Wait for "NO VOLUME LABEL"
        # 29. Press enter
        # 30. Wait for "KEK.der"
        # 31. Press down 4 times ("KEK.der"), press enter
        # 32. Wait for "Commit Changes"
        # 33. Press down 2 times ("Commit Changes"), press enter
        # 34. Wait for "DBT Options"
        # 35. Press up 1 times ("PK Options"), press enter
        # 36. Wait for "Enroll PK"
        # 37. Press enter
        # 38. Wait for "Enroll PK Using File"
        # 39. Press enter
        # 40. Wait for "NO VOLUME LABEL"
        # 41. Press enter
        # 42. Wait for "PK.der"
        # 43. Press down 5 times ("PK.der"), press enter
        # 44. Wait for "Commit Changes"
        # 45. Press down 1 time ("Commit Changes"), press enter
        # 46. Wait for "DBT Options"
        # 47. Press Esc
        # 48. Wait for "Current Secure Boot State"
        # 49. Assure that "Enabled" is displayed
        # 50. Terminate VM


        raise NotImplementedError('Enrolling not yet implemented')


def test_boot(args):
    pass


def main():
    args = parse_args()
    temp_workdir = False
    if not args.workdir:
        temp_workdir = True
        args.workdir = tempfile.mkdtemp(prefix='sb_test_workdir_')
        logging.debug('Working directory: %s', args.workdir)

    if args.test_signed:
        # Assume the shim binary is fully signed
        logging.debug('Assuming shim is fully signed')
        shutil.copy(args.shim_path,
                    os.path.join(args.workdir, 'shimx64.signed.efi'))
    else:
        generate_keys(args)
        sign_shim(args)
    test_shim_signature(args)
    generate_disk(args)
    enroll_keys(args)
    test_boot(args)


    if temp_workdir:
        logging.debug('Deleting temporary directory')
        shutil.rmtree(args.workdir)


if __name__ == '__main__':
    main()
