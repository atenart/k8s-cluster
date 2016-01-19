from contextlib import contextmanager as _cm
import os
import shutil
from StringIO import StringIO
import tempfile

from fabric.api import *
from fabric.contrib.files import append

env.user = 'core'
env.colorize_errors = True

rootdir = os.path.dirname(os.path.realpath(__file__))
bindir = rootdir + '/bin'
clusterdir = os.getcwd()

'''
CA setup
'''
@_cm
def _tmpdir():
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir)

def _make_cfssl_config(outdir, cn):
    open('%s/ca-csr.json' % outdir, 'w').write('''
{
    "CN": "%s",
    "key": {
        "algo": "rsa",
        "size": 4096
    }
}
''' % cn)

    open('%s/ca-config.json' % outdir, 'w').write('''
{
    "signing": {
        "default": {
            "expiry": "43800h",
            "usages": [ "server auth", "client auth" ]
        }
    }
}
''')

def _gen_ca(outdir, cn):
    outdir = os.path.join(clusterdir, outdir)
    with _tmpdir() as tmpdir, lcd(tmpdir):
        _make_cfssl_config(outdir=tmpdir, cn=cn, filename='tmp')

        # generate a certificate authority in 'outdir'
        local('%s/cfssl gencert -initca ca-csr.json | %s/cfssljson -bare ca -' % (bindir, bindir))
        local('cp ca.pem ca-key.pem %s' % outdir)

def _gen_cert(outdir, cadir, cn, prefix, ip=None):
    outdir = os.path.join(clusterdir, outdir)
    cadir = os.path.join(clusterdir, cadir)

    if ip is not None:
        extra_args = '-hostname=%s' % ip
    else:
        extra_args = '-profile=client'

    with _tmpdir() as tmpdir, lcd(tmpdir):
        _make_cfssl_config(outdir=tmpdir, cn=cn, filename='tmp')

        # generate a certificate signed by the CA in 'cadir'
        local('%s/cfssl gencert -ca %s/ca.pem -ca-key=%s/ca-key.pem %s '
              '-config=ca-config.json tmp.json | %s/cfssljson -bare %s -'
              % (bindir, cadir, cadir, extra_args, bindir, prefix))
        local('cp %s.pem %s-key.pem %s' % (prefix, prefix, outdir))

def gen_certificates():
    """Generate the trusted certificates in ca/"""
    if os.path.exists('ca'):
        abort('Certificates already generated')

    os.makedirs('ca/ssh', mode=0700)
    os.makedirs('ca/etcd/peering', mode=0700)
    os.makedirs('ca/etcd/client', mode=0700)
    os.makedirs('ca/kubernetes', mode=0700)

    # generate SSH certificate authority
    local('ssh-keygen -b 4096 -f ca/ssh/machine_ca -C machine-ca')
    local('ssh-keygen -b 4096 -f ca/ssh/user_ca -C user-ca')

    # add the public SSH certificate to the known hosts on the local machine
    ca = '@cert-authority * %s' % open('ca/ssh/machine_ca.pub').read()
    f = os.path.expanduser('~/.ssh/known_hosts')
    known_hosts = open(f).read().splitlines()
    if ca not in known_hosts:
        known_hosts.append(ca)
        with open(f, 'w') as f_w:
            f_w.write('\n'.join(known_hosts))

    # generate the Etcd certificate authority
    _gen_ca(outdir='ca/etcd/peering', cn='Etcd peering CA')
    _gen_ca(outdir='ca/etcd/client', cn='Etcd client CA')

    # generate the Kubernetes certificate authority and admin certificate
    _gen_ca(outdir='ca/kubernetes', cn='Kubernetes CA')
    _gen_cert(outdir='ca/kubernetes', cadir='ca/kubernetes', cn='Kubernetes admin', prefix='admin')

def sign_ssh_key(path, name='cluster admin'):
    '''Sign an SSH key with the cluster CA'''
    key = os.path.expanduser(path)
    if not os.path.isfile(key) or not key.endswith('.pub'):
        abort('No public key to sign')

    local('ssh-keygen -s ca/ssh/user_ca -n root,core -I "%s" %s' % (name, key))

'''
CoreOS setup
'''
def _networkd_config(iface, address, gateway):
    return '''
[Match]
Name=%s

[Network]
Address=%s
Gateway=%s
DNS=8.8.8.8
DNS=4.4.4.4
''' % (iface, address, gateway)

def _configure_coreos(hostname, address, gateway):
    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/mnt'):
        # set the hostname
        put(StringIO(hostname), 'etc/hostname', use_sudo=True)

        # setup the SSH server
        sudo('rm -f etc/ssh/sshd_config')
        sudo('cp /usr/share/ssh/sshd_config etc/ssh/sshd_config')

        # generate and sign the SSH keys
        sudo('chroot . /usr/bin/ssh-keygen -A')
        get(remote_path='etc/ssh/ssh_host_*_key.pub', local_path=tmpdir, use_sudo=True)

        for pubkey in os.listdir(tmpdir):
            local('ssh-keygen -s %s/ca/ssh/machine_ca -I %s -h %s' % (clusterdir, hostname, pubkey))
            append('etc/ssh/sshd_config', 'HostCertificate /etc/ssh/%s-cert.pub' % pubkey[:-4], use_sudo=True)

        put('*-cert.pub', 'etc/ssh', mode=0644, use_sudo=True)
        sudo('chown root:root etc/ssh/*-cert.pub')

        # allow the admins to connect
        authority = 'cert-authority %s' % open(os.path.join(clusterdir, 'ca/ssh/user_ca.pub')).read()

        sudo('mkdir -p -m 0700 root/.ssh')
        put(StringIO(authority), 'root/.ssh/authorized_keys', mode=0600, use_sudo=True)
        sudo('chown -R root:root root/.ssh')

        sudo('mkdir -p -m 0700 home/core/.ssh')
        put(StringIO(authority), 'home/core/.ssh/authorized_keys', mode=0600, use_sudo=True)
        sudo('chown -R core:core home/core/.ssh')

        # set the update strategy
        append('etc/coreos/update.conf', 'REBOOT_STRATEGY=etcd-lock', use_sudo=True)
        append('etc/profile.d/locksmithd.sh', 'export LOCKSMITHD_REBOOT_WINDOW_START=3:00', use_sudo=True)
        append('etc/profile.d/locksmithd.sh', 'export LOCKSMITHD_REBOOT_WINDOW_LENGTH=30m', use_sudo=True)

        # setup the network
        ret = sudo('ip route | grep default | sed \'s/.*dev \\([a-z]\\+[0-9]\\+\\) .*/\\1/\'')
        iface = ret.stdout.strip()
        put(StringIO(_networkd_config(iface, address, gateway)),
            'etc/systemd/network/10-static.network', use_sudo=True)

def bootstrap_replica(hostname=None, address=None, gateway=None, device='/dev/sda', channel='beta'):
    '''Install and configure a CoreOS replica'''
    if hostname is None or address is None or gateway is None:
       abort('incorrect parameters')

    # Install CoreOS on the (virtual?) machine
    sudo('coreos-install -d %s -C %s' % (device, channel))

    @_cm
    def _mount():
        sudo('mount %s9 /mnt' % device)
        sudo('mount -o bind /dev /mnt/dev')
        sudo('mount -o bind /usr /mnt/usr')
        yield
        sudo('umount -R /mnt')

    with _mount():
        _configure_coreos(hostname=hostname, address=address, gateway=gateway)

    with warn_only():
        reboot()
