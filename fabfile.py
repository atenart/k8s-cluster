from contextlib import contextmanager as _cm
import os
import shutil
import tempfile

from fabric.api import *

bindir = os.path.dirname(os.path.realpath(__file__)) + '/bin'
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
