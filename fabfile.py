from contextlib import contextmanager as _cm
import os
import shutil
import socket
from StringIO import StringIO
import tempfile
import time

from fabric.api import *
from fabric.contrib.files import append, sed
from fabric.contrib.project import rsync_project

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

def _get_host_ip():
    try:
        socket.inet_aton(env.host)
        return env.host
    except socket.error:
        return local('dig +short %s' % env.host, capture=True).stdout.strip()

def _make_cfssl_config(outdir, cn, filename='ca-csr'):
    open('%s/%s.json' % (outdir, filename), 'w').write('''
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
        _make_cfssl_config(outdir=tmpdir, cn=cn)

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
    os.makedirs('ca/registry', mode=0700)

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

    # generate the Docker registry certificate authority
    _gen_ca(outdir='ca/registry', cn='Docker registry CA')
    _gen_cert(outdir='ca/registry', cadir='ca/registry', cn='Docker registry client',
              prefix='client')

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

def _systemd_env(env):
    return '[Service]\n' + '\n'.join('Environment=%s=%s' % (k, v) for k,v in env.iteritems())

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

'''
Etcd setup
'''
def _etcd_make_cert(ip, kind):
    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/etc/etcd'):
        _gen_cert(outdir=tmpdir, cadir='ca/etcd/%s' % kind, cn=ip, prefix=kind, ip=ip)

        put('%s-key.pem' % kind, '%s-key.pem' % kind, use_sudo=True)
        sudo('chmod 600 %s-key.pem' % kind)

        put('%s.pem' % kind, '%s.pem' % kind, use_sudo=True)
        put('%s/ca/etcd/%s/ca.pem' % (clusterdir, kind), '%s.ca' % kind, use_sudo=True)
        sudo('cat %s.ca >> %s.pem' % (kind, kind))
        sudo('chmod 644 %s.pem %s.ca' % (kind, kind))

def _etcd_setup_service(ip):
    sudo('mkdir -p /etc/systemd/system/etcd2.service.d')

    env = {
        'ETCD_LISTEN_PEER_URLS'     : 'https://%s:2380' % ip,
        'ETCD_LISTEN_CLIENT_URLS'   : 'https://%s:2379,http://127.0.0.1:2379' % ip,
        'ETCD_ADVERTISE_PEER_URLS'  : 'https://%s:2380' % ip,
        'ETCD_ADVERTISE_CLIENT_URLS': 'https://%s:2379' % ip,
        'ETCD_PEER_CERT_FILE'       : '/etc/etcd/peering.pem',
        'ETCD_PEER_KEY_FILE'        : '/etc/etcd/peering-key.pem',
        'ETCD_PEER_CA_FILE'         : '/etc/etcd/peering.ca',
        'ETCD_CERT_FILE'            : '/etc/etcd/client.pem',
        'ETCD_KEY_FILE'             : '/etc/etcd/client-key.pem',
        'ETCD_PEER_CLIENT_CERT_AUTH': 'true',
    }
    put(StringIO(_systemd_env(env)), '/etc/systemd/system/etcd2.service.d/env.conf', use_sudo=True)

    append('[Service]\nExecStart=\nExecStart=/usr/bin/etcd2',
           '/etc/systemd/system/etcd2.service.d/2.2.conf', use_sudo=True)

    sudo('mkdir -p /etc/profile.d')
    append('/etc/profile.d/etcd.sh', 'export ETCDCTL_CA_FILE=/etc/etcd/client.ca', use_sudo=True)

def _etcd_setup_first_replica(ip, mid):
    env = {
        'ETCD_INITIAL_CLUSTER'              : '%s=https://%s:2380' % (mid, ip),
        'ETCD_INITIAL_CLUSTER_STATE'        : 'new',
        'ETCD_INITIAL_ADVERTISE_PEER_URLS'  : 'https://%s:2380' % ip,
    }
    put(StringIO(_systemd_env(env)), '/etc/systemd/system/etcd2.service.d/bootstrap.conf', use_sudo=True)

def _etcd_setup_additional_replica(ip, mid):
    peers = ['%s=https://%s:2380' % (mid, ip)]

    for l in local('./etcdctl member list', capture=True).stdout.strip().splitlines():
        name, peer = None, None
        for w in l.strip().split():
            if w.startswith('name='):
                name = w.split('=', 1)[1]
            elif w.startswith('peerURLs='):
                peer = w.split('=', 1)[1]

        if name is None or peer is None:
            abort('Bad parse of the etcd member list')

        peers.append('%s=%s' % (name, peer))

    env = {
        'ETCD_INITIAL_CLUSTER'              : ','.join(peers),
        'ETCD_INITIAL_CLUSTER_STATE'        : 'existing',
        'ETCD_INITIAL_ADVERTISE_PEER_URLS'  : 'https://%s:2380' % ip,
    }
    put(StringIO(_systemd_env(env)), '/etc/systemd/system/etcd2.service.d/bootstrap.conf', use_sudo=True)

    local('./etcdctl member add %s https://%s:2380' % (mid, ip))

def _etcd_endpoints():
    endpoints = []
    for l in run('etcdctl --ca-file=/etc/etcd/client.ca member list').stdout.strip().splitlines():
        for w in l.split():
            if not w.startswith('clientURLs='):
                continue
            endpoints.append(w.split('=', 1)[1])
    return ','.join(endpoints)

def _etcd_setup_wrapper():
    wrapper = '#!/bin/bash\n../bin/etcdctl --ca-file=ca/etcd/client/ca.pem -C %s $@' % _etcd_endpoints()
    open('etcdctl', 'w').write(wrapper)
    local('chmod +x etcdctl')

def _setup_etcd(proxy=False):
    machine_id = run('cat /etc/machine-id').stdout.strip()
    ip = _get_host_ip()

    sudo('mkdir -p -m 0755 /etc/etcd')
    _etcd_make_cert(ip, 'peering')
    _etcd_make_cert(ip, 'client')
    sudo('chown etcd:root /etc/etcd/*')

    _etcd_setup_service(ip)

    if not os.path.isfile('etcdctl'):   # first replica
        _etcd_setup_first_replica(ip, machine_id)
    elif not proxy:                     # additional replica
        _etcd_setup_additional_replica(ip, machine_id)
#    else:                               # proxy
#        _etcd_setup_proxy(ip, machine_id)

    sudo('systemctl daemon-reload')
    sudo('systemctl enable etcd2.service')
    sudo('systemctl start etcd2.service')

    # wait for the etcd daemon to be up and running
    with settings(warn_only=True):
        while run('etcdctl --ca-file=/etc/etcd/client.ca ls').failed:
            time.sleep(1)

    sudo('rm -f /etc/systemd/system/etcd2.service.d/bootstrap.conf')
    sudo('systemctl daemon-reload')

    # locally setup/update a wrapper to connect to the etcd cluster
    _etcd_setup_wrapper()

'''
Fleet setup
'''
def _fleet_endpoints():
    endpoints = []
    for l in run('fleetctl --ca-file=/etc/etcd/client.ca list-machines').stdout.strip().splitlines():
        for w in l.split():
            try:
                socket.inet_aton(w)
                endpoints.append(w)
            except socket.error:
                continue
    return endpoints

def _fleet_setup_wrapper():
    endpoints = _fleet_endpoints()
    wrapper = '#!/bin/bash\n'
    # poor's man HA. Yerk :<
    for r in endpoints:
        wrapper += 'nc -z %s 2379 &>/dev/null\n' % r
        wrapper += 'if [ $? -eq 0 ]; then\n'
        wrapper += '../bin/fleetctl --ca-file=ca/etcd/client/ca.pem --endpoint=https://%s:2379 $@\n' % r
        wrapper += 'exit $?\n'
        wrapper += 'fi\n'
    open('fleetctl', 'w').write(wrapper)
    local('chmod +x fleetctl')

def _setup_fleet():
    append('/etc/profile.d/etcd.sh', 'export FLEETCTL_CA_FILE=/etc/etcd/client.ca', use_sudo=True)

    sudo('systemctl enable fleet.service')
    sudo('systemctl start fleet.service')

    # wait for the fleet daemon to be up and running
    with settings(warn_only=True):
        while run('fleetctl --ca-file=/etc/etcd/client.ca status').failed:
            time.sleep(1)

    # locally setup/update a wrapper to connect to the fleet cluster
    _fleet_setup_wrapper()

'''
Flanneld setup
'''
def _setup_flanneld(network='10.10.0.0/16', netmask=24):
    with settings(warn_only=True):
        if local('./etcdctl get /coreos.com/network/config').failed:
            local('./etcdctl set /coreos.com/network/config '
                  '\'{"Network":"%s","SubnetLen":%d,"Backend":{"Type":"host-gw"}}\'' %
                  (network, netmask))

    append('/etc/profile.d/etcd.sh', 'export FLANNELD_ETCD_CAFILE=/etc/etcd/client.ca', use_sudo=True)

    sudo('mkdir -p /etc/systemd/system/docker.service.d')
    dependency = '[Unit]\nRequires=flanneld.service\nAfter=flanneld.service'
    put(StringIO(dependency), '/etc/systemd/system/docker.service.d/40-flannel.conf', use_sudo=True)

    sudo('systemctl daemon-reload')

'''
Kubernetes setup
'''
def _kubernetes_push_manifests(kind, ip, k8s_master):
    sudo('mkdir -p /etc/kubernetes/manifests')
    with settings(user='root'):
        rsync_project(local_dir='%s/k8s_manifests/%s/*' % (rootdir, kind),
                      remote_dir='/etc/kubernetes/manifests', delete=True)

    for f in run('for i in /etc/kubernetes/manifests/*; do echo $i; done').split():
        sed(f, 'ETCD_ENDPOINTS', _etcd_endpoints(), backup='', use_sudo=True)
        sed(f, 'ADVERTISE_IP', ip, backup='', use_sudo=True)
        sed(f, 'MASTER_HOST', k8s_master, backup='', use_sudo=True)
        sed(f, 'K8S_SERVICE_IP', '10.20.0.0/16', backup='', use_sudo=True)

def _kubernetes_master():
    if not os.path.isfile('kubectl'):
        return 'https://%s' % _get_host_ip()

    import re
    regex = re.compile(r'\x1b[^m]*m')

    for w in local('./kubectl cluster-info', capture=True).stdout.strip().split():
        w = regex.sub('', w)
        if w.startswith('http'):
            return w
    return None

def _kubernetes_setup_master(ip):
    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/etc/kubernetes/ssl'):
        _gen_cert(outdir=tmpdir, cadir='ca/kubernetes', cn=ip, prefix='apiserver', ip=ip)
        _gen_cert(outdir=tmpdir, cadir='ca/kubernetes', cn=ip, prefix='worker', ip=ip)

        # API server certs
        put('apiserver-key.pem', 'apiserver-key.pem', use_sudo=True)
        sudo('chmod 600 apiserver-key.pem')

        put('apiserver.pem', 'apiserver.pem', use_sudo=True)
        put('%s/ca/kubernetes/ca.pem' % clusterdir, 'ca.pem', use_sudo=True)
        sudo('cat ca.pem >> apiserver.pem')
        sudo('chmod 644 apiserver.pem ca.pem')

        # worker certs
        put('worker-key.pem', 'worker-key.pem', use_sudo=True)
        sudo('chmod 600 worker-key.pem')

        put('worker.pem', 'worker.pem', use_sudo=True)
        sudo('cat ca.pem >> worker.pem')
        sudo('chmod 644 worker.pem ca.pem')

        sudo('chown root:root *.pem')

    kubelet_service = ('[Service]\n'
                       'ExecStart=/usr/bin/kubelet \\\n'
                       '  --api-servers=http://127.0.0.1:8080 \\\n'
                       '  --register-node=false \\\n'
                       '  --allow-privileged=true \\\n'
                       '  --config=/etc/kubernetes/manifests \\\n'
                       '  --hostname-override=%s\\\n'
                       '  --cluster-dns=10.20.0.42 \\\n'
                       '  --cluster-domain=cluster\n'
                       'Restart=always\n'
                       'RestartSec=10\n'
                       '[Install]\n'
                       'WantedBy=multi-user.target') % ip
    put(StringIO(kubelet_service), '/etc/systemd/system/kubelet.service', use_sudo=True)

    sudo('systemctl daemon-reload')
    sudo('systemctl enable kubelet.service')
    sudo('systemctl start kubelet.service')

    # wait for Kubelet to be up and running
    with settings(warn_only=True):
        while run('curl http://127.0.0.1:8080/version').failed:
            time.sleep(15)

    # add the 'kube-system' namespace
    run('curl -XPOST -d\'{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system"}}\' '
        '"http://127.0.0.1:8080/api/v1/namespaces"')

def _kubernetes_setup_worker(ip, apiserver):
    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/etc/kubernetes/ssl'):
        _gen_cert(outdir=tmpdir, cadir='ca/kubernetes', cn=ip, prefix='worker', ip=ip)

        put('worker-key.pem', 'worker-key.pem', use_sudo=True)
        sudo('chmod 600 worker-key.pem')

        put('worker.pem', 'worker.pem', use_sudo=True)
        put('%s/ca/kubernetes/ca.pem' % clusterdir, 'ca.pem', use_sudo=True)
        sudo('cat ca.pem >> worker.pem')
        sudo('chmod 644 worker.pem ca.pem')

        sudo('chown root:root *.pem')

    kubelet_service = ('[Service]\n'
                        'ExecStart=/usr/bin/kubelet \\\n'
                        '  --api-servers=%s \\\n'
                        '  --register-node=true \\\n'
                        '  --allow-privileged=true \\\n'
                        '  --config=/etc/kubernetes/manifests \\\n'
                        '  --hostname-override=%s \\\n'
                        '  --cluster-dns=10.20.0.42 \\\n'
                        '  --cluster-domain=cluster \\\n'
                        '  --kubeconfig=/etc/kubernetes/worker-kubeconfig.yaml \\\n'
                        '  --tls-cert-file=/etc/kubernetes/ssl/worker.pem \\\n'
                        '  --tls-private-key-file=/etc/kubernetes/ssl/worker-key.pem\n'
                        'Restart=always\n'
                        'RestartSec=10\n'
                        '[Install]\n'
                        'WantedBy=multi-user.target') % (apiserver, ip)
    put(StringIO(kubelet_service), '/etc/systemd/system/kubelet.service', use_sudo=True)

    sudo('systemctl daemon-reload')
    sudo('systemctl enable kubelet.service')
    sudo('systemctl start kubelet.service')

def _kubernetes_setup_wrapper(master):
    wrapper = ('#!/bin/bash\n'
               '../bin/kubectl --server=https://%s --certificate-authority=ca/kubernetes/ca.pem \\\n'
               '    --client-key=ca/kubernetes/admin-key.pem --client-certificate=ca/kubernetes/admin.pem \\\n'
               '    --username=admin $@\n') % master
    open('kubectl', 'w').write(wrapper)
    local('chmod +x kubectl')

def _setup_kubernetes():
    ip = _get_host_ip()
    master = _kubernetes_master()
    sudo('mkdir -p -m 0755 /etc/kubernetes/ssl')

    kubeconfig = ('apiVersion: v1\n'
                  'kind: Config\n'
                  'clusters:\n'
                  '- name: local\n'
                  '  cluster:\n'
                  '    certificate-authority: /etc/kubernetes/ssl/ca.pem\n'
                  'users:\n'
                  '- name: kubelet\n'
                  '  user:\n'
                  '    client-certificate: /etc/kubernetes/ssl/worker.pem\n'
                  '    client-key: /etc/kubernetes/ssl/worker-key.pem\n'
                  'contexts:\n'
                  '- context:\n'
                  '    cluster: local\n'
                  '    user: kubelet\n'
                  '  name: kubelet-context\n'
                  'current-context: kubelet-context')
    put(StringIO(kubeconfig), '/etc/kubernetes/worker-kubeconfig.yaml', use_sudo=True)

    if not os.path.isfile('kubectl'):   # master
        _kubernetes_push_manifests('master', ip, master)
        _kubernetes_setup_master(ip)
        _kubernetes_setup_wrapper(ip)
        _setup_registry()
    else:                               # worker
        _kubernetes_push_manifests('worker', ip, master)
        _kubernetes_setup_worker(ip, master)
        _setup_kubernetes_addons()

    _docker_registry_access(ip, master.split('//', 1)[1])

'''
Kubernetes add-ons
'''
def _setup_kubernetes_addons():
    # DNS add-on
    with settings(warn_only=True):
        if run('dig @10.20.0.42 kubernetes.default.cluster').failed:
            local('./kubectl create -f %s/k8s_addons/dns-addon.yaml' % rootdir)

            # wait for the DNS add-on to be up and running
            while run('dig @10.20.0.42 kubernetes.default.cluster').failed:
                time.sleep(15)

'''
Docker registry pod setup
'''
def _setup_registry():
    ip = _get_host_ip()

    # put the pod manifest
    put('%s/registry/docker-registry.yaml' % rootdir, '/etc/kubernetes/manifests', use_sudo=True)

    # add the nginx configuration
    sudo('mkdir -p -m 0755 /etc/registry')
    put('%s/registry/nginx.conf' % rootdir, '/etc/registry', use_sudo=True)

    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/etc/registry'):
        _gen_cert(outdir=tmpdir, cadir='ca/registry', cn=ip, prefix='registry', ip=ip)

        put('registry-key.pem', 'registry-key.pem', use_sudo=True)
        sudo('chmod 600 registry-key.pem')

        put('registry.pem', 'registry.pem', use_sudo=True)
        put('%s/ca/registry/ca.pem' % clusterdir, 'ca.pem', use_sudo=True)
        sudo('cat ca.pem >> registry.pem')
        sudo('chmod 644 registry.pem ca.pem')

        sudo('chown root:root *.pem')

    sudo('systemctl daemon-reload')
    sudo('systemctl restart kubelet.service')

    # add the private registry certs to the local Docker instance
    local('sudo mkdir -p -m 0755 /etc/docker/certs.d/%s:5000' % ip)
    local('sudo cp %s/ca/registry/ca.pem /etc/docker/certs.d/%s:5000/ca.crt' % (clusterdir, ip))
    local('sudo cp %s/ca/registry/client.pem /etc/docker/certs.d/%s:5000/client.cert' % (clusterdir, ip))
    local('sudo cp %s/ca/registry/client-key.pem /etc/docker/certs.d/%s:5000/client.key' % (clusterdir, ip))

def _docker_registry_access(ip, master):
    sudo('mkdir -p -m 0755 /etc/docker/certs.d/%s:5000' % master)

    with _tmpdir() as tmpdir, lcd(tmpdir), cd('/etc/docker/certs.d/%s:5000' % master):
        _gen_cert(outdir=tmpdir, cadir='ca/registry', cn='Registry client %s' % ip, prefix='client', ip=ip)

        put('client-key.pem', 'client.key', use_sudo=True)
        sudo('chmod 600 client.key')

        put('%s/ca/registry/ca.pem' % clusterdir, 'ca.crt', use_sudo=True)
        put('client.pem', 'client.cert', use_sudo=True)
        sudo('chmod 644 ca.crt client.cert')

        sudo('chown root:root *')

'''
Replica setup
'''
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

    _setup_etcd()
    _setup_fleet()
    _setup_flanneld()
    _setup_kubernetes()
