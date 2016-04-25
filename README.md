# k8s cluster

Bootstraps a CoreOS cluster from scratch, on top of which Kubernetes
will run to manage our pods.

The installation should be as automated as possible. We also need to generate a
few certificate authorities, to secure our cluster communications and
authentications.

## Overview

Once CoreOS is installed, three services are setup: Etcd (Distributed reliable
key-value store), Fleet (low-level distributed init) and Flannel (network
fabric for containers). Etcd and Flannel are needed to run Kubernetes, Fleet is
enabled to allow starting core services outside the Kubernetes management.

We then setup Kubernetes, with currently a single master node. The DNS add-on is
added, to easily lookup the Kubernetes services.

Finally a private Docker registry is started inside the cluster, to host our
Docker images.

## Usage

**Requirements**. We need some binaries to be available: *cfssl*, *cfssljson*,
*etcdctl*, *fleetctl* and *kubectl*. Retrieve or build them and create a *bin/*
directory to store the binaries. You also need to install *Fabric*.

1. Create a directory to host our cluster-specific files:
	```
	$ mkdir cluster-<name>
	$ cd cluster-<name>
	```

1. Generate the trusted certificates:
	```
	$ fab -f ../fabfile.py gen_certificates
	```

1. Sign your SSH key:
	```
	$ fab -f ../fabfile.py sign_ssh_key:path=~/.ssh/id_rsa.pub
	```

1. For each node, run:
	```
	$ fab -f ../fabfile.py -H <node> \
		bootstrap_replica:hostname=<node_hn>,address=<node_addr>/<cidr>,gateway=<node_gw>
	```

Local wrappers will be created in the current directory, to communicate with the
cluster: *docker*, *etcdctl*, *fleetctl* and *kubectl*.

## Use the private Docker registry

```
docker tag <image> <k8s master ip>:5000/<name>
docker push <k8s master ip>:5000/<name>
```

## TODO

- Etcd proxy support.
- More than one Kubernetes master.
- A Kubernetes upgrade mechanism.
