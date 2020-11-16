# Interacting with sysctl in OpenShift
When deploying any pods/containers on to Kubernetes or OpenShift, they should be deployed with minimal privilege, minimal access to capabilities and avoiding root (0) user where possible.

Due to needing to deploy containers that likely need some kernel parameters being amended (cough, cough, SonarQube because of ElasticSearch...) I wanted to look to make the deployment as secure as possible with regards to security contexts.

## Sysctl
Sysctl is is described [here](https://linux.die.net/man/8/sysctl):

> sysctl is used to modify kernel parameters at runtime. The parameters available are those listed under /proc/sys/. Procfs is required for sysctl support in Linux. You can use sysctl to both read and write sysctl data. 

### sysctl.c code
The sysctl.c code is located [here](https://github.com/torvalds/linux/blob/master/kernel/sysctl.c):

I was keen to understand if CAP_SYS_ADMIN is required to make sysctl changes. There are only two references to `CAP_SYS_ADMIN` in kernel v3.10 (this version was looked at as it is the kernel on the hosts in the OpenShift cluster I'm using).

```
/*
 * Taint values can only be increased
 * This means we can safely use a temporary.
 */
static int proc_taint(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long tmptaint = get_taint();
	int err;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;
```

and

```
ifdef CONFIG_PRINTK
static int proc_dointvec_minmax_sysadmin(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;
```

#### The 'capable' function
Some detail regarding the `capable` function is detailed [here](http://www.cis.syr.edu/~wedu/seed/Documentation/Linux/How_Linux_Capability_Works.pdf):

The function `capable(<CAPABILITY_NAME>)` checks whether the current process has `<CAPABILITY_NAME>` as an effective capability. 

These two links define `capable` as a function (however note kernel version is `2.6.15.6`), so we need to check the version applicable to us:
 - [security.c](https://elixir.bootlin.com/linux/v2.6.15.6/source/security/security.c#L186)
 - [sched.h](https://elixir.bootlin.com/linux/v2.6.15.6/source/include/linux/sched.h#L1109)

Perform `oc describe node <node_name> | grep Kernel` to show kernel version on node being used:
```
oc describe node <node_name> | grep Kernel
 Kernel Version:  3.10.0-1160.2.2.el7.x86_64
```

Therefore we need to find where this function is declared in kernel v3.10. Some detail given here: https://elixir.bootlin.com/linux/v3.10/source/kernel/capability.c#L419
```
/**
 * capable - Determine if the current task has a superior capability in effect
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */

#### proc_taint
`kernel.tainted` will is a non-zero value if the kernel has been tainted. Values can be viewed [here](https://sysctl-explorer.net/kernel/tainted/).

Effectively, 'tainted' means that the kernel is in a state other than what it would be in if it were built fresh from the open source origin and used in a way that it had been intended. It is a way of flagging a kernel to warn people (e.g., developers) that there may be unknown reasons for it to be unreliable, and that debugging it may be difficult or impossible.

#### proc_dointvec_minmac_sysadmin
`proc_dointvec_minmac_sysadmin` is related to `dmesg_restrict`. The `dmesg` command is used to see or control the kernel ring buffer.

> `kernel.demsg_restrict` indicates whether unprivileged users are prevented from using dmesg to view messages from the kernel’s log buffer. 
When dmesg_restrict is set to (0) there are no restrictions. When dmesg_restrict is set set to (1), users must have CAP_SYSLOG to use dmesg.

As stated [here](https://lwn.net/Articles/414813/):

> The kernel syslog contains debugging information that is often useful during exploitation of other vulnerabilities, such as kernel heap addresses. 
Rather than futilely attempt to sanitize hundreds (or thousands) of printk statements and simultaneously cripple useful debugging functionality, it is far simpler to create an option that prevents unprivileged users from reading the syslog.

As per [here](https://lore.kernel.org/patchwork/patch/241060/)

> When dmesg_restrict is set to 1 CAP_SYS_SYSLOG is needed to read the kernel ring buffer. But a root user without CAP_SYS_ADMIN is able to reset dmesg_restrict to 0. 
This is an issue when e.g. LXC (Linux Containers) are used and complete user space is running without CAP_SYS_ADMIN. A unprivileged and jailed root user can bypass the dmesg_restrict protection. With this patch writing to dmesg_restrict is only allowed when root has CAP_SYS_ADMIN.

#### sysctl.c summary
It appears that the capability `CAP_SYS_ADMIN` is only required for changes related to tainting and vieing kernel syslog.

## Docker Prvileged mode
Docker privileged mode is detailed [here](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities):

> When the operator executes docker run `--privileged`, Docker will enable access to all devices on the host as well as set some configuration in AppArmor or SELinux to allow the container nearly all the same access to the host as processes running outside containers on the host.

## Namespaced vs Node-level Sysctls
It is worth a read of [this](https://unofficial-kubernetes.readthedocs.io/en/latest/concepts/cluster-administration/sysctl-cluster/#namespaced-vs-node-level-sysctls), which states (amongst other things):
> The following sysctls are known to be namespaced:
>   - kernel.shm*,
>   - kernel.msg*,
>   - kernel.sem,
>   - fs.mqueue.*,
>   - net.*.
>
> Sysctls which are not namespaced are called node-level and must be set manually by the cluster admin, either by means of the underlying Linux distribution of the nodes (e.g. via /etc/sysctls.conf) or using a DaemonSet with privileged containers.

In the example script in this repo, the sysctls are:
 - vm.max_map_count
 - fs.file-max

Neither of which fall into the "namespaced" category.

## Tests performed:
The following tests have been performed to check settings:

| Pod SC fsGroup | Pod SC runAsUser | sysctl runAsUser | sysctl privileged | defaultAddCapabilities | requiredDropCapabilities | sysctl -n Result | sysctl -w Result                                                     |
|----------------|------------------|------------------|-------------------|------------------------|--------------------------|------------------|----------------------------------------------------------------------|
| `1000`         | `1000`           | `1001`           | `true`            | `[]`                   | (not incl. SYS_ADMIN)    | sysctl read      | sysctl: error setting key 'vm.max_map_count': Permission denied      |
| `1000`         | `1000`           | `0`              | `true`            | `[]`                   | (not incl. SYS_ADMIN)    | sysctl read      | sysctl successfully set                                              |
| `1000`         | `1000`           | `1001`           | `false`           | `SYS_ADMIN`            | (not incl. SYS_ADMIN)    | sysctl read      | sysctl: error setting key 'vm.max_map_count': Read-only file system  |
| `1000`         | `1000`           | `0`              | `false`           | `SYS_ADMIN`            | (not incl. SYS_ADMIN)    | sysctl read      | sysctl: error setting key 'vm.max_map_count': Read-only file system  |
| `1000`         | `1000`           | `0`              | `true`            | `[]`                   | (incl. SYS_ADMIN)        | sysctl read      | sysctl successfully set                                              |
| `1000`         | `1000`           | `0`              | `true`            | `[]`                   | `ALL`                    | sysctl read      | sysctl successfully set                                              |

(Note: `sysctl -n` is used to read the setting, `-n` disables printing of the key name when printing values. `sysctl -w` is used to write a sysctl setting change).

*Summary:* Testing has given the following outcomes:
 - SYS_ADMIN capability alone is not sufficient to make sysctl changes as `/proc/sys` is only made available with read permission (note: SYS_ADMIN is not actually required for the specific sysctls being changed above.
 - When testing with `prvilieged:true`, it has been shown that root (0) user must be used other permission is denied.
 - The privileged setting makes `/proc/sys` available with write permission.
 - It also appears that no capabilities are required for sysctls to be set, just root user and privileged container.

## Use of SCCs when trying to make sysctl calls from a container
To make non-namespaced sysctl calls, a container must be `privileged`. Keen to avoid over-assigning privilege and to minimise attack vector, this config uses an SCC where:
 - all capabilities must be dropped (`requiredDropCapabilities: -ALL`)
 - access to the underlying host IPC, network, PID, posts and directory volume plugin are not permitted 

SecurityContexts allow for some granularity of configuration between the pods, initContainers and containers within. Therefore in this example, the Pod is configured with `fsGroup:1000` and `runAsUser: 1000`, the initContainer will run privileged (`privileged: true`) and as user root/0 (`runAsUser: 0`). 
The container `main-container` isn't configured with any securityContexts to override the pod settings and so inherits them.

The volume `init-sysctl`  is mounted at `/tmp/scripts` with user=root and group=1000 (the latter due to the pod setting `fsGroup:1000`). Further to this, due to this configuration in the deployment.yaml:
```
      volumes:
      - name: init-sysctl
        configMap:
          name: matt-sysctl
          items:
            - key: init_sysctl.sh
              path: init_sysctl.sh
```

The file `init_sysctl.sh` is present in the `/tmp/scripts` directory. It is created with user and group both being root.

The initContainer is configured to create some logs, this can be viewed via: `oc logs <pod_name> -c init-sysctl` and with the correct settings, will give results similar to:
```
uid=0(0) gid=0(root) groups=10(wheel),1000
total 16
drwxrwsrwx    3 root     1000          4096 Nov 14 16:45 .
drwxrwxrwt    1 root     root          4096 Nov 14 16:45 ..
drwxr-sr-x    2 root     1000          4096 Nov 14 16:45 ..2020_11_14_16_45_12.427726936
lrwxrwxrwx    1 root     root            31 Nov 14 16:45 ..data -> ..2020_11_14_16_45_12.427726936
lrwxrwxrwx    1 root     root            21 Nov 14 16:45 init_sysctl.sh -> ..data/init_sysctl.sh
sysctl -n vm.max_map_count =  524288
sysctl -n fs.file-max =  131072
vm.max_map_count = 524288
fs.file-max = 131072
ulimit -n 131072
ulimit -u 8192
vm.max_map_count = 524288
1048576
vm.max_map_count=524288
```

## Mounted secret assigned user & group
Currently looking into why the mounted secret is `root:root` rather than having the same group applied as fsGroup does on the volume itself. This seems to be related: https://github.com/kubernetes/kubernetes/issues/81089 but I cannot find the explanation regarding the K8s functionality/reasoning that is causing this to happen. Although you can set the file permissions on the secret, as per [here](https://kubernetes.io/docs/concepts/configuration/secret/#secret-files-permissions), it looks as though there isn't yet the functionality to set user or group and this is what the referenced [github issue](https://github.com/kubernetes/kubernetes/issues/81089) is potentially seeking to do.