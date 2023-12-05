# reversetunnel, a pair of programs to connect to remote servers behind dynamic ips

## Overview

I have a linux machine connected to a camera. It's behind a firewall and a
dynamic ip in a remote location. I'd like to ssh into it occasionally for
maintenance.

Normally, to connect to a remote machine, I'd need to track the dynamic ip and
set up port forwarding rules on the remote firewall. With this program, there's
no need for that.

This is a pair of programs. One runs on the remote machine with a dynamic ip
and one runs on my local server with a fixed ip. The dynamic program connects
to the fixed program and waits for me to connect. When I want to access the
remote machine, I can ssh to my local server and this creates a connection
to sshd on the remote machine. Data is proxied back and forth transparently.

Multiple remote dynamic programs can connect to one local static program. This
is limited by --maxtunnels.

I use this on linux but it should run on other unix systems.

## Installing

After downloading the source with "git clone https://github.com/sanjayrao77/reversetunnel"
you can try to build it with a simple "make". If successful, this will make "fixed\_rtunnel" for
the local server and "dynamic\_rtunnel" for the remote server.

You'll need GNU TLS headers and libraries installed. On my Raspbian, I can do an "apt-get install libgnutls28-dev".

On non-linux systems, you may need to make small modifications.

## Usage

You'll need to compile this on your local server and your remote server(s).

Your local server will run fixed\_rtunnel and your remote servers will run dynamic\_rtunnel.

You'll need to allow the remote server IPs on fixed\_rtunnel, then allow at least one client ip
as well to allow you to connect to it as a user.

For more information, see the example below.

## Security

TLS is used to encrypt connections between remote fixed\_rtunnel and dynamic\_rtunnel. The password
is sent over TLS.

The connection between dynamic\_rtunnel and its server (e.g. sshd) is **not**
encrypted. This is intended to be a loopback connection and encryption isn't
needed for that.

The connection between the user and fixed\_rtunnel is **not** encrypted. This allows transparent
access for the client and is intended to be run on a local network. If you use ssh (the default),
the link will be encrypted at the protocol layer. If you need encryption here for a different service,
you could create an ssh tunnel between your client computer and the fixed\_rtunnel computer.

There are whitelists on fixed\_rtunnel to allow access only from specific IP addresses. By default,
nothing is allowed, so you'll need to allow IPs before anything works.

Be sure to set a password with --password for both fixed\_rtunnel and dynamic\_rtunnel. Passwords
are exactly 16 hexadecimal characters.

## Command line arguments for dynamic\_rtunnel

dynamic\_rtunnel runs on the remote server and connects to fixed\_rtunnel. After a matching client connection is made to fixed\_rtunnel,
dynamic\_rtunnel connects to a local service and proxies data.

### --hostname=HOSTNAME

This will set "HOSTNAME" in the listing for connections in fixed\_rtunnel. This is so the user can keep track of multiple
copies of dynamic\_rtunnel.

### --password=HEXADECIMALPASSWORD

The password should be 16 characters, in hexadecimal format. This defines a 256bit password. This needs to match
the password for fixed\_rtunnel. This password is encrypted over TLS when it is sent.

### --remoteip=IP

This specifies the IPv4 address for the remote fixed\_rtunnel machine. This is required.

### --remoteport=PORT

This specifies the port for the remote fixed\_rtunnel program. The default is 632. If you use a different port on fixed\_rtunnel,
then this should match.

### --localport=PORT

This specifies the port for the local service to connect to. The default value is 22, for sshd.

### --localip=IP

This specifies the IPv4 address for the local service to connect to. The default value ias 127.0.0.1, for the same machine.

### --alarm=SECONDS

If you'd like the program to reconnect periodically, you can specify a number of seconds here. The default is one hour
but it can be disabled by setting it to 0.

Note that this can also kill active tunnels, so you may be interrupted while connecting to it.

### --verbose

This prints extra information to syslog or stderr.

### --notroot

When running as root, this will drop to user "nobody" for safety. To disable this, you can specify --notroot to
tell it you're not running as root.

### --debug

This runs in the foreground, uses stderr instead of syslog and enables --verbose.

## Command line arguments for fixed\_rtunnel

fixed\_rtunnel runs on your local server with a fixed ip and waits for connections. You'll need to allow IP addresses for
clients and dynamic\_rtunnel instances.

### --list-tunnels

This is one of the most useful commands.

This will connect to the local fixed\_rtunnel process and list the connections established with remote dynamic\_rtunnel servers.

This requires access to the unix domain socket, which can be specified with --socketname.

You can kill individual tunnels by killing the associated pid.

You can connect to tunnels by connecting to the port number listed.

### --list-allowed-tunnels
 
This will connect to the local fixed\_rtunnel process and list the remote IPv4 addresses which are allowed to connect
with dynamic\_rtunnel.

This requires access to the unix domain socket, which can be specified with --socketname.

### --list-allowed-clients
 
This will connect to the local fixed\_rtunnel process and list the local IPv4 addresses which are allowed to connect
from client programs (e.g. ssh).

This requires access to the unix domain socket, which can be specified with --socketname.

### --lastip-client
 
This will connect to the local fixed\_rtunnel process and list the last IPv4 address which has attempted to connect
as a client program.

This is useful for authorizing clients. If your client is being blocked, you can check this value and then
allow it with --addip-client.

This requires access to the unix domain socket, which can be specified with --socketname.

### --lastip-tunnel
 
This will connect to the local fixed\_rtunnel process and list the last IPv4 address which has attempted to connect
as a remote dynamic\_rtunnel.

This is useful for authorizing remote tunnels. If your dynamic\_rtunnel is being blocked, you can check this value and then
allow it with --addip-tunnel.

This requires access to the unix domain socket, which can be specified with --socketname.

### --addip-tunnel=IPv4

This will connect to the local fixed\_rtunnel process and add an IPv4 address to the list allowing connections from remote
dynamic\_rtunnel programs.

This requires access to the unix domain socket, which can be specified with --socketname.

### --addip-client=IPv4

This will connect to the local fixed\_rtunnel process and add an IPv4 address to the list allowing connections from local
clients (e.g. ssh).

This requires access to the unix domain socket, which can be specified with --socketname.

### --password=HEXADECIMALPASSWORD

The password should be 16 characters, in hexadecimal format. This defines a 256bit password. This needs to match
the password for dynamic\_rtunnel. This password is encrypted over TLS when it is received.

### --clientinterface=IPv4

To restrict clients to a specific interface, you can set the interface's IP address here.

This is not important from a security standpoint, but it does prevent unknown
public computers from wasting some resources.

### --socketname=FILENAME

This specifies the filename for storing the unix domain socket for communicating with a running fixed\_rtunnel program.

The default is /var/run/rtunnel.socket, which won't work if you're not root. You could use /tmp/USER.rtunnel.socket
in a pinch.

Different systems will set different limits on its length.

### --port=PORT

This specifies the public port we should listen on for remote dynamic\_rtunnel programs. The default is 632 if we're
running as root and 6321 if we're not.

### --maxtunnels=NUMBER

This specifies the number of simultaneous tunnels allowed. The default is 5. You'll want to increase this if you have
more than 5 computers connect.

If you set this too high, you may see lots of processes sitting around from bots probing
your ports.

### --keyfile=FILENAME

This specifies the file that holds the private key for TLS.

You can generate such a file with "certtool --generate-privkey --outfile fixed.key", using the GNU TLS utility.

### --certfile=FILENAME

This specifies the file that holds the certificate for TLS.

You can generate such a file with "certtool --generate-self-signed --load-privkey fixed.key --outfile fixed.cert",
given a "fixed.key" key file (see --keyfile).

### --notroot

fixed\_rtunnel should be run as root. This is needed to reserve a port (below 1000). Your remote programs may not find
the server if it's not running on a fixed port.

However, if you can't run it as root, you can use --notroot. This prevents dropping to user "nobody" and it switches
to port 6321. It also uses /tmp/rtunnel.socket as a default control socket. Anyone who can write to this file can reconfigure
the whitelists.

### --verbose

This prints extra information to syslog or stderr.

### --debug

This runs in the foreground and enables --verbose.

## TLS

You'll need to create a TLS certificate for the server.
The default filenames are certs/fixed.key and certs/fixed.cert but you can override that with --keyfile and --certfile.

I use "certtool" from gnutls. You could probably use other tools instead.

```
mkdir certs
certtool --generate-privkey --outfile certs/fixed.key
certtool --generate-self-signed --load-privkey certs/fixed.key --outfile certs/fixed.cert
```

When making a certificate, you can use the default value (just press Enter) for everything but
the expiration. For the expiration, you could enter "999" or similar.

## Example

In this example we have "Computer A", "Computer B" and "Computer C". 

Computer A is your desktop, using ip 192.168.1.3 on a private network.

Computer B is your local server, using public ip 1.2.3.4 and private ip 192.168.1.2.

Computer C is running behind a firewall on a dynamic ip and is remote.

### Example: Installing fixed\_rtunnel on Computer B

Step 1:
First, download the source code with "git clone https://github.com/sanjayrao77/reversetunnel".
Install GNU TLS development files if needed and run "make".


Step 2:
Create the TLS private key and certificate:
```
mkdir -p certs
cd certs/
certtool --generate-privkey --outfile fixed.key
certtool --generate-self-signed --load-privkey fixed.key --outfile fixed.cert
```

Step 3:
Run the "fixed" server and allow IPs. For now, we'll run it as a user, but it would be best if run as root.
```
./fixed_rtunnel --notroot
# the program should now be running in the background
# it should be listening on port 6321 for tunnels
# it should be listening on /tmp/rtunnel.socket for configuration
./fixed_rtunnel --notroot --addip-client=192.168.1.3
# it's important to allow client IPs before we allow remote tunnels
# otherwise, we'd need to kill the tunnel for it to reload the client whitelist
```

### Example: Installing dynamic\_rtunnel on Computer C

Step 1:
First, download the source code with "git clone https://github.com/sanjayrao77/reversetunnel".
Install GNU TLS development files if needed and run "make".

Step 2:
Run the "dynamic" server and have it phone home.
```
# normally we use port 632 but --notroot uses 6321 as a default
./dynamic_rtunnel --remoteip=1.2.3.4 --remoteport=6321 --notroot --debug 
```

Now, dynamic\_rtunnel will attempt to connect to fixed\_rtunnel but it'll fail as it's not in
the whitelist.

### Example: Adding dynamic\_rtunnel to the fixed\_rtunnel whitelist

On Computer B, run "fixed\_rtunnel --notroot --lastip-tunnel". It should print the IP of Computer C.
This can change in the future since Computer C has a dynamic IP. For the example, let it be 2.3.4.5.

Now, run "fixed\_rtunnel --notroot --addip-tunnel=2.3.4.5". This will allow dynamic\_rtunnel to
get through and make a connection.

After it's connected (a few seconds later), run "fixed\_rtunnel --notroot --list-tunnels".

You'll see something like this:
```
Tunnel: pid:3698 port:38173 remoteip:2.3.4.5 hostname:computerc timestamp:Thu Nov 16 19:20:28 2023
```

### Example: Connect to remote sshd

On Computer A, you can now run "ssh ssh://192.168.1.2:38173" where 38173 is the port displayed in the
previous example.

Computer B will allow Computer A because 192.168.1.3 was added to its client whitelist.

A packet to port 38173 will be forwarded to 2.3.4.5 where it'll be forwarded to port 22.

When done, just exit ssh and dynamic\_rtunnel will reconnect to fixed\_rtunnel with a new port number.

