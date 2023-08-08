# Leaking VPN Client Traffic by Abusing Routing Tables

[<img align="right" src="tunnelcrack.png" width="200px">](https://tunnelcrack.mathyvanhoef.com/)

<a id="id-intro"></a>
## [1. Introduction](#id-intro)

We discovered two new traffic leak attacks against VPN clients. Based on our own experiments
against 66 VPN clients this appears to be a general issue in many VPN clients. For more
information, see our [TunnelCrack website](https://tunnelcrack.mathyvanhoef.com/) and our
[paper](https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf).

This README describes how to test VPN clients for these new traffic leak attacks.
A high-level description of the attacks can be found below, and after this background we
explain how you can test VPN clients.

You can use the following Bibtex entry to cite our work:

	@inproceedings{usenix2023-tunnelcrack,
	  author = {Nian Xue and Yashaswi Malla and Zihang Xia and Christina P\"opper and Mathy Vanhoef},
	  title = {Bypassing Tunnels: Leaking {VPN} Client Traffic by Abusing Routing Tables},
	  booktitle = {Proceedings of the 32th {USENIX} Security Symposium},
	  year = {2023},
	  month = {August},
	  publisher = {{USENIX} Association}
	}

<a id="id-explanation"></a>
## [2. Vulnerability Details](#id-explanation)

Our attacks manipulate the client's [routing table](http://linux-ip.net/html/ch-routing.html)
such that traffic will be sent outside the VPN tunnel, i.e., without encryption.
Normally, when the VPN is not enabled, a client's routing table might look like the following:

    [mathy@zbook-mathy ~]$ ip route
    default via 192.168.1.1 dev wlp0s20f3
    192.168.1.0/24 dev wlp0s20f3 scope link

The IP address of the client in this example is `192.168.1.101`. The two output lines mean:

- The first line says that by _default_ all outgoing IP packets are forwarded _via 192.168.1.1_.
  Here 192.168.1.1 is the router. The rule also specifies `dev wlp0s20f3` meaning the packets
  are sent over the `wlp0s20f3` Wi-Fi network card. All combined, all outgoing IP packets are
  by default sent to the router using the Wi-Fi network card.

- The second line is [an exception](http://linux-ip.net/html/routing-selection.html)
  to the above rule: all IP packets to 192.168.1.0/24, so to IP addresses between 192.168.1.0
  and 192.168.1.255, are sent over `dev wlp0s20f3`. So they're sent over the Wi-Fi network card.
  Moreover, `scope link` means these IP addresses are directly reachable: the packets can
  directly be sent to their destination instead of first being forwarded to the router.

When a VPN is enabled, a client's routing table might look like this:

	[mathy@zbook-mathy ~]$ ip route
	default via 10.8.0.1 dev tun0
	76.26.140.111 via 192.168.1.1 dev wlp0s20f3
	192.168.1.0/24 dev wlp0s20f3 scope link

Here the IP address of the VPN server is `76.26.140.111`. The first rule says
that by _default_, all outgoing IP packets are sent over `dev tun0`. Here `tun0` is a
virtual network card representing the encrypted VPN tunnel. In other words, by default
all packets are sent through the VPN tunnel. There are two exceptions:

1. The second rule says that packets with as destination the VPN server must be sent to
   the router using the Wi-Fi network card. This exception avoids a rooting loop where
   already-encrypted VPN packets would otherwise get encrypted again.

2. The third rule is the same as when the VPN wasn't enabled: all packets to the local
   network (notice the `scope link`) are directly transmitted over the Wi-Fi network card
   to the destination (so not through the VPN tunnel). This assures that local devices in
   the network, such as printers, remain accessible when using the VPN.


<a id="id-localnet"></a>
### [2.1. LocalNet Attacks](#id-attack1)

Our LocalNet attacks abuse the routing exception to the local network, with as main
goal to leak traffic in plaintext outside the VPN tunnel. For example, to leak traffic to
216.165.47.10, the adversary acts as a rogue Wi-Fi network, and for instance advertises the
IP range 216.165.47.0/24 for the local network. As a result, the VPN client will send all
packets to the local network, so all IP packets with as destination 216.165.47.0/24, in
plaintext outside the VPN tunnel.

The [Testing LocalNet Attacks](#id-localnet) section to test VPN clients for
these LocalNet attacks.


<a id="id-serverip"></a>
### [2.2. ServerIP Attacks](#id-attack2)

Our ServerIP attacks abuse the routing exception to the VPN server's IP address,
with as main goal to leak traffic in plaintext outside the VPN tunnel. When not combined
with DNS spoofing, a vulnerable VPN client will leak all traffic to the VPN server's IP
address in plaintext. On its own this has low impact.

However, when a client uses plaintext DNS to look up the VPN server's IP address, traffic
to any IP address can be leaked. For example, when the VPN client looks up the IP address
of the VPN server by sending a plaintext DNS request to get the IP address of `server1.vpn.com`,
the adversary can spoof the DNS response to return any IP address, e.g., 216.165.47.10.
As a result, all traffic to 216.165.47.10 will now be sent outside the VPN tunnel (see
the above routing background).

The instructions under [Testing ServerIP Attacks](id-serverip) can be used to test
VPN clients for these ServerIP attacks.


<a id="id-createap"></a>
## [3. Creating an Access Point](#id-createap)

We used the `create_ap` tool to create a Wi-Fi network for the tests. The generic installation
instructions are available [online](https://github.com/oblique/create_ap#installation). On some
Linux distributions you can install it using the package manager. On Ubuntu you need to install
the following dependencies:

	sudo apt install hostapd wireshark

A standard AP can be created using the command:

	sudo create_ap wlan1 wlan0 testnetwork abcdefgh

This will create a Wi-Fi network called testnetwork with password abcdefgh. The arguments wlan1
and wlan0 depend on your machine:

- The argument wlan0 refers to your builtin network card and may be different on your machine. Find
  out this name by executing `ip addr` and picking the interface that is assigned an IP address.

- The argument wlan1 refers to the Wi-Fi dongle you plugged in. Find out its name on your machine
  by executing `ip addr` before and after plugging in the Wi-Fi dongle and seeing which interface
  was added.

You should now be able to connect to the created Wi-Fi network. To inspect the traffic of any client
connect to the AP start Wireshark and listen for packets on the `ap0` interface (or on the interface
of the Wi-Fi dongle in case it doesn’t support virtual interfaces).

Errors and warnings:

- If you get the error "ERROR: Failed to initialize lock" then execute `sudo rm /tmp/create_ap.all.lock`.

- If you get the warning "Your adapter does not fully support AP virtual interface" this means your
  Wi-Fi dongle cannot simultaneously act as a client and AP. This shouldn’t be a problem in our experiments,
  but if you can't start the Wi-Fi network, try using a different Wi-Fi dongle.


<a id="id-testlocalnet"></a>
## [4. Testing LocalNet Attacks](#id-testlocalnet)

A quick-and-dirty method to test for this vulnerability is to make your router hand out
non-RFC1918 IP addresses for the local network, e.g., using `216.165.47.0/24` for the
local network. Then enable the VPN and try to visit `http://nyu.edu` or directly visit
`http://216.165.47.10`. This should have as result that the NYU website won't load and
in Wireshark you should see ARP requests for the IP address `216.165.47.10`.

Alternatively, start the `create_ap` script to hand out public IP addresses. For example,
if we want to intercept traffic to `nyu.edu`, which has IP address `216.165.47.10`, the
hotspot has to hand out IP addresses from a subnet that contains that IP address. This
can be done by starting `create_ap` as follows:

	sudo create_ap wlan1 wlan0 testnetwork abcdefgh -g 216.165.47.10

Now connect with the created AP and enable the VPN client. Open Wireshark. Then try to
visit `http://216.165.47.10` in a browser. If you see TCP SYN packets to `216.165.47.10`
it means the VPN app is vulnerable: you can use the Wireshark filter `tcp.flags.syn == 1`
to easily filter for plaintext TCP SYN packets.

Some additional notes:

- The adversary can also use 0.0.0.0/1 or similar for the local network to leak nearly all
  IP-based traffic.

- We found that some VPN clients will not leak traffic but instead _block_ traffic to the
  target website/subnet. We still consider this a security risk. For instance, the attack
  can then be abused to: (1) block the IP address of an update service; (2) prevent the
  lookup of revoked TLS certificates; (3) prevent modern browsers from contacting servers
  that can tell whether a website is safe to visit; or (4) Block other security-sensitive
  services.

- With Windows clients, we found that when the website is blocked, Windows may still send
  ARP requests for the IP address being contacted. This is a privacy risk because it can
  be abused to identify when a victim is trying to visit a specific IP address or website.
  
  We conjecture that this is because the Windows firewall was configured to block _packets_
  to local IP addresses, but was not configured to block the initiation of _connections_
  to local IP addresses.


<a id="id-testserverip"></a>
## [5. Testing ServerIP Attacks](id-testserverip)

Start the `create_ap` script and then connect with the device being tested:

	sudo create_ap wlan1 wlan0 testnetwork abcdefgh

Now start capturing frames on `ap0`. After starting to capture frames, connect to the
VPN server and then use Wireshark to identify the VPN server's IP address. Then visit
`http://$VPN_SERVERIP`. If you cannot see plaintext TCP SYNs in Wireshark then the VPN
client cannot be vulnerable (you can use the Wireshark filter `tcp.flags.syn == 1` to
easily filter for plaintext TCP SYN packets). If the VPN protocol is using TCP or UDP
then also try to visit `http://$VPN_SERVERIP:$PORT` where you add the port used by the
server.

In case you _do_ see a plaintext TCP SYN packet, the next step is to test whether the
VPN client used plaintext DNS to find the VPN server's IP address. To determine this,
you can use the Wireshark filter `dns.a == $VPN_SERVERIP`. If you see any results, then
the VPN client is highly likely to be vulnerable.

Some additional notes:

- We found that the VPN protocol being used (OpenVPN, IPsec, WireGuard, etc) may influence
  whether there are plaintext leaks towards the VPN server's IP address.

- Some VPN clients will only leak traffic on specific ports. You can check this manually by
  browsing to `http://SERVERIP:PORT` and using Wireshark with the filter `tcp.port == PORT`
  to detect plaintext TCP SYN packets to this port. For instance, the VPN client might only
  leak traffic on the same port as used by the encrypted VPN tunnel.

- In rare occasions, the selected server in the VPN client may also affect the result of the
  test. This was for example the case when testing Cisco AnyConnect.


<a id="id-changelog"></a>
## [6. Change Log](id-changelog)

- 8 August 2023: Updated the README to have all the instructions in a single markdown file.
  The version submitted to the USENIX Security Artifact Evaluation can be found under
  the tag [`usenix-ae`](https://github.com/vanhoefm/vpnleaks/tree/usenix-ae).

