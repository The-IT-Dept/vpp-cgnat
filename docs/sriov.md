# Running the pair on SR-IOV VFs

Measured on the production pair (two Proxmox VMs on one host, Intel 82599
10G ports), SR-IOV virtual functions give the CGNAT about **7× the packet
rate of DPDK on virtio and 15× the kernel path**, on the same two worker
cores. This page covers the layout we run, what VPP needs for it, and the
failover lessons that only showed up once the NICs were VFs.

## Throughput

The test node had 2 workers on pinned host cores. A DPDK generator VM sent
64-byte UDP from 4096 subscribers × 63 flows (258k flows) through a test map,
and counted what came back translated.

| offered | forwarded | note |
|---|---|---|
| 0.13–1.2 Mpps | all | |
| 1.96 Mpps | all | **lossless ceiling, about 2.0 Mpps** |
| 2.90 Mpps | 2.80 Mpps (96%) | workers saturating |
| 4.0 Mpps | 2.91 Mpps | **peak, about 2.9 Mpps** |
| 5.8 Mpps | 2.85 Mpps | holds at the peak, no collapse |

- **Where it stops:** the two CGNAT workers run out of CPU. At the peak, vectors are full (256 packets per call) and in2out costs about 670 and 1,000 clocks per packet on the two workers. The NIC never dropped on receive (`rx-miss` 0). The excess is shed at the handoff between workers ("handoff queue full"), so overload degrades gracefully.
- **What it means:** 2.0 Mpps lossless is about 14 Gb/s at a typical ~900-byte average packet, more than the 10G port carries. On SR-IOV the port, not the CGNAT, is the limit for real traffic. More workers raise the 64-byte ceiling.

### Against the other ways into a VM

Same generator and test, all with 2 workers:

| node, I/O | lossless up to | best forwarded | limited by |
|---|---|---|---|
| cgnat-1, **SR-IOV VFs** (DPDK) | **~2.0 Mpps** | **~2.9 Mpps** | CGNAT worker CPU |
| cgnat-2, DPDK on virtio | 280 kpps | 426 kpps | host vhost-net/OVS (virtio TX failures) |
| cgnat-1, DPDK on virtio | 255 kpps | 477 kpps | host vhost-net/OVS |
| cgnat-1, `af_packet` (kernel virtio-net) | 130 kpps | 172 kpps | guest kernel; collapses to 99 kpps at 1 Mpps offered |

On virtio the CGNAT had headroom at 1,100–1,500 clocks per packet and
vectors far from full: the host's software switching was the ceiling.
SR-IOV removes the host from the data path.

## Layout

- **VFs:** each of the host's two 10G ports (the members of the host bond to the router) has 16 VFs. One VF per VLAN per port goes to each VM as a PCI device. The host sets each VF's VLAN (host-enforced; see VLAN strip below), its MAC, `trust on` and `spoofchk off`.
- **Bond in VPP:** the two VFs of a VLAN (one per port) form a VPP bond, `create bond mode xor load-balance l34 hw-addr <VF MAC>`. Both VFs carry the same MAC.
  - The router hashes its LAG across both ports, so the VM must accept on either. That rules out active-backup.
  - LACP inside the VM would clash with the host's own LACP on the same ports. That rules out LACP.
- **Pair link:** a VLAN between the two VMs' VFs. VF-to-VF on the same port is switched inside the NIC.
- **Spare VFs:** two VFs per VM on a test VLAN pair, plus a generator VM, make the throughput test above repeatable without touching production interfaces.

## What VPP needs

- **VLAN strip on receive.** With a host-enforced VLAN, the 82599 VF inserts the tag on transmit but hands received frames to the guest still tagged unless the guest asks for stripping. VPP 26.06 has no option for that, so frames arrive as "unknown vlan" and are dropped. [`patches/vpp-26.06-dpdk-vlan-strip.patch`](../patches/vpp-26.06-dpdk-vlan-strip.patch) adds a per-device option:

  ```
  dpdk {
    dev 0000:05:00.0 { name inside-a  vlan-strip-offload on }
    ...
  }
  ```

  It must be on each `dev` line. It doesn't apply from `dev default`. `scripts/apply-patches.sh` applies it with the other two VPP patches (time and BFD; see the [README](../README.md#building-and-testing)).
- **VF link state can't be forced** on ixgbe. A VF's link follows its port. A VF whose port has no carrier is down, and its bond carries on with the other member.

## Failover lessons from VFs

On virtio every link was up the instant VPP started, and failover lost about
one ping per event. On VFs, three timing gaps appeared. The plugin now
handles all three.

1. **The pair VF gets link before its address is usable.** A node that only waited a dead interval after start could declare itself alone before it ever heard its peer. Now `starting` lasts until the pair interface has link, then until the peer is heard on it, or a dead interval plus 1.5 s.
2. **Data VFs get link seconds after the pair VF.** A node could go ready and take its subscribers back from its peer while its inside or outside VF was still down. Now a node is `interface-down` (not ready) while any translating interface is admin-down or has no link. In service, losing an uplink hands everything to the peer, and the node resyncs before serving again.
3. **BFD holds VPP's own next hops down.** A single-hop BFD session makes VPP's FIB treat its neighbour as down until the session is up: `admin-down`, `down` and `init` all count as down. With routing glue that only enables BFD once the node is ready, a rejoining node was ready, took its subscribers, and dropped them into unresolved routes for the one or two BFD slow-start rounds (about 3.4 s). Now a node is ready for routing (BFD may come up), but it only tells its peer READY, and so takes subscribers, once every neighbour on its translating interfaces is up. `show cgnat cluster` prints `next hops: down` in between.

A related operational trap: `bfd udp session set-flags ... admin up` on a
session that is already up resets it, and the router sees a flap. The glue
script ([`contrib/cgnat-ready-bfd.sh`](../contrib/cgnat-ready-bfd.sh)) only
brings up sessions that are admin-down, and runs independently of VPP's
service, so a package upgrade that restarts VPP can't leave it stopped.

## Measured failover on VFs

A 0.2 s ping and a long HTTP download ran through a real subscriber line. The
subscriber's owner node was killed with `kill -9` and came back by itself
(systemd); 30 s after it rejoined, the other node was killed.

| event | before the three fixes | after |
|---|---|---|
| kill the subscriber's owner | 3 pings (0.6 s) | 3 pings (0.6 s) |
| the restarted node rejoins | 17 pings (3.4 s) | **none** |
| kill the other node | 2 pings (0.4 s) | 1 ping (0.2 s) |
| upgrading a node (`deploy rollout`) | 3.2 s mid-install, 33 s resync | 0.4 s at stop, none at rejoin, resync 0.1 s |

Downloads on the final build, each over one TCP connection that kept the same
public IP:port through kill, rejoin and kill:

- **Our own server:** an 800,000,000-byte file, SHA-256 identical to the source.
- **A public mirror** (the Debian 13.7 netinst ISO from AARNet): 792,723,456 bytes, SHA-256 matching Debian's published `SHA256SUMS`. Before the fixes, this mirror closed the connection (a clean FIN mid-body) after the 3.4 s rejoin stall, every time. Our own server rode that stall out.

During the downloads the ping also lost occasional single packets, because
the download filled the subscriber line. Those are queueing on the access
line, not failover.
