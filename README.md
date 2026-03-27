# PXMC P4 Simulation Guide

This guide explains how to run the PXMC P4 project using Mininet and BMv2. It is designed for hands-on learning of the P4 language.

---

## 1. Tutorials Reference

To get hands-on experience with P4, follow the official tutorials:
[https://github.com/p4lang/tutorials/tree/master/exercises](https://github.com/p4lang/tutorials/tree/master/exercises)

Assuming the repository is cloned in:

```bash
~/tutorials/exercises

To run each project follow the readme in the github link.

#Mu Project:

First, you can look into the ~/tutorials/exercises/pxmc/topology.json file to get an idea of the hosts, ports and switches, the ip addresses and mac addresses. Each swicth is linked to a runtime file (the runtime tables are removed except the arp_table that I kept for debugging), so there are useless more and less.
The topology is in stars: h1 is linked to s1 through p1 (see links part ["h1", "s1-p1"]), and s1 is linked to s2 through p1 and p2 (see ["s1-p2", "s2-p2", "0ms", 1]), "0ms" is the propagation delay of the link. "0ms" means no delay is simulated. "1" is unique link ID used internally by Mininet.

To run the pxmc project (mu project):

## 2. Navigate to PXMC Project
`` cd ~/tutorials/exercises/pxmc

## 3. Prepare Environment
Activate the Python virtual environment:

`` source ~/p4venv/bin/activate

Make the run script executable:

`` chmod +x run.sh

Run the simulation:

`` ./run.sh

When prompted for a password, enter: nora2003

## 4. Mininet Console

Once the script runs, you have access to the Mininet console. You can interact with the hosts:

`` xterm h1 h2 h3 h4

Opens a terminal for each host.

You can open multiple instances of the same host:

`` xterm h1 h1

Bash terminals for each host will appear.

## 5. Activate Python Environment on Hosts

Inside each host terminal, activate the P4 Python environment:

`` source ~/p4venv/bin/activate

Now you can run any Python scripts you want to test or interact with the PXMC P4 program.

To exit from mininet type exit


## 6. Runtime Switch Configuration with simple_switch_CLI

After launching the mininet, each BMv2 switch can be configured using the Simple Switch CLI (simple_switch_CLI). This is necessary for multicast forwarding, which allows FLOOD/REQ messages to reach multiple ports.

## #Step 1: Open CLI for each switch, open a new tab (ubuntu cmd or wsl cmd), activate p4venv python environement.

The -i flag specifies interfaces, and --thrift-port specifies the Thrift port for runtime API. Example:

# Switch s1
simple_switch_CLI --thrift-port 9090

# Switch s2
simple_switch_CLI --thrift-port 9091

# Switch s3
simple_switch_CLI --thrift-port 9092

# Switch s4
simple_switch_CLI --thrift-port 9093

## #Step 2: Create a Multicast Group
`` mc_mgrp_create 1

## ##Explanation:

mc_mgrp_create <group_id> creates a multicast group with ID 1.

Multicast groups allow the switch to forward a single packet to multiple egress ports.

## #Step 3: Create Multicast Nodes (Ports)

`` mc_node_create 2 2 3 4 5 6 7 8

the result of the command is :
  Creating node with rid 2 , port map 1100 and lag map
  node was created with handle 4

mc_node_create <rid> <port_list> creates multicast nodes corresponding to each egress port.

Ports 2 3 4 5 6 7 8 correspond to the switch interfaces connected to Mininet hosts (h1–h8), here removed ingress port 1 for loop back.

Each node is used in multicast replication.

## #Step 4: Associate Nodes to the Multicast Group

`` mc_node_associate 1 4

mc_node_associate <group_id> <node_id>

## #Step 5:

To see the multicast groups that have been created:

`` mc_dump

results:

==========
MC ENTRIES
**********
mgrp(1)
  -> (L1h=5, rid=2) -> (ports=[2, 3], lags=[])
**********
mgrp(999)
  -> (L1h=0, rid=3) -> (ports=[4], lags=[])
  -> (L1h=1, rid=2) -> (ports=[3], lags=[])
  -> (L1h=2, rid=1) -> (ports=[2], lags=[])
  -> (L1h=3, rid=0) -> (ports=[1], lags=[])

**Notice: the multicast group 999 is already configured because I kept in purpose a table for arp called arp_table (that can be seen in the pxmc.p4 file), so the multicast group is created in runtime directly in each swicth.

## #Step 6: to exit tap `` EOF

These configurations should be done for each switch on the ports 9091, 9092, 9093, this is the only manual configurations to make, each time you want to run the simulations. These steps are the most important because it allows the packets to travel the network.

## Notes
- Logs are saved under /tmp/tutorial-logs and packet captures under /tmp/tutorial-pcaps.
- The run.sh script handles cleaning Mininet, rebuilding BMv2, and launching the simulation.
- Use Ctrl+Shift+C / Ctrl+Shift+V in XTerm for copying and paste to/fromterm bashes.

## Traffic visualization with tcpdump and Troubleshoot

You can monitor PXMC protocol traffic on your BMv2 switches using tcpdump. For example:
`` sudo tcpdump -ni s2-eth1 -vvv udp port 5004

-n : do no resolve IP addresses to hostnames
-i s2-eth1 : capture traffic on interface s2-eth1 ( replace s2-eth1 with the interface of any switch host you want to monitor.
-vvv : extra verbose output; shows all protocol fields in detail.
udp port 5004: filter only UDP packets on port 5004 (REPLY messages in PXMC)

## # Examples:
1. capture FLOOD messages (port 5003) on switch s1, interface eth2:

`` sudo tcpdump -ni s1-eth2 -vvv udp port 5003

2. capture all outgoing messages from host h1 linked to switch s1, to be run on h1 xterm bash:

`` sudo tcpdump -ni s1-eth0 udp

