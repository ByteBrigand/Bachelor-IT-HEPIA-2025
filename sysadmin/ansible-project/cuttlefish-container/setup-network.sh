#!/bin/bash

# Enable IP forwarding
#echo 1 > /proc/sys/net/ipv4/ip_forward
#echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Create bridge interfaces
ip link add name cvd-ebr type bridge forward_delay 0 stp_state 0
ip link add name cvd-wbr type bridge forward_delay 0 stp_state 0
ip link set dev cvd-ebr up
ip link set dev cvd-wbr up

# Setup ethernet bridge
ip addr add 192.168.98.1/24 broadcast + dev cvd-ebr
for i in $(seq 1); do
    tap="cvd-etap-$(printf %02d $i)"
    ip tuntap add dev $tap mode tap group cvdnetwork vnet_hdr
    ip link set dev $tap master cvd-ebr
    ip link set dev $tap up
done

# Setup mobile network taps
for i in $(seq 1); do
    tap="cvd-mtap-$(printf %02d $i)"
    ip tuntap add dev $tap mode tap group cvdnetwork vnet_hdr
    ip link set dev $tap up
    if [ $i -lt 65 ]; then
        ip addr add 192.168.97.$((4*$i - 3))/30 broadcast + dev $tap
    else
        ip addr add 192.168.93.$((4*($i-64) - 3))/30 broadcast + dev $tap
    fi
done

# Setup wireless bridge
ip addr add 192.168.96.1/24 broadcast + dev cvd-wbr
for i in $(seq 1); do
    tap="cvd-wtap-$(printf %02d $i)"
    ip tuntap add dev $tap mode tap group cvdnetwork vnet_hdr
    ip link set dev $tap master cvd-wbr
    ip link set dev $tap up
done

# Setup wireless access point taps
for i in $(seq 1); do
    tap="cvd-wifiap-$(printf %02d $i)"
    ip tuntap add dev $tap mode tap group cvdnetwork vnet_hdr
    ip link set dev $tap up
    if [ $i -lt 65 ]; then
        ip addr add 192.168.94.$((4*$i - 3))/30 broadcast + dev $tap
    else
        ip addr add 192.168.95.$((4*($i-64) - 3))/30 broadcast + dev $tap
    fi
done

# Start DHCP servers
dnsmasq --port=0 --strict-order --except-interface=lo \
    --interface=cvd-ebr --listen-address=192.168.98.1 \
    --bind-interfaces --dhcp-range=192.168.98.2,192.168.98.255 \
    --dhcp-option="option:dns-server,8.8.8.8,8.8.4.4" \
    --conf-file="" --pid-file=/var/run/cuttlefish-dnsmasq-cvd-ebr.pid \
    --dhcp-leasefile=/var/run/cuttlefish-dnsmasq-cvd-ebr.leases

dnsmasq --port=0 --strict-order --except-interface=lo \
    --interface=cvd-wbr --listen-address=192.168.96.1 \
    --bind-interfaces --dhcp-range=192.168.96.2,192.168.96.255 \
    --dhcp-option="option:dns-server,8.8.8.8,8.8.4.4" \
    --conf-file="" --pid-file=/var/run/cuttlefish-dnsmasq-cvd-wbr.pid \
    --dhcp-leasefile=/var/run/cuttlefish-dnsmasq-cvd-wbr.leases

