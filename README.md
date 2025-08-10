# Netctl

The Anjarai Petti (Traditional Indian Spice Box) for Network Engineers!

Note: Experimental CLI tool. Not stable yet. WIP.

## Documentation

### Crafter

#### ARP

Craft an ARP Request packet.

```
netctl craft arp --srcmac 3a:7e:48:98:7d:8c --senderip 192.168.1.105 --targetip 192.168.1.104 
netctl craft arp -M 3a:7e:48:98:7d:8c -S 192.168.1.105 -T 192.168.1.104 
```

Not receiving ARP reply every time. Need to check on this. 

#### TCP SYN

```
netctl craft tcp --srcmac 3a:7e:48:98:7d:8c --dstmac c2:4a:89:08:39:ea --srcip 192.168.1.105 --dstip 192.168.1.104 --srcport 54321 --dstport 80
netctl craft tcp -M 3a:7e:48:98:7d:8c -m c2:4a:89:08:39:ea -S 192.168.1.105 -D 192.168.1.104 -P 54321 -p 80
```

### Ping

#### Default Ping - Broken

```
./netctl ping 8.8.8.8
```

#### HTTP Ping

Initiate TCP 3WHS followed by a HEAD request.

```
./netctl ping --type=http google.com
```

#### HTTPS Ping

Initiate TCP 3WHS followed by a HEAD request. The difference is over HTTP is encryption.

```
./netctl ping --type=https google.com
```

#### TCP Ping

Initiate TCP 3WHS followed by immediate session closure.

```
./netctl ping --type=tcp google.com
```

#### TLS Ping

Initiate TCP 3WHS followed by TLS client/server certificates exchange.

```
./netctl ping --type=tls google.com
```

#### QUIC Ping

```
./netctl ping --type=quic google.com
```

#### HTTP3 Ping

```
./netctl ping --type=http3 google.com
```

### Scan

#### ARP Scan

Depends on the crafter ARP functions.

```
./netctl scan --type=arp
```