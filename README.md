# Source NAT with DHCP

This is a SDN application project that Source NAT and DHCP Server implementation in Ryu controller.

NOTE: DHCP server application is not working on Windows clients. Linux clients are all fine.

# Testing on Platform

- Pica8 P-3290 with PicOS

```
admin@PicOS-OVS$version
Copyright (C) 2009-2014 Pica8, Inc.
===================================
Hardware Model                : P3290
Linux System Version/Revision : 2.6.5/24714
Linux System Released Date    : 02/22/2016
L2/L3 Version/Revision        : 2.6.5/24714
L2/L3 Released Date           : 02/22/2016
OVS/OF Version/Revision       : 2.6.5/24714
OVS/OF Released Date          : 02/22/2016
```

- OpenvSwitch version

```
admin@PicOS-OVS$ovs-ofctl --version
ovs-ofctl (Open vSwitch) 2.3.0
Compiled Feb 22 2016 16:47:11
OpenFlow versions 0x1:0x4
```

# Usage

Source NAT use `port 1` as WAN port by default.

```bash
$ ryu-manager base.py l2switch.py dhcp.py snat.py --verbose
```

# Northbound API

Ryu web server is running on http://localhost:8080/

## Initialize

`HTTP Request`

`POST /api/nat_config_init`


##### This will initialize NAT configuration

Note: Please modify default settings in `nat_config_init` method to fit your requirements

Request

```
POST /api/nat_config_init HTTP/1.1

{}
```

Response `200`

## Update

`HTTP Request`

`POST /api/nat_config_init`

##### This will update NAT configuration

Request

```
PUT /api/nat_config_save

{
  "wanPort": 1,
  "publicIP": "140.114.xxx.xxx",
  "defultGateway": "140.114.xxx.254",
  "natPrivateNetwork": "192.168.2.0"
}
```

Response `200`

# License

MIT © [Che-Wei Lin](https://github.com/John-Lin)
