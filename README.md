# Source NAT with DHCP

This is a SDN application project that Source NAT and DHCP Server implementation in Ryu controller.

NOTE: DHCP server application is not working on Windows clients. Linux clients are all fine.

# Usage

Source NAT use `port 1` as WAN port by default.

```bash
$ ryu-manager l2switch.py dhcp.py snat.py --verbose
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
