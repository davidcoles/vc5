# Domain Name System examples

A simple DNS service with both TCP and UDP protocols can be created shorthand as follows:

```yaml
  - name: dns
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      domain:
```

This is functionally the same as:

```yaml
  - name: dns
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      domain/tcp:
      domain/udp:
```

Which could be expanded to:

```yaml
  - name: dns
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      53/tcp:
        checks:
          - type: dns
      53/udp:
        checks:
          - type: dns
```

To test the service, the checks send a DNS query (via UDP or TCP
respectively) to the backend server for the A record of localhost. The
resonse does not need to return any particular value, or even be
successful; it just needs to send a DNS response with the same
transaction ID as the request.
