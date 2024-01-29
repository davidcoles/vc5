# Servers

If you want to mark a backend server as administratively down in the load balancer, mark the server with an asterisk:

```yaml
services:

  - name: service1
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
      - 10.1.2.102
      - 10.1.2.103*
    policy:
      http:
```

If you have two (or more) sets of services which will always share the same set of backend servers, eg.:

```yaml
services:

  - name: service1
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
      - 10.1.2.102
      - 10.1.2.103*
    policy:
      http:

  - name: service2
    virtual: 192.168.123.56
    servers:
      - 10.1.2.100
      - 10.1.2.101
      - 10.1.2.102
      - 10.1.2.103*
    policy:
      https:
```

You can tag the servers in a `servers` section and refer to them by name:

```yaml
services:

  - name: service1
    virtual: 192.168.123.45
    servers: my-servers
    policy:
      http:

  - name: service2
    virtual: 192.168.123.56
    servers: my-servers
    policy:
      https:

servers:
  my-servers:
    - 10.1.2.100
    - 10.1.2.101
    - 10.1.2.102
    - 10.1.2.103*
  
```

NB: This means that you cannot *independently* mark servers as
administratively down, and adding or removing servers from the group
applies to all of the services referencing them, so use this
judiciously.
