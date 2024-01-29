# Advanced

## Virtual IPs

If a service has more that one virtual IP address, instead of repeating configuration like ...:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      http:

  - name: webserver
    virtual: 192.168.123.46
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      http:
```

... both VIPs can be specified by making the `virtual` directive a list instead of a scalar.

```yaml
  - name: webserver
    virtual:
      - 192.168.123.45
      - 192.168.123.46      
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      http:
```

If different backends are required for different services on a single VIP this can be achived with:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      http:

  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.222
      - 10.1.2.223
    policy:
      https:
```

It is not supported yet, but This should really be achievable with a tagged or explicit inline server list, eg.:

```yaml
  - name: webserver
    virtual: 192.168.123.46
    policy:
      http:
        servers: list-a
      https:
        servers:
          - 10.1.2.222
          - 10.1.2.223
```

TODO!


## Minimum service levels

If you want the advertised VIP to be withdrawn from BGP sessions when
fewer than a certain number of backends are available
(the default is one):

```yaml
  - name: webserver
    virtual:
      - 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
      - 10.1.2.102
      - 10.1.2.103
    need: 2
    policy:
      http:
```


## Checks

A basic webserver might be healthchecked like this:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    host: foo.example.com
    path: /im-alive.html
    expect: 200
    method: HEAD
    policy:
      http:
```

The HTTP parameters could be moved down to the check level:


```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      80:
        checks:
          - type: http
            host: foo.example.com
            path: /im-alive.html
            method: HEAD
```

Let's say we have some proprietary TCP service which runs on port
9000, but there is no way to signal inline that the instance should be
taken out of service. We could run a special HTTP based
health-checking service on port 8500 which can signal to the load
balancer when to mark the instance as down, eg.:

```yaml
  - name: proprietary
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      9000:
        checks:
          - type: syn  # first make sure that the service is responsing at a TCP level
          - type: http # next ensure that the health-checking service is looking good (note the override of port number)
            port: 8500
            path: /alive
            expect: 200
```

If either the proprietary service stops responding to TCP SYN checks,
or the HTTP signalling service is down or return a non-200 response
then the instance will be marked as down.
