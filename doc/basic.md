# Basic web services

A simple service listening on IP address 192.168.123.45 port 80 which
uses two webservers as a backend and are checked for default HTTP 200
response to a request for the path "/" can be specified such:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      http:
```

If you want both your frontend service and the webservers to listen on
port 8000 instead, but still with HTTP health checks:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    policy:
      8000/http:
```

If you want to use a special path that will be checked (this could either
be a file that is present in the webserver's root or an API endpoint):

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    path: /in-service.html
    policy:
      http:
```

If you need to set the `Host:` header in your health checking requests:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    path: /in-service.html
    host: foo.example.com
    policy:
      http:
```

If you need to check for a different response code (eg., a redirect):

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    path: /in-service.html
    host: foo.example.com
    expect: 301
    policy:
      http:
```

If your webserver redirects all HTTP traffic (301 code) to HTTPS which
returns the a 200 respsonse and which needs to use a TLS encrypted
health check (certificates are not validated), you can use:

```yaml
  - name: webserver
    virtual: 192.168.123.45
    servers:
      - 10.1.2.100
      - 10.1.2.101
    path: /in-service.html
    host: foo.example.com
    policy:
      http:
        expect: 301
      https:
```
