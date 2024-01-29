# Services

The YAML configuration used to program the load balancer is intended
to be a compact, human-readable and, more importantly, human-editable
format. The software itself requires a much more verbose, explicit,
JSON format. A script loads in the YAML format, expands shorthand terms,
and fills in many defaults to produce the JSON configuration.

Generally speaking, directives (or defaults) at higher (eg. `service`)
level of the configuration cascade to lower levels, and can be
overriden (eg. by directives at the `policy` or `checks` level).

Hopefully the configuration parser will do what you would expect. If it
doesn't then it is probably a bug.

* [Basic web services](basic.md)
* [Domain Name System](domain.md)
* [Servers](servers.md)
* [Advanced checks](advanced.md)

