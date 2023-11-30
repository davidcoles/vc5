# Integration


## Development

Ultimately, it would be good to be able to use this as a library such
that the frontend can be controlled by the user. The configuration
could be generated from a dynamic source such as nodes that want to
participate in a pool for a service subscribing to a ZooKeeper
cluster, or pulled as JSON from an HTTP endpoint. A minimal code
snippet for getting a loadbalancer up and running (after obtaining an
initial config) could look like:

```
lb := &vc5.LoadBalancer{
  Native:          true,
  Socket:          "/run/vc5socket",
  NetnsCommand:    []string{os.Args[0], "-s", "/run/vc5socket"},
  Interfaces:      []string{"enp130s0f0", "enp130s0f1"},
  EgressInterface: "bond0",
}

err = lb.Start("10.1.2.3", healthchecks)

if err != nil {
  log.Fatal(err)
}
```

With subsequent configuration updates communicated with
`lb.Update(healthchecks)`. Status and statistics can be obtained from
the `lb` object.

