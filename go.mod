module vc5

go 1.19

require (
	github.com/davidcoles/bgp v0.0.4
	github.com/davidcoles/cue v0.1.4
	github.com/elastic/go-elasticsearch/v7 v7.17.10
)

//replace github.com/davidcoles/cue => ../cue
//replace github.com/davidcoles/bgp => ../bgp
