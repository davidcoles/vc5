module main

go 1.21

toolchain go1.23.1

require (
	github.com/davidcoles/cue v0.1.4
	github.com/davidcoles/xvs v0.2.4
	vc5 v0.0.0
)

require (
	github.com/davidcoles/bgp v0.0.4 // indirect
	github.com/elastic/go-elasticsearch/v7 v7.17.10 // indirect
)

replace vc5 => ../.

//replace github.com/davidcoles/cue => ../../cue
//replace github.com/davidcoles/xvs => ../../xvs
//replace github.com/davidcoles/bgp => ../../bgp
