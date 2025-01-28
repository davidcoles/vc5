module main

go 1.19

require (
	github.com/davidcoles/xvs v0.1.18
	vc5 v0.0.0
)

require (
	github.com/davidcoles/cue v0.1.4 // indirect
	github.com/elastic/go-elasticsearch/v7 v7.17.10 // indirect
)

replace vc5 => ../.

//replace github.com/davidcoles/cue => ../../cue
//replace github.com/davidcoles/xvs => ../../xvs
