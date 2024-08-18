module main

go 1.19

require (
	github.com/davidcoles/cue v0.1.3
	github.com/davidcoles/xvs v0.1.15
	vc5 v0.0.0
)

require github.com/elastic/go-elasticsearch/v7 v7.17.10 // indirect

replace vc5 => ../.
