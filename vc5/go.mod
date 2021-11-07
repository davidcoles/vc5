module vc5

go 1.15

replace xdp => ./xdp

replace bpf => ../bpf

replace bgp4 => ./bgp4

require (
	bgp4 v0.0.0-00010101000000-000000000000
	bpf v0.0.0-00010101000000-000000000000
	xdp v0.0.0-00010101000000-000000000000
	github.com/dchest/siphash v1.2.2
)
