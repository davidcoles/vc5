module example.com/vc5

go 1.15

replace example.com/xdp => ../xdp
replace example.com/bpf => ../bpf
replace example.com/bgp4rhi => ../bgp4rhi

require (
	example.com/bpf v0.0.0-00010101000000-000000000000
	example.com/xdp v0.0.0-00010101000000-000000000000
	example.com/bgp4rhi v0.0.0-00010101000000-000000000000
)


