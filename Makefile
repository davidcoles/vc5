LIBBPF     := $(PWD)
LIBBPF_LIB := $(PWD)/bpf

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

OBJ := core/bpf/bpf.o core/bpf/simple.o kernel/bpf/bpf.o
BIN := cmd/vc5 cmd/vc5ng

## If this is increased to 34000000 it seems to fail on my systems.
## No idea why. Even on sysems with obscene amount of RAM (>200GB)
## libbpf: map 'flows': failed to create: Argument list too long(-7)
#MAX_FLOWS    ?= 33000000

MAX_FLOWS    ?= 10000000
MAX_SERVICES ?= 100

all: clean cmd/vc5.json $(BIN) $(OBJ)

bin:  $(BIN)

xdptest/xdptest: xdptest/xdptest.go xdptest/bpf/bpf.o
	go build -o xdptest/xdptest xdptest/xdptest.go

cmd/vc5.yaml:
	cp docs/config.yaml $@

cmd/vc5.json: tools/config.pl cmd/vc5.yaml
	tools/config.pl cmd/vc5.yaml >$@

cmd/vc5: cmd/main.go $(OBJ)
	go build -o $@ $<

cmd/vc5ng: cmd/vc5ng.go $(OBJ)
	go build -o $@ $<

%.o: %.c bpf
	clang -S \
	    -target bpf \
	    -D MAX_FLOWS=$(MAX_FLOWS) \
	    -D MAX_SERVICES=$(MAX_SERVICES) \
	    -D __BPF_TRACING__ \
	    -I$(LIBBPF) \
	    -Wall \
	    -Werror \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -g -O2 -emit-llvm -c -o $*.ll $*.c
	llc -march=bpf -filetype=obj -o $@ $*.ll
	rm $*.ll

libbpf/src:
	git submodule init
	git submodule update

libbpf/src/libbpf.a: libbpf/src
	cd libbpf/src && $(MAKE)

bpf: libbpf/src/libbpf.a
	ln -s libbpf/src bpf

clean:
	rm -f $(BIN) $(OBJ) cmd/vc5.json

distclean: clean
	rm -rf libbpf
	mkdir libbpf

tests:
	cd maglev/ && go test -v
	cd kernel/ && go test -v
wc:
	find bgp4 cmd config2 healthchecks kernel lb maglev monitor netns types xdp  -name \*.go | xargs wc
	wc kernel/bpf/*.c

