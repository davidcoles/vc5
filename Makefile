LIBBPF     := $(PWD)
LIBBPF_LIB := $(PWD)/bpf

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

OBJ := kernel/bpf/bpf.o
BIN := cmd/vc5

FLOW_STATE_TYPE ?= BPF_MAP_TYPE_LRU_PERCPU_HASH
FLOW_STATE_SIZE ?= 1000000  # 1M
FLOW_SHARE_SIZE ?= 1000000  # 1M
FLOW_QUEUE_SIZE ?= 10000

all: clean cmd/vc5.json $(BIN) $(OBJ)

bin:  $(BIN)

cmd/vc5.yaml:
	cp docs/config.yaml $@

cmd/vc5.json: cmd/config.pl cmd/vc5.yaml
	cmd/config.pl cmd/vc5.yaml >$@

cmd/vc5: cmd/vc5.go cmd/stats.go $(OBJ)
	go build -o $@ cmd/vc5.go cmd/stats.go

%.o: %.c bpf
	clang -S \
	    -target bpf \
	    -D FLOW_STATE_TYPE=$(FLOW_STATE_TYPE) \
	    -D FLOW_STATE_SIZE=$(FLOW_STATE_SIZE) \
	    -D FLOW_SHARE_SIZE=$(FLOW_SHARE_SIZE) \
	    -D FLOW_QUEUE_SIZE=$(FLOW_QUEUE_SIZE) \
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
	rm -f $(BIN) $(OBJ) cmd/vc5.json bpf

distclean: clean
	rm -rf libbpf
	mkdir libbpf

tests:
	cd kernel/        && go test -v
	cd kernel/maglev/ && go test -v
	cd bgp/           && go test -v

wc:
	find bgp4 cmd/vc5.go config kernel lb maglev monitor types -name \*.go | xargs wc
	wc kernel/bpf/*.c
