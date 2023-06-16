LIBBPF     := $(PWD)
LIBBPF_LIB := $(PWD)/bpf

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

OBJ := kernel/bpf/bpf.o
BIN := cmd/vc5ng

MAX_FLOWS    ?= 10000000 # 10M
SHARED_FLOWS ?= 1000000  # 1M
PERCPU_FLOWS ?= 1000000  # 1M
FLOW_QUEUE   ?= 10000

all: clean cmd/vc5.json $(BIN) $(OBJ)

bin:  $(BIN)

cmd/vc5.yaml:
	cp docs/config.yaml $@

cmd/vc5.json: cmd/config.pl cmd/vc5.yaml
	cmd/config.pl cmd/vc5.yaml >$@

cmd/vc5ng: cmd/vc5ng.go $(OBJ)
	go build -o $@ $<

%.o: %.c bpf
	clang -S \
	    -target bpf \
	    -D MAX_FLOWS=$(MAX_FLOWS) \
	    -D SHARED_FLOWS=$(SHARED_FLOWS) \
	    -D PERCPU_FLOWS=$(PERCPU_FLOWS) \
	    -D FLOW_QUEUE=$(FLOW_QUEUE) \
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

wc:
	find bgp4 cmd/vc5ng.go config kernel lb maglev monitor types -name \*.go | xargs wc
	wc kernel/bpf/*.c
