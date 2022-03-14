LIBBPF     := $(PWD)/libbpf
LIBBPF_LIB := $(PWD)/bpf
LIBBPF_VER := v0.4.0

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

MAX_FLOWS    ?= 10000000
MAX_SERVICES ?= 100

all: clean cmd/vc5 cmd/vc5.json

cmd/vc5: cmd/main.go core/bpf/bpf.o core/bpf/simple.o 
	cd cmd && go build -o vc5 main.go

cmd/vc5.yaml:
	cp docs/config.yaml $@

cmd/vc5.json: tools/config.pl cmd/vc5.yaml
	tools/config.pl cmd/vc5.yaml >$@

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


libbpf/src:
	git submodule init
	git submodule update

libbpf/src/libbpf.a: libbpf/src
	cd libbpf/src && $(MAKE)

bpf: libbpf/src/libbpf.a
	ln -s libbpf/src bpf

clean:
	rm -f cmd/vc5 cmd/vc5.json core/bpf/*.ll core/bpf/*.o bpf

distclean: clean
	rm -rf libbpf
	mkdir libbpf

