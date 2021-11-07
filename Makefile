LIBBPF     := $(PWD)/libbpf
LIBBPF_LIB := $(PWD)/libbpf/bpf
LIBBPF_VER := v0.4.0

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

MAX_FLOWS    ?= 10000000
MAX_SERVICES ?= 100

all: clean build

build: vc5/vc5 vc5.json

vc5.json: tools/config.pl vc5.yaml
	tools/config.pl vc5.yaml >vc5.json

wc: clean
	wc */*.go */*.c */*.h

vc5/vc5: */*.go */*.c bpf/bpf.go bpf/simple.go
	cd vc5 && go build

bpf/%.go: src/%.o
	 go run tools/include.go BPF_$* src/$*.o >$@

%.o: %.c libbpf/bpf
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



libbpf/bpf: libbpf
	if [ ! -d libbpf/bpf ]; then (cd libbpf/src && make && cd .. && ln -s src bpf); fi

libbpf:
	if [ ! -d libbpf ]; then git clone https://github.com/libbpf/libbpf/ && cd libbpf && git checkout $(LIBBPF_VER); fi

clean:
	rm -f vc5/vc5 src/*.o src/*.ll bpf/*.go vc5.json

distclean: clean
	rm -rf libbpf
