LIBBPF     := $(PWD)/libbpf
LIBBPF_LIB := $(PWD)/libbpf/bpf
LIBBPF_VER := v0.4.0

export CGO_CFLAGS = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF_LIB)

MAX_FLOWS    ?= 10000000
MAX_SERVICES ?= 100

all: clean build

build: vc5/vc5 vc5.json

test:
	cd vc5 && go run test.go

vc5.json: tools/config.pl vc5.yaml
	tools/config.pl vc5.yaml >vc5.json

wc: clean
	wc vc5/*.go vc5/*/*.go vc5/*/*.c vc5/*/*.h

vc5/vc5: vc5/bpf/bpf.o vc5/bpf/simple.o
	cd vc5 && go build -o vc5 main.go

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
	rm -f vc5/vc5 vc5.json vc5/bpf/*.ll vc5/bpf/*.o

distclean: clean
	rm -rf libbpf
