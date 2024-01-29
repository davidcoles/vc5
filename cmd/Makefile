# If you already have libbpf installed elsewhere on your system then
# specify the path like so:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

BPFVER = v1.3.0
LIBBPF = $(PWD)/libbpf/src

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)

default: libbpf/src/libbpf.a vc5

vc5: *.go static/* libbpf/src/libbpf.a
	go build -race -o $@

# avoid clobbering an existing config file when make is run with -B
config.yaml:
	if [ ! -e $@ ]; then cp config.sample.yaml $@; fi

config.json: config.pl config.yaml
	./config.pl config.yaml >$@- && mv $@- $@

clean:
	rm -f vc5 config.json

distclean: clean
	rm -rf libbpf

libbpf:
	git clone -b $(BPFVER) https://github.com/libbpf/libbpf

libbpf/src/libbpf.a: libbpf
	cd libbpf/src && $(MAKE)

# need to ass a hook to git
pre-commit:
	if grep '^replace' go.mod; then false; fi
