# If you already have libbpf installed elsewhere on your system then
# specify the path like so:
# CGO_CFLAGS=-I/path/to/libbpf CGO_LDFLAGS=-L/path/to/libbpf go build

BPFVER ?= v1.4.6
LIBBPF ?= $(PWD)/libbpf
GOLANG ?= 1.21

default: vc5 config.json

race:
	$(MAKE) default FLAGS=-race

vc5: libbpf/bpf/libbpf.a *.go
	CGO_CFLAGS="-I$(LIBBPF)" CGO_LDFLAGS="-L$(LIBBPF)/bpf" go build $(FLAGS) -o $@

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
	git clone -b $(BPFVER) --depth 1 https://github.com/libbpf/libbpf

libbpf/bpf: libbpf
	cd libbpf && ln -s src bpf

libbpf/bpf/libbpf.a:
	$(MAKE) libbpf/bpf
	cd libbpf/bpf && $(MAKE)

# just for quick setup on testing machines
focal: apt-install /usr/local/bin/go
jammy: apt-install /usr/local/bin/go
bookworm: apt-install; $(MAKE) /usr/local/bin/go GOLANG=1.19

apt-install:; apt install -y libelf-dev libyaml-perl libjson-perl

/usr/local/bin/go:
	apt install -y golang-$(GOLANG)
	ln -s /usr/lib/go-$(GOLANG)/bin/go /usr/local/bin/go

# alternately: cloc --match-f='\.go$' --not-match-f='_test.go' ..
cloc:
	cloc *.go ../*.go


