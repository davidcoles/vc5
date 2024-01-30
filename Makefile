
default: cmd/vc5 cmd/config.json

cmd/vc5:
	cd cmd && $(MAKE) vc5

cmd/config.json:
	cd cmd && $(MAKE) config.json

clean:
	cd cmd && $(MAKE) clean

distclean: clean
	cd cmd && $(MAKE) distclean
