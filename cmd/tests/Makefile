# regression tests for the config parser

SERVICES != (ls services*.yaml | sed 's/yaml$$/test/')
BGP      != (ls bgp*.yaml | sed 's/yaml$$/test/')

tests: services bgp

services: $(SERVICES)
bgp:	  $(BGP)


%.test:; ../config.pl $*.yaml | ./compare.pl $*.json
ref:; for json in $$(ls *.yaml | sed 's/yaml$$/json/'); do $(MAKE) $$json; done
%.json: %.yaml; ../config.pl $< > $@- && mv $@- $@
reset:; rm -f -- *.json

