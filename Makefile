SCRIPTS=./scripts
TESTPATH=./tests

.PHONY: all check execcheck jscheck nlcheck pycheck test unittest

all: test

test: check unittest

unittest:
	nosetests --with-coverage --cover-package=node --cover-package=rudp --cover-package=db --cover-inclusive $(TESTPATH)

check: execcheck nlcheck jscheck pycheck

banditcheck: $(SCRIPTS)/banditcheck.sh
	$(SCRIPTS)/banditcheck.sh

execcheck: $(SCRIPTS)/execcheck.sh
	$(SCRIPTS)/execcheck.sh

jscheck: $(SCRIPTS)/jscheck.sh
	$(SCRIPTS)/jscheck.sh

nlcheck: $(SCRIPTS)/nlcheck.sh
	$(SCRIPTS)/nlcheck.sh

pycheck: $(SCRIPTS)/pycheck.sh
	$(SCRIPTS)/pycheck.sh
