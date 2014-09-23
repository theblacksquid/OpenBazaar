SCRIPTS=./scripts
TESTPATH=./test

.PHONY: all check execcheck jscheck nlcheck pycheck test unittest

all: test

test: check unittest

unittest:
	nosetests --with-coverage --cover-package=node --cover-inclusive $(TESTPATH)

check: execcheck nlcheck jscheck pycheck

execcheck: $(SCRIPTS)/execcheck.sh
	$(SCRIPTS)/execcheck.sh

jscheck: $(SCRIPTS)/jscheck.sh
	$(SCRIPTS)/jscheck.sh

nlcheck: $(SCRIPTS)/nlcheck.sh
	$(SCRIPTS)/nlcheck.sh

pycheck: $(SCRIPTS)/pycheck.sh
	$(SCRIPTS)/pycheck.sh
