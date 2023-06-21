.PHONY: all clean test

SYSBOOSTD=../../target/debug/sysboostd

all: test

test:
	clear
	rm -rf /etc/sysboost.d
	mkdir -p /etc/sysboost.d
	cp -f app1.toml app2.toml app3.toml bash.toml /etc/sysboost.d/
	@echo ======
	$(SYSBOOSTD)
