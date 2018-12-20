VERSION ?= OpenSSL_1_1_1a

all:
	curl -kL https://github.com/openssl/openssl/archive/$(VERSION).tar.gz | tar -xz
	mv openssl-$(VERSION) openssl && cd openssl && ./config && make && make install

clean:
	rm -rf openssl
