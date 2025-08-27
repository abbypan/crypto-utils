# libbswabe

## install pbc

	wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz
	tar zxvf pbc-1.0.0.tar.gz
	cd pbc-1.0.0/
	./configure
	make
	make install


## install gmp

	wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
	tar -I zstd -xvf gmp-6.3.0.tar.xz
	cd gmp-6.3.0/
	./configure
	make
	make install


## install libbswabe

	wget http://acsc.cs.utexas.edu/cpabe/libbswabe-0.9.tar.gz
	tar zxvf libbswabe-0.9.tar.gz
	cd libbswabe-0.9/
	./configure
	make
	make install


# install cp-abe

参考: https://blog.csdn.net/qq_34018719/article/details/115007249

	wget http://acsc.cs.utexas.edu/cpabe/cpabe-0.11.tar.gz
	tar zxvf cpabe-0.11.tar.gz
	cd cpabe-0.11/
	./configure

修改 Makefile，把gmp放到LDFLAGS末尾

	LDFLAGS = -O3 -Wall   \
		-lglib-2.0 \
		-Wl,-rpath /usr/local/lib -lpbc -lbswabe -lcrypto -lgmp

修改 policy_lang.y，在final_policy = $1后加一个分号 ;

	result: policy { final_policy = $1; }


	make
	make install

# use cp-abe

https://acsc.cs.utexas.edu/cpabe/tutorial.html

# test

	make
	./cp-abe-t
