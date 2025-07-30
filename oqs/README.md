# oqs

## liboqs

https://github.com/open-quantum-safe/liboqs

## install

	make

## usage

### kem

	./oqs-kem BIKE-L1
	./oqs-kem Classic-McEliece-348864
	./oqs-kem FrodoKEM-640-SHAKE
	./oqs-kem Kyber768
	./oqs-kem ML-KEM-768
	./oqs-kem sntrup761 

### sig

	./oqs-sig Dilithium2
	./oqs-sig Falcon-512
	./oqs-sig ML-DSA-65
	./oqs-sig SPHINCS+-SHAKE-128f-simple
