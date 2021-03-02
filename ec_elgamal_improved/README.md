# ec elgamal improved

# EC ElGamal (improved version)

see also: http://zoo.cs.yale.edu/classes/cs467/2017f/lectures/ln13.pdf

use r.x for encryption, use inverse r.x for decryption

    $ python ec_elgamal_improved.py

    plain-text:
    m: 0xcdc271e654075e9567fda6cf7765dd0

    encrypt:
    k: 0x6c99c3f4e8c023f38e26fe23f390eeedafacab4be4656ff7da970dfe2a572e7b
    r: 0x6ea2842f812f462beae9be9058ee4fdf45500017de65b00a7b049e59a5452a35, 0x43517f409169db6161107b664653f5dcd5afcc417768a5df41116231d7e92f63
    cipher y1: 0x421a9145f0fd4d4933ddff39051f56e47068a66b1283bae0fcca26305fe13b1c, 0x465a537b06bab6adec8a18c05c16355a745a2eb6afd1e08fd115e42e8e5d4a21
    cipher y2: 0x144a7d861b18ea94a7c8755f9d12923c1b5dde68a1c0b411cdd494b0545f4d46

    decrypt:
    r: 0x6ea2842f812f462beae9be9058ee4fdf45500017de65b00a7b049e59a5452a35, 0x43517f409169db6161107b664653f5dcd5afcc417768a5df41116231d7e92f63
    inv of r.x: 0x8025cbed276597b07c05ade43a0b280608297288aaaa6d66473e02e45b20d704
    m: 0xcdc271e654075e9567fda6cf7765dd0

# EC ElGamal (improved version), inverse r.x for encryption

use inverse r.x for encryption, use r.x for decryption

    $ python ec_elgamal_improved2.py

    plain-text:
    m: 0xa2fa056617c1f5d197c580d100dd69f8

    encrypt:
    k: 0x2b53c15152b59155a14a8a23482243259208b8330b2bfac85c3f0c7ecba6904b
    r: 0xe7db03150dc9d73af07c6de545dd81400976560a2a78a2f688522ccfa8f51894, 0xe9594d15b2974ea7ed406209f81bc8b020820ce1874ec37bd7994ff4fec68881
    cipher y1: 0x144ca4ec646c4526757c4b23faabcc062570fb7693f5a7cc815dfe12b45eadd6, 0xfdd38545b55562b9a55dece073a37b8734516d20388ee8b6da06922921bdcfb5
    inv of r.x: 0x33732d1609aadb232d2fb402b8605b190e7850478fd86bdeb4089bcbbe1a80ad
    cipher y2: 0x29e9904ad7fe52b2d29c36216b4195c0945615e942648cf76e1ec7f45903b92

    decrypt:
    r: 0xe7db03150dc9d73af07c6de545dd81400976560a2a78a2f688522ccfa8f51894, 0xe9594d15b2974ea7ed406209f81bc8b020820ce1874ec37bd7994ff4fec68881
    m: 0xa2fa056617c1f5d197c580d100dd69f8

