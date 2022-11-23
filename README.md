
# SRSC 2022/2023 - Project 2

This repo will be used to store the first project of Network and Computer Systems Security Course of 2022/2023.

- [Assignment Information](http://vps726303.ovh.net/srsc/wa/TP2/TP2-Requirements/ProjectAssignment2-ExtendedDescription%20.pdf)


The goal of the project assignment 2 (PA#2) is the design, implementation, and experimental
demonstration and evaluation of a dynamic protocol for establishment of security
associations (SA) (including ciphersuites, session keys and all required parameters), as an
enhanced solution for the previous secure real-time streaming protocol supported by UDP, as
initially designed and implemented in the Project Assignment 1 (PA#1). The goal is to avoid
the need of statically defined configuration files, as pre-shared and security associations, as
used in the initial PA#1 specification.

## Base Components

- Streaming Server

- Box(es)

- Media Playing Client (Suggestion: [VLC](https://www.videolan.org))




## Required Properties

Required properties as defined in the OSI X.800 framework and related terminology

- Connectionless confidentiality
- connectionless integrity control without recovery
- data-origin authentication. and integrity

Adversary model and typology of threats for which you must implement countermeasures:
- Packet sniffing / illicit access to data in RTSSP/UDP/IP data-flows
- Leakage (copy and/or release) of contents
- Illicit message (or packet) replaying
- Data integrity breaks (or message tampering) in payloads (Application Level)


## Trust Computing Base Assumptions

- We only consider attacks against the communication channels
- We will consider that the endpoints (principals) and runtime environments for Streaming Server, Box and Media Player used tool are trusted components (in the TCB)
- We will consider that the runtime stack (including JAVA-JVM/OS/firmware and hardware in use computers) is trustable
- We will consider that the the JAVA runtime framework (JRE) is trustable
- We will consider that the cryptographic mechanisms are based on secure crypto algorithms (we can select/configure for their operation) and we consider that they are provided by trustable cryptographic providers in the JCA/JCE runtime support
- We will consider that the Java development environment and used tools, are trustable

## Run/Debug Configurations

HjStreamServer:
- HjStreamServer "movie" "movies-config" "ip-multicast-address" "port" "box-config" "password"

HjBox:
- HjBox "config" "box-config" "password"

EncryptMovies:
- EncryptMovies "movie" "movies-config" "password"
(If you want to encrypt the movie with different configs, run this with the corresponding "movie-config")

PBEFileEncryption:
- PBEFileEncryption "config" "password"
(If you want to encrypt the configs file with a given password, run this with the corresponding "password")

# Aditional Information

To run this program it is not necessary to have the configuration files in clear. Therefore, the project works properly WITHOUT these being available!
However, it was decided to put them in the repo so that the Professor could test things out.

Also, the password used to encrypt and decrypt the files was: "omsqptaesdfommptvsnfiocmlesrfoqppms".

The password used for the boxkeystore was:     "omsqptaesd12345fommptvsnf54321iocmlesrfoqppms12345".

The password used for the streamkeystore was:  "12345omsqptaesd54321fommptvsnf12345iocmlesrfoqppms".

The password used for the trustedstore was:    "cIBXzKN5WU5aVMqYKuWGncATG35M3Yok6wJvZ0tdlnzBp0R1Gv".
