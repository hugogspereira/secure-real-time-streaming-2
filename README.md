
# SRSC 2022/2023 - Project 1

This repo will be used to store the first project of Network and Computer Systems Security Course of 2022/2023.

- [Assignment Information](http://vps726303.ovh.net/srsc/)


In this project, we propose to design and implement a secure UDP channel to support real-time streaming based on a protocal usign cryptographic protection, supporting encrypted and integrity-controlled payloads of protected media frames encoding MPEG4 encoded movies.

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
