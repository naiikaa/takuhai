# Takuhai 宅配便 CLI Chat
Takuhai is a CLI Chat application that was developed as the final project for the lecture `Cryptographic Engineering` in the computer science masters program of the University of Kassel.

The main goal of the lecture was to learn implementing various different cryptographic algorithms that were or are used in applications around the world. 

This implementation provides a [Client](client.py) and [Server](server.py) pair that can be started individually via terminals. Clients can then register to the server and send messages to other registered clients.

## Project requirements 

Design and Implementation of a secure messaging system. The goal is to integrate cryptographic protocols to provide confidentiality, integrity, authenticity as well as forwards and backwards secrecy.

The implementation should include the following four phases:

### Registration

Clients can register with the server by creating long-term identity keys and other necessary credentials.

### Login

Clients should be able to log in by using a secure authentication process.

### X3DH

Synchronizing a shared secret between two clients should be achieved by using the `X3DH` protocol. The protocol ensures mutual authentication and supports offline communication by using key bundles.

### Double Ratchet

Encrypted messaging between two clients is achieved by using the `Double Ratchet` algorithm to ensure forwards and backwards secrecy.