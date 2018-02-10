#!/bin/sh

openssl req             \
    -x509               \
    -sha256             \
    -days 365           \
    -newkey rsa:4096    \
    -keyout key.pem     \
    -out cert.pem       \
    -nodes              \
    -subj "/C=US/ST=./L=The internet/O=./OU=./CN=www.example.com"
