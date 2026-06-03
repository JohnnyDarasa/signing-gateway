#!/bin/bash

mkdir -p logs

./target/release/signing-gateway >> logs/signing-gateway.log 2>&1
