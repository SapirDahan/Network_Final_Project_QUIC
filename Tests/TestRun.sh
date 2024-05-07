#!/bin/bash

python3 ../QUIC_Server.py -d $1 > /dev/null &

sleep 0.01

python3 ../QUIC_Client.py > client_output.txt &

wait