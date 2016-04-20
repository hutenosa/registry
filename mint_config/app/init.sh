#! /bin/bash
# This is a sample bash script for a TMSP application

cd app/
git clone https://github.com/tendermint/nomnomcoin.git
cd nomnomcoin
npm install .

node app.js --addr="unix:///data/tendermint/app/app.sock" --eyes="unix:///data/tendermint/data/data.sock"