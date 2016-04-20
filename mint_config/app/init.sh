#! /bin/bash

go get github.com/hutenosa/registry/app
go install github.com/hutenosa/registry/app

$GOPATH/bin/app -addr="unix:///data/tendermint/app/app.sock" -dbpath="/data/tendermint/" -masterkeys="0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
