#!/usr/local/bin/fish

set curdir (dirname (status -f))
set GOPATH (dirname (dirname (dirname (dirname $curdir))))

set pubKey "0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
set privKey "016E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D04D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"

function hexencode
    set data $argv[1]
    echo -n $data | xxd -p | tr -d '\n'
end

function sendTx
    set name $argv[1]
    set action $argv[2]
    set arg1 $argv[3]
    set arg2 $argv[4]
    set expected $argv[5]

    if test -n $arg2
        set args '["'$arg1'", "'$arg2'"]'
    else
        set args '["'$arg1'"]'
    end

    set data (hexencode '{"Nonce": "'(gdate +%s)'","Action":"'$action'","Args":'$args'}')
    set params (hexencode '{"Owner": "'$pubKey'", "Signature": "'(go run sign/main.go $privKey $data)'", "Data": "'$data'"}')
    set res (http -j POST 127.0.0.1:46657 method=broadcast_tx_sync params:='["'$params'"]' | jq -r '.result[1].log')

    if test "$res" = "$expected"
        echo -n "ok"
    else
        echo -n "not ok - received "$res
    end
    echo ' 2 - '$name

    sleep 1

end

go install github.com/hutenosa/loveme/app; and app >/dev/null &
go install github.com/tendermint/tendermint/cmd/tendermint; and tendermint node >/dev/null &

sleep 5

echo "1..7"

sendTx 'test ask first' 'Ask' 'domain.com' '' 'error: data not found'
sendTx 'test reg' 'Reg' 'domain.com' 'Augusto Sanchez' 'ok, can reg'
sendTx 'test reg again' 'Reg' 'domain.com' 'Augusto Sanchez' 'error: data exists'
sendTx 'test ask existing' 'Ask' 'domain.com' '' 'ok, data found'
sendTx 'test free existing' 'Free' 'domain.com' '' 'ok, can free'
sendTx 'test free non-existing' 'Free' 'domain.com' '' 'error: data not found'
sendTx 'test ask freed' 'Ask' 'domain.com' '' 'error: data not found'


kill %tendermint
kill %app
