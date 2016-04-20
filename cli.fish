#!/usr/local/bin/fish

set curdir (dirname (status -f))
set GOPATH (dirname (dirname (dirname (dirname $curdir))))

# set host 127.0.0.1
# set host (docker-machine ip mach1)
set host (docker-machine ip mach2)

# Master
set pubKey "0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
set privKey "016E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D04D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"

# User
set pubKey "014EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174"
set privKey "014BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A4EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174"

function hexencode
    set data $argv[1]
    echo -n $data | xxd -p | tr -d '\n'
end

set action $argv[1]

if test (count $argv) -eq 3
    set args '["'$argv[2]'", "'$argv[3]'"]'
else
    set args '["'$argv[2]'"]'
end

set data (hexencode '{"Nonce": "'(gdate +%s)'","Action":"'$action'","Args":'$args'}')
set signature (go run sign/main.go $privKey $data)
set params (hexencode '{"Owner": "'$pubKey'", "Signature": "'$signature'", "Data": "'$data'"}')
set res (http -j POST $host:46657 method=broadcast_tx_sync params:='["'$params'"]')
set log (echo $res |  jq -r '.result[1].log')
set data (echo $res |  jq -r '.result[1].data' | xxd -r -p)

echo 'data: ' $data
echo 'log: ' $log


