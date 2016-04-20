package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"flag"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-crypto"
	dbs "github.com/tendermint/go-db"
	merkle "github.com/tendermint/go-merkle"
	"github.com/tendermint/go-wire"
	"github.com/tendermint/tmsp/server"
	"github.com/tendermint/tmsp/types"
)

type Message struct {
	Nonce  string
	Action string
	Args   []string
}

type SignedMessage struct {
	Data      string
	Owner     string
	Signature string
}

type MerklePayload struct {
	Owner string
	Meta  string
}

var masterKeys = []string{
	"0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1",
}

func main() {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	flag.Parse()

	// Start the listener
	_, err := server.NewServer(*addrPtr, NewInMemoryApp())
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// Cleanup
	})

}

type DummyApplication struct {
	state merkle.Tree
	db    dbs.DB
}

func NewInMemoryApp() *DummyApplication {
	state := merkle.NewIAVLTree(0, nil)
	return &DummyApplication{state: state}
}

func NewPersistentApp(databaseFileName string) *DummyApplication {
	db, err := dbs.NewLevelDB(databaseFileName)
	if err != nil {
		// TODO: abort
		fmt.Printf("error %v\n", err)
		return nil
	}
	state := merkle.NewIAVLTree(0, db)
	if db.Get([]byte("root")) != nil {
		state.Load(db.Get([]byte("root")))
	}
	return &DummyApplication{state: state, db: db}
}

func (app *DummyApplication) Info() string {
	return Fmt("size:%v", app.state.Size())
}

func (app *DummyApplication) Close() {
	app.db.Set([]byte("root"), app.state.Save())
	app.db.Close()
}

func (app *DummyApplication) SetOption(key string, value string) (log string) {
	return ""
}

func (app *DummyApplication) AppendTx(tx []byte) types.Result {
	if checkRes := app.CheckTx(tx); checkRes.Code != 0 {
		return checkRes
	}

	var signedMessage SignedMessage
	var message Message

	json.Unmarshal(tx, &signedMessage)
	messageData, _ := hex.DecodeString(signedMessage.Data)
	json.Unmarshal(messageData, &message)

	switch message.Action {
	case "Reg":
		data := message.Args[0]
		meta := message.Args[1]
		merklePayload := MerklePayload{signedMessage.Owner, meta}
		buf := new(bytes.Buffer)
		encoder := gob.NewEncoder(buf)
		encoder.Encode(merklePayload)
		app.state.Set([]byte(data), buf.Bytes())
	case "Free":
		data := message.Args[0]
		app.state.Remove([]byte(data))
	case "Mod":
		data := message.Args[0]
		meta := message.Args[1]
		merklePayload := MerklePayload{signedMessage.Owner, meta}
		buf := new(bytes.Buffer)
		encoder := gob.NewEncoder(buf)
		encoder.Encode(merklePayload)
		app.state.Set([]byte(data), buf.Bytes())
	case "Pass":
		data := message.Args[0]
		owner := message.Args[1]
		_, binaryData, _ := app.state.Get([]byte(data))
		var merklePayload MerklePayload
		buf := bytes.NewReader(binaryData)
		decoder := gob.NewDecoder(buf)
		decoder.Decode(&merklePayload)
		merklePayload.Owner = owner
		bufWriter := new(bytes.Buffer)
		encoder := gob.NewEncoder(bufWriter)
		encoder.Encode(merklePayload)
		app.state.Set([]byte(data), bufWriter.Bytes())
	}

	if app.db != nil {
		app.db.Set([]byte("root"), app.state.Save())
	}

	return types.OK
}

func (app *DummyApplication) CheckTx(tx []byte) types.Result {
	var sm SignedMessage
	var m Message

	if err := json.Unmarshal(tx, &sm); err != nil {
		return types.NewError(1, "error: decoding tx JSON")
	}

	if sm.Owner == "" {
		return types.NewError(1, "error: owner cannot be null")
	}

	if sm.Signature == "" {
		return types.NewError(1, "error: signature cannot be null")
	}

	if sm.Data == "" {
		return types.NewError(1, "error: message cannot be null")
	}

	messageData, err := hex.DecodeString(sm.Data)

	if err != nil {
		return types.NewError(1, "error: decoding hex data")
	}

	ownerBin, err := hex.DecodeString(sm.Owner)
	if err != nil {
		return types.NewError(1, "error: cannot decode owner")
	}

	signatureBin, err := hex.DecodeString(sm.Signature)
	if err != nil {
		return types.NewError(1, "error: cannot decode signature")
	}
	// check signature
	pubKey, err := crypto.PubKeyFromBytes(ownerBin)
	if err != nil {
		return types.NewError(1, "error: cannot read pubkey")
	}

	sigStruct := struct{ crypto.Signature }{}
	var n int
	sig2 := wire.ReadBinary(sigStruct, bytes.NewReader(signatureBin), 0, &n, &err)

	if !pubKey.VerifyBytes(messageData, sig2.(struct{ crypto.Signature }).Signature.(crypto.SignatureEd25519)) {
		return types.NewError(1, "error: signature not valid")
	}

	if err := json.Unmarshal(messageData, &m); err != nil {
		return types.NewError(1, "error: decoding message JSON")
	}

	switch m.Action {
	case "Ask":
		if m.Args == nil || len(m.Args) != 1 {
			return types.NewError(1, "error: ask should have 1 argument")
		}
		data := m.Args[0]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		_, binaryData, exists := app.state.Get([]byte(data))
		if exists {
			var merklePayload MerklePayload
			buf := bytes.NewReader(binaryData)
			decoder := gob.NewDecoder(buf)
			decoder.Decode(&merklePayload)
			return types.NewResultOK([]byte(merklePayload.Meta), "ok, data found")
		} else {
			return types.NewResultOK([]byte{}, "error: data not found")
		}
	case "Own":
		if m.Args == nil || len(m.Args) != 1 {
			return types.NewError(1, "error: own should have 1 argument")
		}
		data := m.Args[0]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		_, binaryData, exists := app.state.Get([]byte(data))
		if exists {
			var merklePayload MerklePayload
			buf := bytes.NewReader(binaryData)
			decoder := gob.NewDecoder(buf)
			decoder.Decode(&merklePayload)
			return types.NewResultOK([]byte(merklePayload.Owner), "ok, data found")
		} else {
			return types.NewResultOK([]byte{}, "error: data not found")
		}
	case "Reg":
		if m.Args == nil || len(m.Args) != 2 {
			return types.NewError(1, "error: reg should have 2 arguments")
		}
		data := m.Args[0]
		meta := m.Args[1]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		if meta == "" {
			return types.NewError(1, "error: meta cannot be null")
		}
		if !isMaster(sm.Owner) {
			return types.NewError(1, "error: not authorized")
		}
		if app.state.Has([]byte(data)) {
			return types.NewError(1, "error: data exists")
		} else {
			return types.NewResultOK([]byte{}, "ok, can reg")
		}
	case "Free":
		if len(m.Args) != 1 {
			return types.NewError(1, "error: free should have 1 argument")
		}
		data := m.Args[0]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		if !isMaster(sm.Owner) {
			return types.NewError(1, "error: not authorized")
		}
		if !app.state.Has([]byte(data)) {
			return types.NewError(1, "error: data not found")
		} else {
			return types.NewResultOK([]byte{}, "ok, can free")
		}
	case "Mod":
		if len(m.Args) != 2 {
			return types.NewError(1, "error: mod should have 2 arguments")
		}
		data := m.Args[0]
		newMeta := m.Args[1]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		if newMeta == "" {
			return types.NewError(1, "error: meta cannot be null")
		}
		_, binaryData, exists := app.state.Get([]byte(data))
		if exists {
			var merklePayload MerklePayload
			buf := bytes.NewReader(binaryData)
			decoder := gob.NewDecoder(buf)
			decoder.Decode(&merklePayload)
			if sm.Owner != merklePayload.Owner {
				return types.NewError(1, "error: not authorized")
			} else {
				return types.NewResultOK([]byte{}, "ok, can mod")
			}
		} else {
			return types.NewError(1, "error: data not found")
		}
	case "Pass":
		if len(m.Args) != 2 {
			return types.NewError(1, "error: pass should have 2 arguments")
		}
		data := m.Args[0]
		newOwner := m.Args[1]
		if data == "" {
			return types.NewError(1, "error: data cannot be null")
		}
		if newOwner == "" {
			return types.NewError(1, "error: owner cannot be null")
		}
		_, binaryData, exists := app.state.Get([]byte(data))
		if exists {
			var merklePayload MerklePayload
			buf := bytes.NewReader(binaryData)
			decoder := gob.NewDecoder(buf)
			decoder.Decode(&merklePayload)
			if sm.Owner != merklePayload.Owner {
				return types.NewError(1, "error: not authorized")
			} else {
				return types.NewResultOK([]byte{}, "ok, can pass")
			}
		} else {
			return types.NewError(1, "error: data not found")
		}
	default:
		return types.NewError(1, "error: unknown action")
	}

}

func (app *DummyApplication) Commit() types.Result {
	hash := app.state.Hash()
	return types.NewResultOK(hash, "")
}

func (app *DummyApplication) Query(query []byte) types.Result {
	index, value, exists := app.state.Get(query)
	resStr := Fmt("Index=%v value=%v exists=%v", index, string(value), exists)
	return types.NewResultOK([]byte(resStr), "")
}

func isMaster(key string) bool {
	for _, masterKey := range masterKeys {
		if key == masterKey {
			return true
		}
	}
	return false
}
