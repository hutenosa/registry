package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path"
	"strings"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-crypto"
	dbs "github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
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

const (
	merkleRootKey = "root"
)

func main() {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")

	defaultDbPath := path.Join(os.Getenv("HOME"), ".tendermint/data/registry.db")
	dbPath := flag.String("dbpath", defaultDbPath, "Database path (empty string for inmem)")

	mastersStr := flag.String("masterkeys", "", "Comma-separated list of hex-encoded masterkeys")
	flag.Parse()

	var masters []string
	if *mastersStr != "" {
		masters = strings.Split(*mastersStr, ",")
		log.Printf("initialized %d master keys", len(masters))
	} else {
		log.Printf("anarchy mode - no master keys defined")
	}

	// Start the listener
	var err error
	if *dbPath != "" {
		_, err = server.NewServer(*addrPtr, NewPersistentApp(*dbPath, masters))
	} else {
		_, err = server.NewServer(*addrPtr, NewInMemoryApp(masters))
	}
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// Cleanup
	})

}

type Application struct {
	state   merkle.Tree
	db      dbs.DB
	masters []string
}

func NewInMemoryApp(masters []string) *Application {
	state := merkle.NewIAVLTree(0, nil)
	return &Application{state: state, masters: masters}
}

func NewPersistentApp(databaseFileName string, masters []string) *Application {
	log.Print("use database from ", databaseFileName)
	db, err := dbs.NewLevelDB(databaseFileName)
	if err != nil {
		log.Fatal("cannot init database: ", err)
	}
	state := merkle.NewIAVLTree(0, db)
	merkleRoot := db.Get([]byte(merkleRootKey))
	if merkleRoot != nil {
		log.Printf("load merkle root '%X'\n", merkleRoot)
		state.Load(merkleRoot)
	}
	return &Application{state: state, db: db, masters: masters}
}

func (app *Application) Info() string {
	return Fmt("Merkle tree size: %v", app.state.Size())
}

func (app *Application) Close() {
	app.db.Set([]byte(merkleRootKey), app.state.Save())
	app.db.Close()
}

func (app *Application) SetOption(key string, value string) (log string) {
	return ""
}

func (app *Application) AppendTx(tx []byte) types.Result {
	if checkRes := app.CheckTx(tx); checkRes.Code != 0 {
		return checkRes
	}

	var signedMessage SignedMessage
	var message Message

	json.Unmarshal(tx, &signedMessage)
	messageData, _ := hex.DecodeString(signedMessage.Data)
	json.Unmarshal(messageData, &message)

	switch message.Action {
	case "Reg", "Mod":
		data := message.Args[0]
		meta := message.Args[1]
		app.setMerklePayload(data, MerklePayload{signedMessage.Owner, meta})
	case "Free":
		data := message.Args[0]
		app.state.Remove([]byte(data))
	case "Pass":
		data := message.Args[0]
		owner := message.Args[1]
		merklePayload, _ := app.getMerklePayload(data)
		merklePayload.Owner = owner
		app.setMerklePayload(data, merklePayload)
	}

	if app.db != nil {
		rootHash := app.state.Save()
		log.Printf("save merkle root '%X'\n", rootHash)
		app.db.Set([]byte(merkleRootKey), rootHash)
	}

	return types.OK
}

func (app *Application) CheckTx(tx []byte) types.Result {
	var sm SignedMessage

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

	var m Message
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
		if merklePayload, err := app.getMerklePayload(data); err == nil {
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
		if merklePayload, err := app.getMerklePayload(data); err == nil {
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
		if !app.isMaster(sm.Owner) {
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
		if !app.isMaster(sm.Owner) {
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
		if merklePayload, err := app.getMerklePayload(data); err == nil {
			if app.isMaster(sm.Owner) || sm.Owner == merklePayload.Owner {
				return types.NewResultOK([]byte{}, "ok, can mod")
			} else {
				return types.NewError(1, "error: not authorized")
			}
		} else {
			return types.NewResultOK([]byte{}, "error: data not found")
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
		if merklePayload, err := app.getMerklePayload(data); err == nil {
			if app.isMaster(sm.Owner) || sm.Owner == merklePayload.Owner {
				return types.NewResultOK([]byte{}, "ok, can pass")
			} else {
				return types.NewError(1, "error: not authorized")
			}
		} else {
			return types.NewResultOK([]byte{}, "error: data not found")
		}
	default:
		return types.NewError(1, "error: unknown action")
	}

}

func (app *Application) Commit() types.Result {
	hash := app.state.Hash()
	return types.NewResultOK(hash, "")
}

func (app *Application) Query(query []byte) types.Result {
	return types.OK
}

func (app *Application) isMaster(key string) bool {
	if len(app.masters) == 0 {
		return true
	}
	for _, masterKey := range app.masters {
		if key == masterKey {
			return true
		}
	}
	return false
}

func (app *Application) getMerklePayload(data string) (MerklePayload, error) {
	_, binaryData, exists := app.state.Get([]byte(data))
	if exists {
		var merklePayload MerklePayload
		buf := bytes.NewReader(binaryData)
		decoder := gob.NewDecoder(buf)
		decoder.Decode(&merklePayload)
		return merklePayload, nil
	} else {
		return MerklePayload{}, errors.New("")
	}
}

func (app *Application) setMerklePayload(data string, merklePayload MerklePayload) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	encoder.Encode(merklePayload)
	app.state.Set([]byte(data), buf.Bytes())
}
