package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tendermint/go-crypto"
	"github.com/tendermint/tmsp/types"
)

const (
	pubAlex  = "0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
	pubBrat  = "014EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174"
	privAlex = "016E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D04D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
	privBrat = "014BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A4EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174"
)

var masters = []string{pubAlex}

type MessagePak struct {
	PublicKey  string
	PrivateKey string
	Action     string
	Args       []string
}

var tests = []struct {
	name string
	paks []MessagePak
	log  string
	data []byte
}{
	// ==========================
	// sanity checks ------------
	// ==========================
	{"sanity ask arg less", []MessagePak{
		{pubAlex, privAlex, "ask", []string{}},
	}, "error: ask should have 1 argument", []byte{}},

	{"sanity ask arg more", []MessagePak{
		{pubAlex, privAlex, "ask", []string{"a", "b"}},
	}, "error: ask should have 1 argument", []byte{}},

	{"sanity ask data", []MessagePak{
		{pubAlex, privAlex, "ask", []string{""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity reg arg less 1", []MessagePak{
		{pubAlex, privAlex, "reg", []string{}},
	}, "error: reg should have 2 arguments", []byte{}},

	{"sanity reg arg less 2", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"a"}},
	}, "error: reg should have 2 arguments", []byte{}},

	{"sanity reg arg more", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"a", "b", "c"}},
	}, "error: reg should have 2 arguments", []byte{}},

	{"sanity reg data", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"", ""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity reg meta", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", ""}},
	}, "error: meta cannot be null", []byte{}},

	{"sanity free arg less", []MessagePak{
		{pubAlex, privAlex, "free", []string{}},
	}, "error: free should have 1 argument", []byte{}},

	{"sanity free arg more", []MessagePak{
		{pubAlex, privAlex, "free", []string{"a", "b"}},
	}, "error: free should have 1 argument", []byte{}},

	{"sanity free data", []MessagePak{
		{pubAlex, privAlex, "free", []string{""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity own arg less", []MessagePak{
		{pubAlex, privAlex, "own", []string{}},
	}, "error: own should have 1 argument", []byte{}},

	{"sanity own arg more", []MessagePak{
		{pubAlex, privAlex, "own", []string{"a", "b"}},
	}, "error: own should have 1 argument", []byte{}},

	{"sanity own data", []MessagePak{
		{pubAlex, privAlex, "own", []string{""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity pass arg less 1", []MessagePak{
		{pubAlex, privAlex, "pass", []string{}},
	}, "error: pass should have 2 arguments", []byte{}},

	{"sanity pass arg less 2", []MessagePak{
		{pubAlex, privAlex, "pass", []string{"a"}},
	}, "error: pass should have 2 arguments", []byte{}},

	{"sanity pass arg more", []MessagePak{
		{pubAlex, privAlex, "pass", []string{"a", "b", "c"}},
	}, "error: pass should have 2 arguments", []byte{}},

	{"sanity pass data", []MessagePak{
		{pubAlex, privAlex, "pass", []string{"", ""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity pass owner", []MessagePak{
		{pubAlex, privAlex, "pass", []string{"alex.com", ""}},
	}, "error: owner cannot be null", []byte{}},

	{"sanity mod arg less 1", []MessagePak{
		{pubAlex, privAlex, "mod", []string{}},
	}, "error: mod should have 2 arguments", []byte{}},

	{"sanity mod arg less 2", []MessagePak{
		{pubAlex, privAlex, "mod", []string{"a"}},
	}, "error: mod should have 2 arguments", []byte{}},

	{"sanity mod arg more", []MessagePak{
		{pubAlex, privAlex, "mod", []string{"a", "b", "c"}},
	}, "error: mod should have 2 arguments", []byte{}},

	{"sanity mod data", []MessagePak{
		{pubAlex, privAlex, "mod", []string{"", ""}},
	}, "error: data cannot be null", []byte{}},

	{"sanity mod meta", []MessagePak{
		{pubAlex, privAlex, "mod", []string{"alex.com", ""}},
	}, "error: meta cannot be null", []byte{}},

	{"sanity unknown action", []MessagePak{
		{pubAlex, privAlex, "revolve", []string{}},
	}, "error: unknown action", []byte{}},

	// ==========================
	// func checks --------------
	// ==========================
	{"simple ask", []MessagePak{
		{pubAlex, privAlex, "ask", []string{"alex.com"}},
	}, "error: data not found", []byte{}},

	{"simple free", []MessagePak{
		{pubAlex, privAlex, "free", []string{"alex.com"}},
	}, "error: data not found", []byte{}},

	{"simple reg", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
	}, "ok, can reg", []byte{}},

	{"reg ask", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "ask", []string{"alex.com"}},
	}, "ok, data found", []byte("Alex")},

	{"reg own", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "own", []string{"alex.com"}},
	}, "ok, data found", []byte(pubAlex)},

	{"double reg", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
	}, "error: data exists", []byte{}},

	{"reg free ask", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "free", []string{"alex.com"}},
		{pubAlex, privAlex, "ask", []string{"alex.com"}},
	}, "error: data not found", []byte{}},

	{"reg mod", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "mod", []string{"alex.com", "Alex"}},
	}, "ok, can mod", []byte{}},

	{"reg mod ask", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "mod", []string{"alex.com", "Mr Nobody"}},
		{pubAlex, privAlex, "ask", []string{"alex.com"}},
	}, "ok, data found", []byte("Mr Nobody")},

	{"mod unathorized", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubBrat, privBrat, "mod", []string{"alex.com", "Alex"}},
	}, "error: not authorized", []byte{}},

	{"reg pass", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubAlex}},
	}, "ok, can pass", []byte{}},

	{"reg pass own", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubAlex, privAlex, "own", []string{"alex.com"}},
	}, "ok, data found", []byte(pubBrat)},

	{"pass unathorized", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubBrat, privBrat, "pass", []string{"alex.com", pubBrat}},
	}, "error: not authorized", []byte{}},

	{"reg unathorized", []MessagePak{
		{pubBrat, privBrat, "reg", []string{"brat.com", "Brat"}},
	}, "error: not authorized", []byte{}},

	{"free unathorized", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"brat.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"brat.com", pubBrat}},
		{pubBrat, privBrat, "free", []string{"brat.com"}},
	}, "error: not authorized", []byte{}},

	{"pass authorized user", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubBrat, privBrat, "pass", []string{"alex.com", pubAlex}},
	}, "ok, can pass", []byte{}},

	{"pass force authorized master", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
	}, "ok, can pass", []byte{}},

	{"mod force authorized master", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubAlex, privAlex, "mod", []string{"alex.com", "Sophie"}},
	}, "ok, can mod", []byte{}},

	{"pass unathorized user", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubBrat, privBrat, "pass", []string{"alex.com", pubAlex}},
		{pubBrat, privBrat, "pass", []string{"alex.com", pubAlex}},
	}, "error: not authorized", []byte{}},

	{"mod unathorized user", []MessagePak{
		{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}},
		{pubAlex, privAlex, "pass", []string{"alex.com", pubBrat}},
		{pubBrat, privBrat, "pass", []string{"alex.com", pubAlex}},
		{pubBrat, privBrat, "mod", []string{"alex.com", "Larry"}},
	}, "error: not authorized", []byte{}},
}

func TestFunc(t *testing.T) {

	for _, test := range tests {
		app := *NewInMemoryApp(masters)
		var res types.Result
		for _, pak := range test.paks {
			res = testMessagePak(pak, &app, t)
		}
		compareResult(test.name, res, string(test.data), test.log, t)
	}
}

// ==========================
// missing data -------------
// ==========================

func TestMissingMessage(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "", Owner: "FEED", Signature: "AAEE"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("missing message", res, "", "error: message cannot be null", t)
}

func TestMissingOwner(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "DEADBEEF", Owner: "", Signature: "AAEE"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("missing owner", res, "", "error: owner cannot be null", t)
}

func TestMissingSignature(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "DEADBEEF", Owner: "FEED", Signature: ""}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("missing signature", res, "", "error: signature cannot be null", t)
}

// ==========================
// json decoding ------------
// ==========================

func TestTxJsonDecoding(t *testing.T) {
	app := *NewInMemoryApp(masters)
	txdata := []byte("not-a-valid-json-string")
	res := app.CheckTx(txdata)
	compareResult("tx json decoding", res, "", "error: decoding tx JSON", t)
}

func TestMessageJsonDecoding(t *testing.T) {
	app := *NewInMemoryApp(masters)
	messageDataHex := "DEADBEEF"
	messageData, _ := hex.DecodeString(messageDataHex)
	privKeyBytes, _ := hex.DecodeString(privAlex)
	privKey, _ := crypto.PrivKeyFromBytes(privKeyBytes)
	signature := hex.EncodeToString(privKey.Sign(messageData).Bytes())
	signedMessage := SignedMessage{Data: messageDataHex, Owner: pubAlex, Signature: signature}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("message json decoding", res, "", "error: decoding message JSON", t)
}

// ==========================
// hex decoding -------------
// ==========================

func TestMessageHexDecoding(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "not-hex-encoded-string", Owner: "FEED", Signature: "AAEE"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("message hex decoding", res, "", "error: decoding hex data", t)
}

func TestOwnerHexDecoding(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "DEADBEEF", Owner: "not-hex-encoded-string", Signature: "AAEE"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("owner hex decoding", res, "", "error: cannot decode owner", t)
}

func TestSignatureHexDecoding(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "DEADBEEF", Owner: "FEED", Signature: "not-hex-encoded-string"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("signature hex decoding", res, "", "error: cannot decode signature", t)
}

func TestUnmarshalPubKey(t *testing.T) {
	app := *NewInMemoryApp(masters)
	signedMessage := SignedMessage{Data: "DEADBEEF", Owner: "FEED", Signature: "AAEE"}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	compareResult("unmarshal pub key", res, "", "error: cannot read pubkey", t)
}

func TestPersistency(t *testing.T) {
	dir, err := ioutil.TempDir("", "testPersistency")
	if err != nil {
		t.Errorf("cannot create temp directory")
	}

	defer os.RemoveAll(dir) // clean up

	var pak MessagePak
	var app Application
	var res types.Result

	app = *NewPersistentApp(dir+"/database.db", masters)

	pak = MessagePak{pubAlex, privAlex, "reg", []string{"alex.com", "Alex"}}
	res = testMessagePak(pak, &app, t)
	compareResult("persistency check 1", res, "", "ok, can reg", t)

	app.Close()

	app = *NewPersistentApp(dir+"/database.db", masters)
	pak = MessagePak{pubAlex, privAlex, "ask", []string{"alex.com"}}
	res = testMessagePak(pak, &app, t)
	compareResult("persistency check 2", res, "Alex", "ok, data found", t)

}

// ==========================
// helpers ------------------
// ==========================

func testMessagePak(pak MessagePak, app *Application, t *testing.T) types.Result {

	message := Message{Nonce: "1", Action: pak.Action, Args: pak.Args}
	messageData, _ := json.Marshal(message)
	messageDataHex := hex.EncodeToString(messageData)
	privKeyBytes, _ := hex.DecodeString(pak.PrivateKey)
	privKey, _ := crypto.PrivKeyFromBytes(privKeyBytes)
	signature := hex.EncodeToString(privKey.Sign(messageData).Bytes())
	signedMessage := SignedMessage{Data: messageDataHex, Owner: pak.PublicKey, Signature: signature}
	txdata, _ := json.Marshal(signedMessage)
	res := app.CheckTx(txdata)
	app.AppendTx(txdata)

	return res
}

func compareResult(name string, res types.Result, data, log string, t *testing.T) {
	if res.Log != log {
		t.Errorf("\"%s\" failed, got \"%v\"; want \"%v\"", name, res.Log, log)
	}
	if !equals(res.Data, []byte(data)) {
		t.Errorf("\"%s\" failed, got \"%v\"; want \"%v\"", name, string(res.Data), data)
	}
}

func equals(a1, a2 []byte) bool {
	if len(a1) != len(a2) {
		return false
	}

	for i, item1 := range a1 {
		if item1 != a2[i] {
			return false
		}
	}

	return true
}

// func TestGenKeys(t *testing.T) {

// 	for i := 0; i < 10; i++ {
// 		secret := []byte{byte(i)}
// 		privKey := crypto.GenPrivKeyEd25519FromSecret(secret)
// 		pubKey := privKey.PubKey()
// 		t.Logf("secret: %X, pubKey: %X, privKey: %X", secret, pubKey.Bytes(), privKey.Bytes())
// 	}

// }

// ==========================
// public - private pairs ---
// ==========================
// "0104D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1": "016E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D04D3BE256C58CAA83F87008D3537FE3928B814F2EF6FE09D0A00CD090A74CFA1"
// "014EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174": "014BF5122F344554C53BDE2EBB8CD2B7E3D1600AD631C385A5D7CCE23C7785459A4EEAAADF130120EDE39396A95A48A46377E1A81503B1161A777116E56C9C8174"
// "015710507DF12263139FCD4A386E6FA441EE7242F772FBEA5227DE8F3C00742B21": "01DBC1B4C900FFE48D575B5DA5C638040125F65DB0FE3E24494B76EA986457D9865710507DF12263139FCD4A386E6FA441EE7242F772FBEA5227DE8F3C00742B21"
// "0193FBCE7316450A74E8A7F12DFB32131096CC06F4F08B63CBF649317B21869DB8": "01084FED08B978AF4D7D196A7446A86B58009E636B611DB16211B65A9AADFF29C593FBCE7316450A74E8A7F12DFB32131096CC06F4F08B63CBF649317B21869DB8"
// "01B84B18824FCD1F89D54F7CF656B51339007B935FDDFE170933E97C83BBA2D0A5": "01E52D9C508C502347344D8C07AD91CBD6068AFC75FF6292F062A09CA381C89E71B84B18824FCD1F89D54F7CF656B51339007B935FDDFE170933E97C83BBA2D0A5"
// "0180FED1B8CFF04E77A07DCFD4DD26A5B649081249FFA14DB6ABCEBD0339C45432": "01E77B9A9AE9E30B0DBDB6F510A264EF9DE781501D7B6B92AE89EB059C5AB743DB80FED1B8CFF04E77A07DCFD4DD26A5B649081249FFA14DB6ABCEBD0339C45432"
// "01A9AC0CF99119D37289F68467B35946A1AE8DB1A2E28560C80CBD1CD52A071DAB": "0167586E98FAD27DA0B9968BC039A1EF34C939B9B8E523A8BEF89D478608C5ECF6A9AC0CF99119D37289F68467B35946A1AE8DB1A2E28560C80CBD1CD52A071DAB"
// "01DF84BEE1F1D75814472E65C50943A39666B229723FFEA50E91DD4F6A85C45D18": "01CA358758F6D27E6CF45272937977A748FD88391DB679CEDA7DC7BF1F005EE879DF84BEE1F1D75814472E65C50943A39666B229723FFEA50E91DD4F6A85C45D18"
// "01D98330445F40711A43809242AD5BE98314F76E433135BABA4772A07D88FC1DBC": "01BEEAD77994CF573341EC17B58BBF7EB34D2711C993C1D976B128B3188DC1829AD98330445F40711A43809242AD5BE98314F76E433135BABA4772A07D88FC1DBC"
// "01E09480E3D2A8663A48DEA67EE478916FD24CD27B09162107835DF53F0060A4AC": "012B4C342F5433EBE591A1DA77E013D1B72475562D48578DCA8B84BAC6651C3CB9E09480E3D2A8663A48DEA67EE478916FD24CD27B09162107835DF53F0060A4AC"
