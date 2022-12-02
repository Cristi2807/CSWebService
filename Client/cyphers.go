package main

type CypherType string

const (
	Caesar = CypherType(rune(iota))
	CaesarPerm
	Vigenere
)

type Request struct {
	Cypher    CypherType `json:"cypher"`
	Text      string     `json:"text"`
	Method    string     `json:"method"`
	Key       int        `json:"key"`
	StringKey string     `json:"stringKey"`
}
