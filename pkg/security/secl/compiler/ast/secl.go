// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ast

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

type ParsingContext struct {
	ruleParser  *participle.Parser[Rule]
	macroParser *participle.Parser[Macro]
}

func NewParsingContext() *ParsingContext {
	/*seclLexer := lexer.Must(ebnf.New(`
	Comment = ("#" | "//") { "\u0000"…"\uffff"-"\n" } .
	CIDR = IP "/" digit { digit } .
	IP = (ipv4 | ipv6) .
	Variable = "${" (alpha | "_") { "_" | alpha | digit | "." } "}" .
	Duration = digit { digit } ("m" | "s" | "m" | "h") { "s" } .
	Regexp = "r\"" { "\u0000"…"\uffff"-"\""-"\\" | "\\" any } "\"" .
	Ident = (alpha | "_") { "_" | alpha | digit | "." | "[" | "]" } .
	String = "\"" { "\u0000"…"\uffff"-"\""-"\\" | "\\" any } "\"" .
	Pattern = "~\"" { "\u0000"…"\uffff"-"\""-"\\" | "\\" any } "\"" .
	Int = [ "-" | "+" ] digit { digit } .
	Punct = "!"…"/" | ":"…"@" | "["…` + "\"`\"" + ` | "{"…"~" .
	Whitespace = ( " " | "\t" | "\n" ) { " " | "\t" | "\n" } .
	ipv4 = (digit { digit } "." digit { digit } "." digit { digit } "." digit { digit }) .
	ipv6 = ( [hex { hex }] ":" [hex { hex }] ":" [hex { hex }] [":" | "."] [hex { hex }] [":" | "."] [hex { hex }] [":" | "."] [hex { hex }] [":" | "."] [hex { hex }] [":" | "."] [hex { hex }]) .
	hex = "a"…"f" | "A"…"F" | "0"…"9" .
	alpha = "a"…"z" | "A"…"Z" .
	digit = "0"…"9" .
	any = "\u0000"…"\uffff" .
	`))*/

	ipv4 := `([[:digit:]]+\.){3}[[:digit:]]+`
	ipv6 := `([[:xdigit:]]*(:|\.)){2,7}[[:xdigit:]]*`
	ip := fmt.Sprintf("(%s)|(%s)", ipv4, ipv6)

	seclLexer := lexer.MustSimple([]lexer.SimpleRule{
		{Name: "Comment", Pattern: `(#|//)[^\n]*`},
		{Name: "Whitespace", Pattern: `\s+`},

		{Name: "CIDR", Pattern: fmt.Sprintf(`(%s)/[[:digit:]]+`, ip)},
		{Name: "IP", Pattern: ip},

		{Name: "Variable", Pattern: `\${([[:alpha:]]|_)([[:alnum:]]|[_\.])*}`},
		{Name: "Duration", Pattern: `[[:digit:]]+(ms|s|m|h|d)`},

		{Name: "Pattern", Pattern: `~"([^\\"]|\\.)*"`},
		{Name: "Regexp", Pattern: `r"([^\\"]|\\.)*"`},
		{Name: "String", Pattern: `"([^\\"]|\\.)*"`},

		{Name: "Ident", Pattern: `([[:alpha:]]|_)([[:alnum:]]|[_\.\[\]])*`},
		{Name: "Int", Pattern: `[+-]?[[:digit:]]+`},

		{Name: "Punct", Pattern: `[[:punct:]]`},
	})

	return &ParsingContext{
		ruleParser:  buildParser[Rule](seclLexer),
		macroParser: buildParser[Macro](seclLexer),
	}
}

func buildParser[T any](lexer lexer.Definition) *participle.Parser[T] {
	parser, err := participle.Build[T](
		participle.Lexer(lexer),
		participle.Elide("Whitespace", "Comment"),
		participle.Unquote("String"),
		participle.Map(parseDuration, "Duration"),
		participle.Map(unquotePattern, "Pattern", "Regexp"),
	)
	if err != nil {
		panic(err)
	}
	return parser
}

func unquotePattern(t lexer.Token) (lexer.Token, error) {
	unquoted := strings.TrimSpace(t.Value[1:])
	unquoted = unquoted[1 : len(unquoted)-1]
	t.Value = unquoted
	return t, nil
}

func parseDuration(t lexer.Token) (lexer.Token, error) {
	duration, err := time.ParseDuration(t.Value)
	if err != nil {
		return t, participle.Errorf(t.Pos, "invalid duration string %q: %s", t.Value, err)
	}

	t.Value = strconv.Itoa(int(duration.Nanoseconds()))

	return t, nil
}

// ParseRule parses a SECL rule.
func (pc *ParsingContext) ParseRule(expr string) (*Rule, error) {
	rule, err := pc.ruleParser.Parse("", bytes.NewBufferString(expr))
	if err != nil {
		return nil, err
	}
	rule.Expr = expr
	return rule, nil
}

// Rule describes a SECL rule
type Rule struct {
	Pos  lexer.Position
	Expr string

	BooleanExpression *BooleanExpression `parser:"@@"`
}

// ParseMacro parses a SECL macro
func (pc *ParsingContext) ParseMacro(expr string) (*Macro, error) {
	return pc.macroParser.Parse("", bytes.NewBufferString(expr))
}

// Macro describes a SECL macro
type Macro struct {
	Pos lexer.Position

	Expression *Expression `parser:"@@"`
	Array      *Array      `parser:"| @@"`
	Primary    *Primary    `parser:"| @@"`
}

// BooleanExpression describes a boolean expression
type BooleanExpression struct {
	Pos lexer.Position

	Expression *Expression `parser:"@@"`
}

// Expression describes an expression
type Expression struct {
	Pos lexer.Position

	Comparison *Comparison        `parser:"@@"`
	Op         *string            `parser:"[ @( \"|\" \"|\" | \"or\" | \"&\" \"&\" | \"and\" )"`
	Next       *BooleanExpression `parser:"@@ ]"`
}

// Comparison describes a comparison
type Comparison struct {
	Pos lexer.Position

	ArithmeticOperation *ArithmeticOperation `parser:"@@"`
	ScalarComparison    *ScalarComparison    `parser:"[ @@"`
	ArrayComparison     *ArrayComparison     `parser:"| @@ ]"`
}

// ScalarComparison describes a scalar comparison : the operator with the right operand
type ScalarComparison struct {
	Pos lexer.Position

	Op   *string     `parser:"@( \">\" \"=\" | \">\" | \"<\" \"=\" | \"<\" | \"!\" \"=\" | \"=\" \"=\" | \"=\" \"~\" | \"!\" \"~\" )"`
	Next *Comparison `parser:"@@"`
}

// ArrayComparison describes an operation that tests membership in an array
type ArrayComparison struct {
	Pos lexer.Position

	Op    *string `parser:"( @( \"in\" | \"not\" \"in\" | \"allin\" )"`
	Array *Array  `parser:"@@ )"`
}

// BitOperation describes an operation on bits
type BitOperation struct {
	Pos lexer.Position

	Unary *Unary        `parser:"@@"`
	Op    *string       `parser:"[ @( \"&\" | \"|\" | \"^\" )"`
	Next  *BitOperation `parser:"@@ ]"`
}

type ArithmeticOperation struct {
	Pos lexer.Position

	First *BitOperation        `parser:"@@"`
	Rest  []*ArithmeticElement `parser:"[ @@ { @@ } ]"`
}

type ArithmeticElement struct {
	Op      string        `parser:"@( \"+\" | \"-\" )"`
	Operand *BitOperation `parser:"@@"`
}

// Unary describes an unary operation like logical not, binary not, minus
type Unary struct {
	Pos lexer.Position

	Op      *string  `parser:"( @( \"!\" | \"not\" | \"-\" | \"^\" )"`
	Unary   *Unary   `parser:"@@ )"`
	Primary *Primary `parser:"| @@"`
}

// Primary describes a single operand. It can be a simple identifier, a number,
// a string or a full expression in parenthesis
type Primary struct {
	Pos lexer.Position

	Ident         *string     `parser:"@Ident"`
	CIDR          *string     `parser:"| @CIDR"`
	IP            *string     `parser:"| @IP"`
	Number        *int        `parser:"| @Int"`
	Variable      *string     `parser:"| @Variable"`
	String        *string     `parser:"| @String"`
	Pattern       *string     `parser:"| @Pattern"`
	Regexp        *string     `parser:"| @Regexp"`
	Duration      *int        `parser:"| @Duration"`
	SubExpression *Expression `parser:"| \"(\" @@ \")\""`
}

// StringMember describes a String based array member
type StringMember struct {
	Pos lexer.Position

	String  *string `parser:"@String"`
	Pattern *string `parser:"| @Pattern"`
	Regexp  *string `parser:"| @Regexp"`
}

// CIDRMember describes a CIDR based array member
type CIDRMember struct {
	Pos lexer.Position

	IP   *string `parser:"@IP"`
	CIDR *string `parser:"| @CIDR"`
}

// Array describes an array of values
type Array struct {
	Pos lexer.Position

	CIDR          *string        `parser:"@CIDR"`
	Variable      *string        `parser:"| @Variable"`
	Ident         *string        `parser:"| @Ident"`
	StringMembers []StringMember `parser:"| \"[\" @@ { \",\" @@ } \"]\""`
	CIDRMembers   []CIDRMember   `parser:"| \"[\" @@ { \",\" @@ } \"]\""`
	Numbers       []int          `parser:"| \"[\" @Int { \",\" @Int } \"]\""`
}
