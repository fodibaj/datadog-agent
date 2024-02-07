// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package events

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjsonF642ad3eDecodeGithubComDataDogDatadogAgentPkgSecurityEvents(in *jlexer.Lexer, out *BackendEvent) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "agent":
			(out.AgentContext).UnmarshalEasyJSON(in)
		case "title":
			out.Title = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonF642ad3eEncodeGithubComDataDogDatadogAgentPkgSecurityEvents(out *jwriter.Writer, in BackendEvent) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"agent\":"
		out.RawString(prefix[1:])
		(in.AgentContext).MarshalEasyJSON(out)
	}
	{
		const prefix string = ",\"title\":"
		out.RawString(prefix)
		out.String(string(in.Title))
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v BackendEvent) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonF642ad3eEncodeGithubComDataDogDatadogAgentPkgSecurityEvents(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *BackendEvent) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonF642ad3eDecodeGithubComDataDogDatadogAgentPkgSecurityEvents(l, v)
}
func easyjsonF642ad3eDecodeGithubComDataDogDatadogAgentPkgSecurityEvents1(in *jlexer.Lexer, out *AgentContext) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeFieldName(false)
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "rule_id":
			out.RuleID = string(in.String())
		case "rule_version":
			out.RuleVersion = string(in.String())
		case "rule_actions":
			if in.IsNull() {
				in.Skip()
				out.RuleActions = nil
			} else {
				in.Delim('[')
				if out.RuleActions == nil {
					if !in.IsDelim(']') {
						out.RuleActions = make([]json.RawMessage, 0, 2)
					} else {
						out.RuleActions = []json.RawMessage{}
					}
				} else {
					out.RuleActions = (out.RuleActions)[:0]
				}
				for !in.IsDelim(']') {
					var v1 json.RawMessage
					if data := in.Raw(); in.Ok() {
						in.AddError((v1).UnmarshalJSON(data))
					}
					out.RuleActions = append(out.RuleActions, v1)
					in.WantComma()
				}
				in.Delim(']')
			}
		case "policy_name":
			out.PolicyName = string(in.String())
		case "policy_version":
			out.PolicyVersion = string(in.String())
		case "version":
			out.Version = string(in.String())
		case "os":
			out.OS = string(in.String())
		case "arch":
			out.Arch = string(in.String())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjsonF642ad3eEncodeGithubComDataDogDatadogAgentPkgSecurityEvents1(out *jwriter.Writer, in AgentContext) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"rule_id\":"
		out.RawString(prefix[1:])
		out.String(string(in.RuleID))
	}
	if in.RuleVersion != "" {
		const prefix string = ",\"rule_version\":"
		out.RawString(prefix)
		out.String(string(in.RuleVersion))
	}
	if len(in.RuleActions) != 0 {
		const prefix string = ",\"rule_actions\":"
		out.RawString(prefix)
		{
			out.RawByte('[')
			for v2, v3 := range in.RuleActions {
				if v2 > 0 {
					out.RawByte(',')
				}
				out.Raw((v3).MarshalJSON())
			}
			out.RawByte(']')
		}
	}
	if in.PolicyName != "" {
		const prefix string = ",\"policy_name\":"
		out.RawString(prefix)
		out.String(string(in.PolicyName))
	}
	if in.PolicyVersion != "" {
		const prefix string = ",\"policy_version\":"
		out.RawString(prefix)
		out.String(string(in.PolicyVersion))
	}
	if in.Version != "" {
		const prefix string = ",\"version\":"
		out.RawString(prefix)
		out.String(string(in.Version))
	}
	if in.OS != "" {
		const prefix string = ",\"os\":"
		out.RawString(prefix)
		out.String(string(in.OS))
	}
	if in.Arch != "" {
		const prefix string = ",\"arch\":"
		out.RawString(prefix)
		out.String(string(in.Arch))
	}
	out.RawByte('}')
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v AgentContext) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonF642ad3eEncodeGithubComDataDogDatadogAgentPkgSecurityEvents1(w, v)
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *AgentContext) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonF642ad3eDecodeGithubComDataDogDatadogAgentPkgSecurityEvents1(l, v)
}
