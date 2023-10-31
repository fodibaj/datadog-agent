// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.9
// source: datadog/trace/span.proto

package trace

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Span struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// service is the name of the service with which this span is associated.
	// @gotags: json:"service" msg:"service"
	Service string `protobuf:"bytes,1,opt,name=service,proto3" json:"service" msg:"service"`
	// name is the operation name of this span.
	// @gotags: json:"name" msg:"name"
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name" msg:"name"`
	// resource is the resource name of this span, also sometimes called the endpoint (for web spans).
	// @gotags: json:"resource" msg:"resource"
	Resource string `protobuf:"bytes,3,opt,name=resource,proto3" json:"resource" msg:"resource"`
	// traceID is the ID of the trace to which this span belongs.
	// @gotags: json:"trace_id" msg:"trace_id"
	TraceID uint64 `protobuf:"varint,4,opt,name=traceID,proto3" json:"trace_id" msg:"trace_id"`
	// spanID is the ID of this span.
	// @gotags: json:"span_id" msg:"span_id"
	SpanID uint64 `protobuf:"varint,5,opt,name=spanID,proto3" json:"span_id" msg:"span_id"`
	// parentID is the ID of this span's parent, or zero if this span has no parent.
	// @gotags: json:"parent_id" msg:"parent_id"
	ParentID uint64 `protobuf:"varint,6,opt,name=parentID,proto3" json:"parent_id" msg:"parent_id"`
	// start is the number of nanoseconds between the Unix epoch and the beginning of this span.
	// @gotags: json:"start" msg:"start"
	Start int64 `protobuf:"varint,7,opt,name=start,proto3" json:"start" msg:"start"`
	// duration is the time length of this span in nanoseconds.
	// @gotags: json:"duration" msg:"duration"
	Duration int64 `protobuf:"varint,8,opt,name=duration,proto3" json:"duration" msg:"duration"`
	// error is 1 if there is an error associated with this span, or 0 if there is not.
	// @gotags: json:"error" msg:"error"
	Error int32 `protobuf:"varint,9,opt,name=error,proto3" json:"error" msg:"error"`
	// meta is a mapping from tag name to tag value for string-valued tags.
	// @gotags: json:"meta,omitempty" msg:"meta,omitempty"
	Meta map[string]string `protobuf:"bytes,10,rep,name=meta,proto3" json:"meta,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3" msg:"meta,omitempty"`
	// metrics is a mapping from tag name to tag value for numeric-valued tags.
	// @gotags: json:"metrics,omitempty" msg:"metrics,omitempty"
	Metrics map[string]float64 `protobuf:"bytes,11,rep,name=metrics,proto3" json:"metrics,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"fixed64,2,opt,name=value,proto3" msg:"metrics,omitempty"`
	// type is the type of the service with which this span is associated.  Example values: web, db, lambda.
	// @gotags: json:"type" msg:"type"
	Type string `protobuf:"bytes,12,opt,name=type,proto3" json:"type" msg:"type"`
	// meta_struct is a registry of structured "other" data used by, e.g., AppSec.
	// @gotags: json:"meta_struct,omitempty" msg:"meta_struct,omitempty"
	MetaStruct map[string][]byte `protobuf:"bytes,13,rep,name=meta_struct,json=metaStruct,proto3" json:"meta_struct,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3" msg:"meta_struct,omitempty"`
	// @gotags: json:"semantics_schema_url" msg:"semantics_schema_url"
	SemanticsSchemaUrl string `protobuf:"bytes,14,opt,name=semantics_schema_url,json=semanticsSchemaUrl,proto3" json:"semantics_schema_url" msg:"semantics_schema_url"`
	// @gotags: json:"semantic_tags" msg:"semantic_tags"
	SemanticTags map[string]uint64 `protobuf:"bytes,15,rep,name=semantic_tags,json=semanticTags,proto3" json:"semantic_tags" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3" msg:"semantic_tags"`
}

func (x *Span) Reset() {
	*x = Span{}
	if protoimpl.UnsafeEnabled {
		mi := &file_datadog_trace_span_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Span) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Span) ProtoMessage() {}

func (x *Span) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_trace_span_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Span.ProtoReflect.Descriptor instead.
func (*Span) Descriptor() ([]byte, []int) {
	return file_datadog_trace_span_proto_rawDescGZIP(), []int{0}
}

func (x *Span) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *Span) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Span) GetResource() string {
	if x != nil {
		return x.Resource
	}
	return ""
}

func (x *Span) GetTraceID() uint64 {
	if x != nil {
		return x.TraceID
	}
	return 0
}

func (x *Span) GetSpanID() uint64 {
	if x != nil {
		return x.SpanID
	}
	return 0
}

func (x *Span) GetParentID() uint64 {
	if x != nil {
		return x.ParentID
	}
	return 0
}

func (x *Span) GetStart() int64 {
	if x != nil {
		return x.Start
	}
	return 0
}

func (x *Span) GetDuration() int64 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *Span) GetError() int32 {
	if x != nil {
		return x.Error
	}
	return 0
}

func (x *Span) GetMeta() map[string]string {
	if x != nil {
		return x.Meta
	}
	return nil
}

func (x *Span) GetMetrics() map[string]float64 {
	if x != nil {
		return x.Metrics
	}
	return nil
}

func (x *Span) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Span) GetMetaStruct() map[string][]byte {
	if x != nil {
		return x.MetaStruct
	}
	return nil
}

func (x *Span) GetSemanticsSchemaUrl() string {
	if x != nil {
		return x.SemanticsSchemaUrl
	}
	return ""
}

func (x *Span) GetSemanticTags() map[string]uint64 {
	if x != nil {
		return x.SemanticTags
	}
	return nil
}

var File_datadog_trace_span_proto protoreflect.FileDescriptor

var file_datadog_trace_span_proto_rawDesc = []byte{
	0x0a, 0x18, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2f,
	0x73, 0x70, 0x61, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x64, 0x61, 0x74, 0x61,
	0x64, 0x6f, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x22, 0xa2, 0x06, 0x0a, 0x04, 0x53, 0x70,
	0x61, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x49, 0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x49, 0x44, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x70, 0x61, 0x6e, 0x49, 0x44,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x73, 0x70, 0x61, 0x6e, 0x49, 0x44, 0x12, 0x1a,
	0x0a, 0x08, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x49, 0x44, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x08, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74,
	0x61, 0x72, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x12, 0x1a, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05,
	0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x12, 0x31, 0x0a, 0x04, 0x6d, 0x65, 0x74, 0x61, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x2e, 0x53, 0x70, 0x61, 0x6e, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x04, 0x6d, 0x65, 0x74, 0x61, 0x12, 0x3a, 0x0a, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73,
	0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x53, 0x70, 0x61, 0x6e, 0x2e, 0x4d, 0x65, 0x74, 0x72,
	0x69, 0x63, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x44, 0x0a, 0x0b, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x73, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x64, 0x61, 0x74,
	0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x53, 0x70, 0x61, 0x6e, 0x2e,
	0x4d, 0x65, 0x74, 0x61, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x0a, 0x6d, 0x65, 0x74, 0x61, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x12, 0x30, 0x0a, 0x14, 0x73,
	0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x73, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x5f,
	0x75, 0x72, 0x6c, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x73, 0x65, 0x6d, 0x61, 0x6e,
	0x74, 0x69, 0x63, 0x73, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x55, 0x72, 0x6c, 0x12, 0x4a, 0x0a,
	0x0d, 0x73, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x5f, 0x74, 0x61, 0x67, 0x73, 0x18, 0x0f,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x2e, 0x53, 0x70, 0x61, 0x6e, 0x2e, 0x53, 0x65, 0x6d, 0x61, 0x6e, 0x74,
	0x69, 0x63, 0x54, 0x61, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0c, 0x73, 0x65, 0x6d,
	0x61, 0x6e, 0x74, 0x69, 0x63, 0x54, 0x61, 0x67, 0x73, 0x1a, 0x37, 0x0a, 0x09, 0x4d, 0x65, 0x74,
	0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x1a, 0x3a, 0x0a, 0x0c, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x01, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3d,
	0x0a, 0x0f, 0x4d, 0x65, 0x74, 0x61, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3f, 0x0a,
	0x11, 0x53, 0x65, 0x6d, 0x61, 0x6e, 0x74, 0x69, 0x63, 0x54, 0x61, 0x67, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x16,
	0x5a, 0x14, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x62, 0x67, 0x6f,
	0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_datadog_trace_span_proto_rawDescOnce sync.Once
	file_datadog_trace_span_proto_rawDescData = file_datadog_trace_span_proto_rawDesc
)

func file_datadog_trace_span_proto_rawDescGZIP() []byte {
	file_datadog_trace_span_proto_rawDescOnce.Do(func() {
		file_datadog_trace_span_proto_rawDescData = protoimpl.X.CompressGZIP(file_datadog_trace_span_proto_rawDescData)
	})
	return file_datadog_trace_span_proto_rawDescData
}

var file_datadog_trace_span_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_datadog_trace_span_proto_goTypes = []interface{}{
	(*Span)(nil), // 0: datadog.trace.Span
	nil,          // 1: datadog.trace.Span.MetaEntry
	nil,          // 2: datadog.trace.Span.MetricsEntry
	nil,          // 3: datadog.trace.Span.MetaStructEntry
	nil,          // 4: datadog.trace.Span.SemanticTagsEntry
}
var file_datadog_trace_span_proto_depIdxs = []int32{
	1, // 0: datadog.trace.Span.meta:type_name -> datadog.trace.Span.MetaEntry
	2, // 1: datadog.trace.Span.metrics:type_name -> datadog.trace.Span.MetricsEntry
	3, // 2: datadog.trace.Span.meta_struct:type_name -> datadog.trace.Span.MetaStructEntry
	4, // 3: datadog.trace.Span.semantic_tags:type_name -> datadog.trace.Span.SemanticTagsEntry
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_datadog_trace_span_proto_init() }
func file_datadog_trace_span_proto_init() {
	if File_datadog_trace_span_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_datadog_trace_span_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Span); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_datadog_trace_span_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_datadog_trace_span_proto_goTypes,
		DependencyIndexes: file_datadog_trace_span_proto_depIdxs,
		MessageInfos:      file_datadog_trace_span_proto_msgTypes,
	}.Build()
	File_datadog_trace_span_proto = out.File
	file_datadog_trace_span_proto_rawDesc = nil
	file_datadog_trace_span_proto_goTypes = nil
	file_datadog_trace_span_proto_depIdxs = nil
}
