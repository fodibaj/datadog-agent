package trace

// Code generated by github.com/tinylib/msgp DO NOT EDIT.

import (
	"github.com/tinylib/msgp/msgp"
)

// MarshalMsg implements msgp.Marshaler
func (z *Span) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0001Len := uint32(14)
	var zb0001Mask uint16 /* 14 bits */
	if z.Meta == nil {
		zb0001Len--
		zb0001Mask |= 0x200
	}
	if z.Metrics == nil {
		zb0001Len--
		zb0001Mask |= 0x400
	}
	if z.MetaStruct == nil {
		zb0001Len--
		zb0001Mask |= 0x1000
	}
	if z.SpanLinks == nil {
		zb0001Len--
		zb0001Mask |= 0x2000
	}
	// variable map header, size zb0001Len
	o = append(o, 0x80|uint8(zb0001Len))
	if zb0001Len == 0 {
		return
	}
	// string "service"
	o = append(o, 0xa7, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65)
	o = msgp.AppendString(o, z.Service)
	// string "name"
	o = append(o, 0xa4, 0x6e, 0x61, 0x6d, 0x65)
	o = msgp.AppendString(o, z.Name)
	// string "resource"
	o = append(o, 0xa8, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65)
	o = msgp.AppendString(o, z.Resource)
	// string "trace_id"
	o = append(o, 0xa8, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x69, 0x64)
	o = msgp.AppendUint64(o, z.TraceID)
	// string "span_id"
	o = append(o, 0xa7, 0x73, 0x70, 0x61, 0x6e, 0x5f, 0x69, 0x64)
	o = msgp.AppendUint64(o, z.SpanID)
	// string "parent_id"
	o = append(o, 0xa9, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64)
	o = msgp.AppendUint64(o, z.ParentID)
	// string "start"
	o = append(o, 0xa5, 0x73, 0x74, 0x61, 0x72, 0x74)
	o = msgp.AppendInt64(o, z.Start)
	// string "duration"
	o = append(o, 0xa8, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e)
	o = msgp.AppendInt64(o, z.Duration)
	// string "error"
	o = append(o, 0xa5, 0x65, 0x72, 0x72, 0x6f, 0x72)
	o = msgp.AppendInt32(o, z.Error)
	if (zb0001Mask & 0x200) == 0 { // if not empty
		// string "meta"
		o = append(o, 0xa4, 0x6d, 0x65, 0x74, 0x61)
		o = msgp.AppendMapHeader(o, uint32(len(z.Meta)))
		for za0001, za0002 := range z.Meta {
			o = msgp.AppendString(o, za0001)
			o = msgp.AppendString(o, za0002)
		}
	}
	if (zb0001Mask & 0x400) == 0 { // if not empty
		// string "metrics"
		o = append(o, 0xa7, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73)
		o = msgp.AppendMapHeader(o, uint32(len(z.Metrics)))
		for za0003, za0004 := range z.Metrics {
			o = msgp.AppendString(o, za0003)
			o = msgp.AppendFloat64(o, za0004)
		}
	}
	// string "type"
	o = append(o, 0xa4, 0x74, 0x79, 0x70, 0x65)
	o = msgp.AppendString(o, z.Type)
	if (zb0001Mask & 0x1000) == 0 { // if not empty
		// string "meta_struct"
		o = append(o, 0xab, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74)
		o = msgp.AppendMapHeader(o, uint32(len(z.MetaStruct)))
		for za0005, za0006 := range z.MetaStruct {
			o = msgp.AppendString(o, za0005)
			o = msgp.AppendBytes(o, za0006)
		}
	}
	if (zb0001Mask & 0x2000) == 0 { // if not empty
		// string "span_links"
		o = append(o, 0xaa, 0x73, 0x70, 0x61, 0x6e, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x73)
		o = msgp.AppendArrayHeader(o, uint32(len(z.SpanLinks)))
		for za0007 := range z.SpanLinks {
			if z.SpanLinks[za0007] == nil {
				o = msgp.AppendNil(o)
			} else {
				o, err = z.SpanLinks[za0007].MarshalMsg(o)
				if err != nil {
					err = msgp.WrapError(err, "SpanLinks", za0007)
					return
				}
			}
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Span) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	hook, hookok := MetaHook()
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "service":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Service = ""
				break
			}
			z.Service, bts, err = parseStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Service")
				return
			}
		case "name":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Name = ""
				break
			}
			z.Name, bts, err = parseStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Service")
				return
			}
		case "resource":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Resource = ""
				break
			}
			z.Resource, bts, err = parseStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Service")
				return
			}
		case "trace_id":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.TraceID = 0
				break
			}
			z.TraceID, bts, err = parseUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "TraceID")
				return
			}
		case "span_id":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.SpanID = 0
				break
			}
			z.SpanID, bts, err = parseUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "SpanID")
				return
			}
		case "parent_id":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.ParentID = 0
				break
			}
			z.ParentID, bts, err = parseUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "ParentID")
				return
			}
		case "start":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Start = 0
				break
			}
			z.Start, bts, err = parseInt64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Start")
				return
			}
		case "duration":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Duration = 0
				break
			}
			z.Duration, bts, err = parseInt64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Duration")
				return
			}
		case "error":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Error = 0
				break
			}
			z.Error, bts, err = parseInt32Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Error")
				return
			}
		case "meta":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Meta = nil
				break
			}
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Meta")
				return
			}
			if z.Meta == nil && zb0002 > 0 {
				z.Meta = make(map[string]string, zb0002)
			} else if len(z.Meta) > 0 {
				for key := range z.Meta {
					delete(z.Meta, key)
				}
			}
			for zb0002 > 0 {
				var za0001 string
				var za0002 string
				zb0002--
				za0001, bts, err = parseStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Meta")
					return
				}
				za0002, bts, err = parseStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Meta", za0001)
					return
				}
				if hookok {
					z.Meta[za0001] = hook(za0001, za0002)
				} else {
					z.Meta[za0001] = za0002
				}
			}
		case "metrics":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Metrics = nil
				break
			}
			var zb0003 uint32
			zb0003, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Metrics")
				return
			}
			if z.Metrics == nil && zb0003 > 0 {
				z.Metrics = make(map[string]float64, zb0003)
			} else if len(z.Metrics) > 0 {
				for key := range z.Metrics {
					delete(z.Metrics, key)
				}
			}
			for zb0003 > 0 {
				var za0003 string
				var za0004 float64
				zb0003--
				za0003, bts, err = parseStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Metrics")
					return
				}
				za0004, bts, err = parseFloat64Bytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Metrics", za0003)
					return
				}
				z.Metrics[za0003] = za0004
			}
		case "type":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				z.Type = ""
				break
			}
			z.Type, bts, err = parseStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Type")
				return
			}
		case "meta_struct":
			var zb0004 uint32
			zb0004, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "MetaStruct")
				return
			}
			if z.MetaStruct == nil {
				z.MetaStruct = make(map[string][]byte, zb0004)
			} else if len(z.MetaStruct) > 0 {
				for key := range z.MetaStruct {
					delete(z.MetaStruct, key)
				}
			}
			for zb0004 > 0 {
				var za0005 string
				var za0006 []byte
				zb0004--
				za0005, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "MetaStruct")
					return
				}
				za0006, bts, err = msgp.ReadBytesBytes(bts, za0006)
				if err != nil {
					err = msgp.WrapError(err, "MetaStruct", za0005)
					return
				}
				z.MetaStruct[za0005] = za0006
			}
		case "span_links":
			var zb0005 uint32
			zb0005, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "SpanLinks")
				return
			}
			if cap(z.SpanLinks) >= int(zb0005) {
				z.SpanLinks = (z.SpanLinks)[:zb0005]
			} else {
				z.SpanLinks = make([]*SpanLink, zb0005)
			}
			for za0007 := range z.SpanLinks {
				if msgp.IsNil(bts) {
					bts, err = msgp.ReadNilBytes(bts)
					if err != nil {
						return
					}
					z.SpanLinks[za0007] = nil
				} else {
					if z.SpanLinks[za0007] == nil {
						z.SpanLinks[za0007] = new(SpanLink)
					}
					bts, err = z.SpanLinks[za0007].UnmarshalMsg(bts)
					if err != nil {
						err = msgp.WrapError(err, "SpanLinks", za0007)
						return
					}
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *Span) Msgsize() (s int) {
	s = 1 + 8 + msgp.StringPrefixSize + len(z.Service) + 5 + msgp.StringPrefixSize + len(z.Name) + 9 + msgp.StringPrefixSize + len(z.Resource) + 9 + msgp.Uint64Size + 8 + msgp.Uint64Size + 10 + msgp.Uint64Size + 6 + msgp.Int64Size + 9 + msgp.Int64Size + 6 + msgp.Int32Size + 5 + msgp.MapHeaderSize
	if z.Meta != nil {
		for za0001, za0002 := range z.Meta {
			_ = za0002
			s += msgp.StringPrefixSize + len(za0001) + msgp.StringPrefixSize + len(za0002)
		}
	}
	s += 8 + msgp.MapHeaderSize
	if z.Metrics != nil {
		for za0003, za0004 := range z.Metrics {
			_ = za0004
			s += msgp.StringPrefixSize + len(za0003) + msgp.Float64Size
		}
	}
	s += 5 + msgp.StringPrefixSize + len(z.Type) + 12 + msgp.MapHeaderSize
	if z.MetaStruct != nil {
		for za0005, za0006 := range z.MetaStruct {
			_ = za0006
			s += msgp.StringPrefixSize + len(za0005) + msgp.BytesPrefixSize + len(za0006)
		}
	}
	s += 11 + msgp.ArrayHeaderSize
	for za0007 := range z.SpanLinks {
		if z.SpanLinks[za0007] == nil {
			s += msgp.NilSize
		} else {
			s += z.SpanLinks[za0007].Msgsize()
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *SpanLink) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0001Len := uint32(6)
	var zb0001Mask uint8 /* 6 bits */
	if z.TraceIDHigh == 0 {
		zb0001Len--
		zb0001Mask |= 0x2
	}
	if z.Attributes == nil {
		zb0001Len--
		zb0001Mask |= 0x8
	}
	if z.Tracestate == "" {
		zb0001Len--
		zb0001Mask |= 0x10
	}
	if z.Flags == 0 {
		zb0001Len--
		zb0001Mask |= 0x20
	}
	// variable map header, size zb0001Len
	o = append(o, 0x80|uint8(zb0001Len))
	if zb0001Len == 0 {
		return
	}
	// string "trace_id"
	o = append(o, 0xa8, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x69, 0x64)
	o = msgp.AppendUint64(o, z.TraceID)
	if (zb0001Mask & 0x2) == 0 { // if not empty
		// string "trace_id_high"
		o = append(o, 0xad, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x5f, 0x68, 0x69, 0x67, 0x68)
		o = msgp.AppendUint64(o, z.TraceIDHigh)
	}
	// string "span_id"
	o = append(o, 0xa7, 0x73, 0x70, 0x61, 0x6e, 0x5f, 0x69, 0x64)
	o = msgp.AppendUint64(o, z.SpanID)
	if (zb0001Mask & 0x8) == 0 { // if not empty
		// string "attributes"
		o = append(o, 0xaa, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73)
		o = msgp.AppendMapHeader(o, uint32(len(z.Attributes)))
		for za0001, za0002 := range z.Attributes {
			o = msgp.AppendString(o, za0001)
			o = msgp.AppendString(o, za0002)
		}
	}
	if (zb0001Mask & 0x10) == 0 { // if not empty
		// string "tracestate"
		o = append(o, 0xaa, 0x74, 0x72, 0x61, 0x63, 0x65, 0x73, 0x74, 0x61, 0x74, 0x65)
		o = msgp.AppendString(o, z.Tracestate)
	}
	if (zb0001Mask & 0x20) == 0 { // if not empty
		// string "flags"
		o = append(o, 0xa5, 0x66, 0x6c, 0x61, 0x67, 0x73)
		o = msgp.AppendUint32(o, z.Flags)
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *SpanLink) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "trace_id":
			z.TraceID, bts, err = msgp.ReadUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "TraceID")
				return
			}
		case "trace_id_high":
			z.TraceIDHigh, bts, err = msgp.ReadUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "TraceIDHigh")
				return
			}
		case "span_id":
			z.SpanID, bts, err = msgp.ReadUint64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "SpanID")
				return
			}
		case "attributes":
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Attributes")
				return
			}
			if z.Attributes == nil {
				z.Attributes = make(map[string]string, zb0002)
			} else if len(z.Attributes) > 0 {
				for key := range z.Attributes {
					delete(z.Attributes, key)
				}
			}
			for zb0002 > 0 {
				var za0001 string
				var za0002 string
				zb0002--
				za0001, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Attributes")
					return
				}
				za0002, bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Attributes", za0001)
					return
				}
				z.Attributes[za0001] = za0002
			}
		case "tracestate":
			z.Tracestate, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Tracestate")
				return
			}
		case "flags":
			z.Flags, bts, err = msgp.ReadUint32Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Flags")
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *SpanLink) Msgsize() (s int) {
	s = 1 + 9 + msgp.Uint64Size + 14 + msgp.Uint64Size + 8 + msgp.Uint64Size + 11 + msgp.MapHeaderSize
	if z.Attributes != nil {
		for za0001, za0002 := range z.Attributes {
			_ = za0002
			s += msgp.StringPrefixSize + len(za0001) + msgp.StringPrefixSize + len(za0002)
		}
	}
	s += 11 + msgp.StringPrefixSize + len(z.Tracestate) + 6 + msgp.Uint32Size
	return
}
