package mongodb

import (
	"encoding/hex"
	"math"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/nimi-io/better-auth-go/adapter"
	bacrypto "github.com/nimi-io/better-auth-go/crypto"
)

// idCodec converts between string ids and their BSON representation: ObjectId by default,
// BSON UUID (binary subtype 4) when generateId is "uuid". With a custom id generator ids are
// stored as given.
type idCodec struct {
	uuid   bool
	custom bool
}

// coerce ports coerceToIdType (new ObjectId(value) / new UUID(value)); ok is false when the
// string is not a valid id of that kind (the constructor would throw).
func (c idCodec) coerce(s string) (any, bool) {
	if c.uuid {
		b, ok := parseUUID(s)
		if !ok {
			return nil, false
		}
		return bson.Binary{Subtype: bson.TypeBinaryUUID, Data: b}, true
	}
	if len(s) != 24 {
		return nil, false
	}
	id, err := bson.ObjectIDFromHex(s)
	if err != nil {
		return nil, false
	}
	return id, true
}

// isInstance ports isIdInstance.
func (c idCodec) isInstance(v any) bool {
	if c.uuid {
		return isUUID(v)
	}
	_, ok := v.(bson.ObjectID)
	return ok
}

// generate returns a new id (new ObjectId() / new UUID()).
func (c idCodec) generate() any {
	if c.uuid {
		b, _ := parseUUID(bacrypto.RandomUUID())
		return bson.Binary{Subtype: bson.TypeBinaryUUID, Data: b}
	}
	return bson.NewObjectID()
}

func isUUID(v any) bool {
	b, ok := v.(bson.Binary)
	return ok && b.Subtype == bson.TypeBinaryUUID && len(b.Data) == 16
}

// parseUUID accepts 32 hex digits or the canonical hyphenated form, like the bson UUID
// constructor.
func parseUUID(s string) ([]byte, bool) {
	switch len(s) {
	case 32:
	case 36:
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return nil, false
		}
		s = strings.ReplaceAll(s, "-", "")
		if len(s) != 32 {
			return nil, false
		}
	default:
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// formatUUID renders 16 bytes in the canonical lowercase hyphenated form (UUID.toString()).
func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// idToString ports the id branch of customTransformOutput: ObjectId → hex, UUID → string,
// arrays element-wise; anything else is returned unchanged.
func idToString(v any) any {
	switch t := v.(type) {
	case bson.ObjectID:
		return t.Hex()
	case bson.Binary:
		if isUUID(t) {
			return formatUUID(t.Data)
		}
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = idToString(x)
		}
		return out
	}
	return v
}

// toBSON prepares a Go value for the MongoDB driver so that documents are encoded exactly
// like the Node.js driver encodes JavaScript values: integral numbers that fit in 32 bits
// become int32, every other number a double. Documents and arrays are converted
// recursively; Records become bson.D with sorted keys.
func toBSON(v any) any {
	switch t := v.(type) {
	case nil, string, bool, time.Time, bson.ObjectID, bson.Binary, bson.Regex, bson.DateTime:
		return v
	case int:
		return jsNumber(float64(t))
	case int8:
		return int32(t)
	case int16:
		return int32(t)
	case int32:
		return t
	case int64:
		return jsNumber(float64(t))
	case uint:
		return jsNumber(float64(t))
	case uint8:
		return int32(t)
	case uint16:
		return int32(t)
	case uint32:
		return jsNumber(float64(t))
	case uint64:
		return jsNumber(float64(t))
	case float32:
		return jsNumber(float64(t))
	case float64:
		return jsNumber(t)
	case bson.D:
		out := make(bson.D, len(t))
		for i, e := range t {
			out[i] = bson.E{Key: e.Key, Value: toBSON(e.Value)}
		}
		return out
	case bson.A:
		out := make(bson.A, len(t))
		for i, x := range t {
			out[i] = toBSON(x)
		}
		return out
	case map[string]any:
		return sortedDoc(t)
	case bson.M:
		return sortedDoc(t)
	case []string:
		return v
	}
	if arr, ok := adapter.ToSlice(v); ok {
		out := make(bson.A, len(arr))
		for i, x := range arr {
			out[i] = toBSON(x)
		}
		return out
	}
	return v
}

func sortedDoc(m map[string]any) bson.D {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make(bson.D, 0, len(keys))
	for _, k := range keys {
		out = append(out, bson.E{Key: k, Value: toBSON(m[k])})
	}
	return out
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// jsNumber encodes a JavaScript number the way js-bson does: int32 when it is an integer in
// the int32 range, double otherwise.
func jsNumber(f float64) any {
	if f == math.Trunc(f) && f >= math.MinInt32 && f <= math.MaxInt32 && !math.IsInf(f, 0) {
		return int32(f)
	}
	return f
}

// fromBSON converts a decoded BSON value into plain Go values: documents become Records,
// arrays []any, dates time.Time and int32 int64.
func fromBSON(v any) any {
	switch t := v.(type) {
	case bson.D:
		rec := make(adapter.Record, len(t))
		for _, e := range t {
			rec[e.Key] = fromBSON(e.Value)
		}
		return rec
	case bson.M:
		rec := make(adapter.Record, len(t))
		for k, x := range t {
			rec[k] = fromBSON(x)
		}
		return rec
	case map[string]any:
		rec := make(adapter.Record, len(t))
		for k, x := range t {
			rec[k] = fromBSON(x)
		}
		return rec
	case bson.A:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = fromBSON(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = fromBSON(x)
		}
		return out
	case bson.DateTime:
		return t.Time().UTC()
	case int32:
		return int64(t)
	case bson.Null, bson.Undefined:
		return nil
	}
	return v
}
