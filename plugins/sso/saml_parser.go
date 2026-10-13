package sso

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// A minimal emulation of fast-xml-parser's XMLParser as configured upstream
// ({ ignoreAttributes: false, attributeNamePrefix: "@_", removeNSPrefix: true,
// processEntities: false }): element names lose their namespace prefix, xmlns attributes
// are dropped, attributes become "@_name", text is trimmed (numeric text becomes a number),
// repeated children become arrays and entities are left undecoded.

// xNode is a parsed element object with ordered keys.
type xNode struct {
	keys []string
	vals map[string]any
}

func newXNode() *xNode { return &xNode{vals: map[string]any{}} }

func (n *xNode) get(k string) (any, bool) {
	if n == nil {
		return nil, false
	}
	v, ok := n.vals[k]
	return v, ok
}

func (n *xNode) add(k string, v any) {
	if existing, ok := n.vals[k]; ok {
		if arr, isArr := existing.([]any); isArr {
			n.vals[k] = append(arr, v)
		} else {
			n.vals[k] = []any{existing, v}
		}
		return
	}
	n.keys = append(n.keys, k)
	n.vals[k] = v
}

func (n *xNode) set(k string, v any) {
	if _, ok := n.vals[k]; !ok {
		n.keys = append(n.keys, k)
	}
	n.vals[k] = v
}

var errXMLParse = errors.New("xml parse error")

func stripNS(name string) string {
	if i := strings.Index(name, ":"); i >= 0 {
		return name[i+1:]
	}
	return name
}

var numericText = regexp.MustCompile(`^[-+]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?$`)

func textValue(s string) any {
	if numericText.MatchString(s) {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return s
}

type xFrame struct {
	name string
	node *xNode
	text strings.Builder
}

// parseXMLObject parses xml into the fast-xml-parser object shape.
func parseXMLObject(xml string) (*xNode, error) {
	root := &xFrame{node: newXNode()}
	stack := []*xFrame{root}
	i := 0
	n := len(xml)
	for i < n {
		lt := strings.IndexByte(xml[i:], '<')
		if lt < 0 {
			stack[len(stack)-1].text.WriteString(xml[i:])
			break
		}
		stack[len(stack)-1].text.WriteString(xml[i : i+lt])
		i += lt
		switch {
		case strings.HasPrefix(xml[i:], "<!--"):
			end := strings.Index(xml[i+4:], "-->")
			if end < 0 {
				return nil, errXMLParse
			}
			i += 4 + end + 3
		case strings.HasPrefix(xml[i:], "<![CDATA["):
			end := strings.Index(xml[i+9:], "]]>")
			if end < 0 {
				return nil, errXMLParse
			}
			stack[len(stack)-1].text.WriteString(xml[i+9 : i+9+end])
			i += 9 + end + 3
		case strings.HasPrefix(xml[i:], "<?"):
			end := strings.Index(xml[i:], "?>")
			if end < 0 {
				return nil, errXMLParse
			}
			i += end + 2
		case strings.HasPrefix(xml[i:], "<!"):
			// DOCTYPE and other declarations (bracketed internal subsets included)
			depth := 0
			j := i + 2
			for ; j < n; j++ {
				if xml[j] == '[' {
					depth++
				} else if xml[j] == ']' {
					depth--
				} else if xml[j] == '>' && depth <= 0 {
					break
				}
			}
			if j >= n {
				return nil, errXMLParse
			}
			i = j + 1
		case strings.HasPrefix(xml[i:], "</"):
			end := strings.IndexByte(xml[i:], '>')
			if end < 0 {
				return nil, errXMLParse
			}
			name := strings.TrimSpace(xml[i+2 : i+end])
			i += end + 1
			if len(stack) < 2 || stack[len(stack)-1].name != name {
				return nil, errXMLParse
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			closeFrame(f, stack[len(stack)-1].node)
		default:
			end, selfClose, name, attrs, err := parseTag(xml, i)
			if err != nil {
				return nil, err
			}
			i = end
			node := newXNode()
			for _, a := range attrs {
				if a[0] == "xmlns" || strings.HasPrefix(a[0], "xmlns:") {
					continue
				}
				node.set("@_"+stripNS(a[0]), a[1])
			}
			f := &xFrame{name: name, node: node}
			if selfClose {
				closeFrame(f, stack[len(stack)-1].node)
			} else {
				stack = append(stack, f)
			}
		}
	}
	if len(stack) != 1 {
		return nil, errXMLParse
	}
	return root.node, nil
}

func closeFrame(f *xFrame, parent *xNode) {
	text := strings.TrimSpace(f.text.String())
	key := stripNS(f.name)
	if len(f.node.keys) == 0 {
		if text == "" {
			parent.add(key, "")
		} else {
			parent.add(key, textValue(text))
		}
		return
	}
	if text != "" {
		f.node.set("#text", textValue(text))
	}
	parent.add(key, f.node)
}

func parseTag(xml string, i int) (end int, selfClose bool, name string, attrs [][2]string, err error) {
	n := len(xml)
	j := i + 1
	for j < n && !isXMLSpace(xml[j]) && xml[j] != '>' && xml[j] != '/' {
		j++
	}
	name = xml[i+1 : j]
	if name == "" {
		return 0, false, "", nil, errXMLParse
	}
	for j < n {
		for j < n && isXMLSpace(xml[j]) {
			j++
		}
		if j >= n {
			return 0, false, "", nil, errXMLParse
		}
		if xml[j] == '>' {
			return j + 1, false, name, attrs, nil
		}
		if xml[j] == '/' {
			if j+1 < n && xml[j+1] == '>' {
				return j + 2, true, name, attrs, nil
			}
			return 0, false, "", nil, errXMLParse
		}
		k := j
		for k < n && !isXMLSpace(xml[k]) && xml[k] != '=' && xml[k] != '>' && xml[k] != '/' {
			k++
		}
		aname := xml[j:k]
		for k < n && isXMLSpace(xml[k]) {
			k++
		}
		if k < n && xml[k] == '=' {
			k++
			for k < n && isXMLSpace(xml[k]) {
				k++
			}
			if k >= n || (xml[k] != '"' && xml[k] != '\'') {
				return 0, false, "", nil, errXMLParse
			}
			q := xml[k]
			close := strings.IndexByte(xml[k+1:], q)
			if close < 0 {
				return 0, false, "", nil, errXMLParse
			}
			attrs = append(attrs, [2]string{aname, xml[k+1 : k+1+close]})
			j = k + 1 + close + 1
		} else {
			attrs = append(attrs, [2]string{aname, "true"})
			j = k
		}
	}
	return 0, false, "", nil, errXMLParse
}

func isXMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// findNode returns the first value stored under nodeName (depth-first by key order).
func findNode(obj any, nodeName string) any {
	switch t := obj.(type) {
	case *xNode:
		if v, ok := t.vals[nodeName]; ok {
			return v
		}
		for _, k := range t.keys {
			v := t.vals[k]
			switch vv := v.(type) {
			case []any:
				for _, item := range vv {
					if f := findNode(item, nodeName); jsTruthy(f) {
						return f
					}
				}
			case *xNode:
				if f := findNode(vv, nodeName); jsTruthy(f) {
					return f
				}
			}
		}
	}
	return nil
}

// countAllNodes counts every occurrence of nodeName in the tree.
func countAllNodes(obj any, nodeName string) int {
	t, ok := obj.(*xNode)
	if !ok {
		return 0
	}
	count := 0
	if v, ok := t.vals[nodeName]; ok {
		if arr, isArr := v.([]any); isArr {
			count += len(arr)
		} else {
			count++
		}
	}
	for _, k := range t.keys {
		switch vv := t.vals[k].(type) {
		case []any:
			for _, item := range vv {
				count += countAllNodes(item, nodeName)
			}
		case *xNode:
			count += countAllNodes(vv, nodeName)
		}
	}
	return count
}

func jsTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case float64:
		return t != 0
	case bool:
		return t
	}
	return true
}
