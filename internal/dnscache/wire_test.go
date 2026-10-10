package dnscache

import "testing"

// A question's key holds the name in lower case and the type as it is: a
// number, not a letter. HTTPS (65, 'A') went under 97's key.
func TestQuestionKeyType(t *testing.T) {
	typed := func(name string, qtype byte) string {
		q := query(name, 1)
		q[len(q)-3] = qtype
		k, _, ok := question(q)
		if !ok {
			t.Fatalf("%s type %d: not a question", name, qtype)
		}
		return k
	}
	if typed("a.example", 65) == typed("a.example", 97) {
		t.Error("types 65 and 97 share a key")
	}
	if typed("A.Example", 65) != typed("a.example", 65) {
		t.Error("the name's case makes two keys")
	}
}
