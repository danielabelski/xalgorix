package har

import "testing"

const sampleHAR = `{"log":{"entries":[
 {"request":{"method":"GET","url":"https://app.example.com/api/orders?id=42","headers":[{"name":"Authorization","value":"Bearer TOKEN"},{"name":"Accept","value":"*/*"}],"queryString":[{"name":"id","value":"42"}],"cookies":[{"name":"session","value":"abc"}]}},
 {"request":{"method":"POST","url":"https://app.example.com/api/orders","headers":[{"name":"Cookie","value":"session=abc"}],"postData":{"mimeType":"application/json","text":"{\"item\":\"x\",\"qty\":2}"}}},
 {"request":{"method":"GET","url":"https://app.example.com/static/app.js","headers":[]}},
 {"request":{"method":"GET","url":"https://cdn.other.com/lib.js","headers":[]}}
]}}`

func TestParseAndEndpoints(t *testing.T) {
	h, err := Parse([]byte(sampleHAR))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eps := h.Endpoints()
	// Two API endpoints (GET + POST /api/orders); static .js requests skipped.
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints (static assets skipped), got %d: %+v", len(eps), eps)
	}
	var get, post *EndpointInfo
	for i := range eps {
		switch eps[i].Method {
		case "GET":
			get = &eps[i]
		case "POST":
			post = &eps[i]
		}
	}
	if get == nil || post == nil {
		t.Fatalf("expected GET and POST endpoints, got %+v", eps)
	}
	if get.URL != "https://app.example.com/api/orders" || !hasParam(get.Params, "id") {
		t.Fatalf("GET endpoint wrong: %+v", get)
	}
	if !hasParam(post.Params, "item") || !hasParam(post.Params, "qty") {
		t.Fatalf("expected POST JSON body keys item+qty, got %+v", post.Params)
	}
}

func TestAuthHeadersMerged(t *testing.T) {
	h, _ := Parse([]byte(sampleHAR))
	auth := h.AuthHeaders()
	if auth["Authorization"] != "Bearer TOKEN" {
		t.Fatalf("expected merged Authorization header, got %q", auth["Authorization"])
	}
	if auth["Cookie"] != "session=abc" {
		t.Fatalf("expected Cookie header, got %q", auth["Cookie"])
	}
}

func TestInScopeEndpoints(t *testing.T) {
	h, _ := Parse([]byte(sampleHAR))
	if n := len(h.InScopeEndpoints("app.example.com")); n != 2 {
		t.Fatalf("expected 2 in-scope endpoints for app.example.com, got %d", n)
	}
	if n := len(h.InScopeEndpoints("nope.com")); n != 0 {
		t.Fatalf("expected 0 endpoints for an out-of-scope host, got %d", n)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse([]byte(`{"log":{"entries":[]}}`)); err == nil {
		t.Fatal("expected error for a HAR with no entries")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func hasParam(ps []string, want string) bool {
	for _, p := range ps {
		if p == want {
			return true
		}
	}
	return false
}
