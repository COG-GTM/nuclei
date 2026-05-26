package projectfile

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashDeterministic(t *testing.T) {
	data := "test data"
	hash1, err1 := hash(data)
	hash2, err2 := hash(data)

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, hash1, hash2)
}

func TestHashDifferentInputs(t *testing.T) {
	hash1, err1 := hash("data1")
	hash2, err2 := hash("data2")

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotEqual(t, hash1, hash2)
}

func TestMarshalUnmarshal(t *testing.T) {
	original := HTTPRecord{
		Request: []byte("GET / HTTP/1.1"),
		Response: &InternalResponse{
			HTTPMajor:    1,
			HTTPMinor:    1,
			StatusCode:   200,
			StatusReason: "200 OK",
			Headers:      map[string][]string{"Content-Type": {"text/html"}},
			Body:         []byte("<html></html>"),
		},
	}

	data, err := marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded HTTPRecord
	decoded.Response = newInternalResponse()
	err = unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Equal(t, original.Request, decoded.Request)
	require.Equal(t, original.Response.StatusCode, decoded.Response.StatusCode)
	require.Equal(t, original.Response.Body, decoded.Response.Body)
	require.Equal(t, original.Response.Headers, decoded.Response.Headers)
}

func TestNewInternalResponse(t *testing.T) {
	resp := newInternalResponse()
	require.NotNil(t, resp)
	require.NotNil(t, resp.Headers)
	require.Equal(t, 0, resp.StatusCode)
}

func TestToInternalResponse(t *testing.T) {
	httpResp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: 404,
		Status:     "404 Not Found",
		Header:     http.Header{"X-Custom": {"value"}},
	}
	body := []byte("not found")

	intResp := toInternalResponse(httpResp, body)

	require.Equal(t, 1, intResp.HTTPMajor)
	require.Equal(t, 1, intResp.HTTPMinor)
	require.Equal(t, 404, intResp.StatusCode)
	require.Equal(t, "404 Not Found", intResp.StatusReason)
	require.Equal(t, body, intResp.Body)
	require.Equal(t, []string{"value"}, intResp.Headers["X-Custom"])
}

func TestFromInternalResponse(t *testing.T) {
	intResp := &InternalResponse{
		HTTPMajor:    2,
		HTTPMinor:    0,
		StatusCode:   201,
		StatusReason: "201 Created",
		Headers:      map[string][]string{"Content-Type": {"application/json"}},
		Body:         []byte(`{"id":1}`),
	}

	httpResp := fromInternalResponse(intResp)

	require.Equal(t, 2, httpResp.ProtoMajor)
	require.Equal(t, 0, httpResp.ProtoMinor)
	require.Equal(t, 201, httpResp.StatusCode)
	require.Equal(t, "201 Created", httpResp.Status)
	require.Equal(t, int64(8), httpResp.ContentLength)

	body, err := io.ReadAll(httpResp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"id":1}`, string(body))
}

func TestFromInternalResponseNilBody(t *testing.T) {
	intResp := &InternalResponse{
		StatusCode: 204,
		Headers:    map[string][]string{},
	}

	httpResp := fromInternalResponse(intResp)
	require.Equal(t, int64(0), httpResp.ContentLength)
}

func TestCleanupData(t *testing.T) {
	pf := &ProjectFile{}

	input := []byte("GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nHost: example.com\r\n")
	cleaned := pf.cleanupData(input)
	require.NotContains(t, string(cleaned), "Mozilla/5.0")
	require.Contains(t, string(cleaned), "Host: example.com")
}

func TestCleanupDataInteractsh(t *testing.T) {
	pf := &ProjectFile{}

	input := []byte("GET /test?param=abc123.interact.sh HTTP/1.1\r\n")
	cleaned := pf.cleanupData(input)
	require.NotContains(t, string(cleaned), "interact.sh")
}
