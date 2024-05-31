package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	t.Run("reads secret", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/v1/test/path/read", r.URL.Path)
			assert.Empty(t, r.URL.RawQuery)
			_, err := r.Body.Read(nil)
			assert.Equal(t, io.EOF, err) // no request body

			err = json.NewEncoder(w).Encode(&vaultapi.Secret{
				Data: map[string]interface{}{
					"secretkey": "secretvalue",
				},
			})
			require.NoError(t, err)
		}

		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		want := map[string]interface{}{"secretkey": "secretvalue"}

		secret, err := client.ReadWithData(context.Background(), "test/path/read", nil)
		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, want, secret.Data)
	})

	t.Run("encodes data as query string", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "testvalue", r.URL.Query().Get("testkey"))
			_, err := r.Body.Read(nil)
			assert.Equal(t, io.EOF, err) // no request body
		}

		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		data := map[string][]string{"testkey": {"testvalue"}}
		_, err := client.ReadWithData(context.Background(), "test/path/read", data)
		assert.NoError(t, err)
	})

	t.Run("canceled context", func(t *testing.T) {
		var waitForHandler sync.WaitGroup
		waitForHandler.Add(1)

		handler := func(w http.ResponseWriter, r *http.Request) {
			waitForHandler.Done()
			<-r.Context().Done()
		}

		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			// cancel after handler entry
			waitForHandler.Wait()
			cancel()
		}()

		_, err := client.ReadWithData(ctx, "testpath", nil)
		assert.Equal(t, context.Canceled, err)
	})
}

func TestWrite(t *testing.T) {
	t.Run("writes secret", func(t *testing.T) {
		handler := func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/v1/test/path/write", r.URL.Path)

			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.JSONEq(t, `{"testkey": "testvalue"}`, string(body))

			err = json.NewEncoder(w).Encode(&vaultapi.Secret{
				Data: map[string]interface{}{
					"secretkey": "secretvalue",
				},
			})
			require.NoError(t, err)
		}

		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		want := map[string]interface{}{"secretkey": "secretvalue"}

		secret, err := client.Write(context.Background(), "test/path/write", map[string]interface{}{"testkey": "testvalue"})
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, want, secret.Data)
	})
}

func TestDelete(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/v1/test/path/delete", r.URL.Path)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Empty(t, body)

		respData := map[string]interface{}{}
		for k, v := range r.URL.Query() {
			respData[k] = v
		}

		err = json.NewEncoder(w).Encode(&vaultapi.Secret{
			Data: respData,
		})
		require.NoError(t, err)
	}

	t.Run("delete secret", func(t *testing.T) {
		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		secret, err := client.Delete(context.Background(), "test/path/delete")
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, map[string]interface{}{}, secret.Data)
	})

	t.Run("delete secret with data", func(t *testing.T) {
		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		data := map[string][]string{"testkey": {"testvalue"}}
		secret, err := client.DeleteWithData(context.Background(), "test/path/delete", data)
		assert.NoError(t, err)

		expected := map[string]interface{}{
			"testkey": []interface{}{"testvalue"},
		}
		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, expected, secret.Data)
	})
}

func TestList(t *testing.T) {
	expected := map[string]interface{}{"keys": []interface{}{"the", "list", "of", "strings"}}
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "true", r.URL.Query().Get("list"))
		assert.Equal(t, "/v1/test/path/list", r.URL.Path)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Empty(t, body)

		err = json.NewEncoder(w).Encode(&vaultapi.Secret{
			Data: expected,
		})
		require.NoError(t, err)
	}

	t.Run("list", func(t *testing.T) {
		client, done := testClientServer(t, DefaultConfig(), handler)
		defer done()

		secret, err := client.List(context.Background(), "test/path/list")
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.NotNil(t, secret)
		assert.Equal(t, expected, secret.Data)
	})
}

func testClientServer(t *testing.T, cfg *Config, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()

	ts := httptest.NewServer(handler)
	cfg.Address = ts.URL

	client, err := NewClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	return client, ts.Close
}
