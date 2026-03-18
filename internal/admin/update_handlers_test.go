package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/updater"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUpdateStatus(t *testing.T) {
	u := updater.New(updater.Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})

	h := &Handler{updater: u}

	req := httptest.NewRequest(http.MethodGet, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var status updater.UpdateStatus
	err := json.Unmarshal(w.Body.Bytes(), &status)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", status.CurrentVersion)
	assert.True(t, status.AutoUpdate)
}

func TestHandleUpdateStatus_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodGet, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdateStatus_MethodNotAllowed(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleUpdateCheck_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/check", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateCheck(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleUpdateApply_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/apply", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateApply(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
