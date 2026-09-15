// at-verify — the self-hosted Agent Trust verifier. Serves POST /v1/verify and GET /v1/status/{subject}
// from an exported organization snapshot (console → Settings → Security → "Export snapshot", or
// GET /api/admin/snapshot/export), with no database. Reloads the file when it changes.
//
//	at-verify -snapshot org.json -addr :8787
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MNKIAgentOS/agent-trust/go/verifier"
)

type server struct {
	path string
	mu   sync.RWMutex
	snap verifier.Snapshot
	deps verifier.Deps
	mod  time.Time
}

func (s *server) load() error {
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	s.mu.RLock()
	same := st.ModTime().Equal(s.mod)
	s.mu.RUnlock()
	if same {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var snap verifier.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	s.mu.Lock()
	s.snap, s.deps, s.mod = snap, verifier.SnapshotDeps(snap), st.ModTime()
	s.mu.Unlock()
	log.Printf("snapshot loaded: org %s · %d agents · %d delegations · taken %s", snap.OrgID, len(snap.Agents), len(snap.Delegations), snap.At)
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_body"})
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_body"})
		return
	}
	req, bad := verifier.ParseVerifyRequest(raw)
	if bad != "" {
		writeJSON(w, 400, map[string]string{"error": "invalid_" + bad})
		return
	}
	s.mu.RLock()
	deps, snap := s.deps, s.snap
	s.mu.RUnlock()
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("x-forwarded-proto"), "https") {
		scheme = "https"
	}
	var proof *string
	if p := r.Header.Get("agent-proof"); p != "" {
		proof = &p
	}
	binding := &verifier.RequestBinding{Proof: proof, Htm: r.Method, Htu: scheme + "://" + r.Host + r.URL.Path, BodyHash: verifier.BodyHash(body)}
	started := time.Now()
	res := verifier.Verify(req, deps, verifier.Options{Now: started, Request: binding, RequireProof: snap.Settings.RequireSignedRequests})
	age := int(time.Since(verifier.ParseISO(snap.At)).Seconds())
	res.Evidence = append([]verifier.Evidence{{Step: "registry", Status: "warn", Title: "Decided by at-verify from a snapshot", Detail: fmt.Sprintf("snapshot %ds old; budgets not enforced; decision not written to the ledger", age)}}, res.Evidence...)
	res.Reasons = append(res.Reasons, "degraded_snapshot")
	out := map[string]any{}
	b, _ := json.Marshal(res)
	_ = json.Unmarshal(b, &out)
	out["request_id"] = fmt.Sprintf("req_local_%d", started.UnixNano())
	out["decision_id"] = nil
	out["approval_id"] = nil
	out["latency_ms"] = time.Since(started).Milliseconds()
	out["degraded"] = true
	writeJSON(w, 200, out)
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimPrefix(r.URL.Path, "/v1/status/")
	s.mu.RLock()
	snap := s.snap
	s.mu.RUnlock()
	for _, rv := range snap.Revocations {
		if rv.SubjectID == subject {
			writeJSON(w, 200, map[string]any{"subject_id": subject, "revoked": true, "subject_type": rv.SubjectType})
			return
		}
	}
	for _, id := range snap.RevokedAttestations {
		if id == subject {
			writeJSON(w, 200, map[string]any{"subject_id": subject, "revoked": true, "subject_type": "attestation"})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"subject_id": subject, "revoked": false, "subject_type": nil})
}

func main() {
	path := flag.String("snapshot", "snapshot.json", "exported organization snapshot (JSON)")
	addr := flag.String("addr", ":8787", "listen address")
	every := flag.Duration("reload", 30*time.Second, "how often to check the snapshot file for changes")
	flag.Parse()
	s := &server{path: *path}
	if err := s.load(); err != nil {
		log.Fatal(err)
	}
	go func() {
		for range time.Tick(*every) {
			if err := s.load(); err != nil {
				log.Printf("reload: %v", err)
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/verify", s.verify)
	mux.HandleFunc("/v1/status/", s.status)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		writeJSON(w, 200, map[string]any{"ok": true, "org_id": s.snap.OrgID, "snapshot_at": s.snap.At, "agents": len(s.snap.Agents)})
	})
	log.Printf("at-verify listening on %s (snapshot %s)", *addr, *path)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
