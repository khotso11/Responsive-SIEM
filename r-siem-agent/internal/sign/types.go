package sign

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Signature struct {
	Algo          string          `json:"algo"`
	KeyID         string          `json:"key_id"`
	CreatedAt     string          `json:"created_at"`
	SubjectType   string          `json:"subject_type"`
	SubjectPath   string          `json:"subject_path"`
	Manifest      []ManifestEntry `json:"manifest,omitempty"`
	SHA256        string          `json:"sha256,omitempty"`
	Count         int64           `json:"count,omitempty"`
	FirstTSUnixMs int64           `json:"first_ts_unix_ms,omitempty"`
	LastTSUnixMs  int64           `json:"last_ts_unix_ms,omitempty"`
	HMACSHA256    string          `json:"hmac_sha256"`
}
