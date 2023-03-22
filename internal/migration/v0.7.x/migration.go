package migration

type DataEntry struct {
	ID       string `json:"id,omitempty"`
	DataType string `json:"data_type,omitempty"`
	Data     []byte `json:"data,omitempty"`
}
