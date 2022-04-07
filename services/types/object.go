package types

import "time"

type Object interface {
	GetKind() string
	SetKind(string)
	GetID() string
	SetID(string)
	GetCreationTime() time.Time
	SetCreationTime(time.Time)
	GetUpdateTime() time.Time
	SetUpdateTime(time.Time)
	GetRevision() uint64
	SetRevision(uint64)
}

type TypeMeta struct {
	Kind string `json:"kind,omitempty"`

	Version string `json:"version,omitempty"`
}

func (m *TypeMeta) GetKind() string {
	return m.Kind
}

func (m *TypeMeta) SetKind(kind string) {
	m.Kind = kind
}

type ObjectMeta struct {
	// ID is the unique ID of the object.
	ID string `json:"id,omitempty"`

	// CreationTime represents the time when this object has been created.
	CreationTime time.Time `json:"creationTime,omitempty"`

	// UpdateTime represents the time when this object has been created/updated.
	UpdateTime time.Time `json:"updateTime,omitempty"`

	// Revision is the object revision, it's not saved in the object but
	// populated by the fetch from the database
	Revision uint64 `json:"-"`
}

func (m *ObjectMeta) GetID() string {
	return m.ID
}

func (m *ObjectMeta) SetID(id string) {
	m.ID = id
}

func (m *ObjectMeta) GetCreationTime() time.Time {
	return m.CreationTime
}

func (m *ObjectMeta) SetCreationTime(t time.Time) {
	m.CreationTime = t
}

func (m *ObjectMeta) GetUpdateTime() time.Time {
	return m.UpdateTime
}

func (m *ObjectMeta) SetUpdateTime(t time.Time) {
	m.UpdateTime = t
}

func (m *ObjectMeta) GetRevision() uint64 {
	return m.Revision
}

func (m *ObjectMeta) SetRevision(revision uint64) {
	m.Revision = revision
}
