package types

type UserProjectFavoriteResponse struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
}

type CreateUserProjectFavoriteRequest struct {
	ProjectRef string
}
