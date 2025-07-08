package models

type User struct {
	GUID         string `json:"guid"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refreshToken"`
}

type CurrentGuidResponse struct {
	GUID string `json:"guid"`
}

type UpdateTokensPairResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}
