package data

// User represents a registered user, providing a valid login.
type User struct {
	Email       string `json:"email"`
	Password    string `json:"password`
	DisplayName string `json:"displayName`
}

func (user User) GetDisplayName() string {
	if user.DisplayName != "" {
		return user.DisplayName
	}

	return user.Email
}

type Session struct {
	Token string `json:"token"`
	Email string `json:"email`
}
