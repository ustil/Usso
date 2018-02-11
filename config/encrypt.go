package config

import (
	"golang.org/x/crypto/bcrypt"
)

var (
	PasswordFunc map[string]interface{}
)

func init() {
	PasswordFunc = make(map[string]interface{})
	PasswordFunc["bcrypt"] = BcryptEncrypt
}

func BcryptEncrypt(password string, num int) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), num)
	return string(hashedPassword)
}
