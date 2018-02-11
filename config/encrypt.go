package config

import (
	"golang.org/x/crypto/bcrypt"
)

var (
	PassWordFunc map[string]interface{}
)

func init() {
	PassWordFunc = make(map[string]interface{})
	PassWordFunc["bcrypt"] = BcryptEncrypt
}

func BcryptEncrypt(password string, num int) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), num)
	return string(hashedPassword)
}
