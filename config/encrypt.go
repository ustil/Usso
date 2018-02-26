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

func BcryptEncrypt(PassWord string, num int) string {
	HashedPassWord, _ := bcrypt.GenerateFromPassword([]byte(PassWord), num)
	return string(HashedPassWord)
}
