package config

const (
	Second uint32 = 1
	Minute        = 60 * Second
	Hour          = 60 * Minute
	Day           = 24 * Hour
)

const (
	DefaultEncryptAlgorithm string = "bcrypt"
	DefaultTokenDay         uint32 = Day * 7
)

const (
	FromMailAddress  string = "admin@ustil.cn"
	FromMailName     string = "Usso"
	FromMailPassWord string = "******"
	SendMailHost     string = "smtp.qq.com"
	SendMailPort     string = ":465"
)
