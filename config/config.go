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

const (
	Database string = "mysql"
	User     string = "root"
	Host     string = "localhost"
	Url      string = "127.0.0.1"
	PassWord string = "123456"
	Port     string = "3306"
)
