package models

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"usso/config"

	"github.com/satori/go.uuid"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	_ "github.com/go-sql-driver/mysql"
	"github.com/scorredoira/email"
	"net/mail"
	"net/smtp"
)

var (
	o                orm.Ormer
	DefaultRowsLimit = -1
	Users            map[string]*User
	Tokens           map[string]*User
)

type User struct {
	Id       int
	Email    string
	PassWord string

	Token string    `orm:"null"`
	Time  time.Time `orm:"type(datetime)"`

	AdminType int       `orm:"default(0)"`
	Authtime  time.Time `orm:"type(datetime)"`

	Status int    `orm:"default(0)"`
	Mtoken string `orm:"null"`

	ResetPassToken string    `orm:"null"`
	ResetPassTime  time.Time `orm:"type(datetime)"`

	Created time.Time `orm:"auto_now_add;type(datetime)"`
	Updated time.Time `orm:"auto_now;type(datetime)"`
}

func init() {
	var users []*User
	o := orm.NewOrm()
	o.QueryTable(new(User)).All(&users)
	now := time.Now()
	for _, user := range users {
		Users[user.Email] = user
		if user.Token != "" {
			if now.Before(user.Time) {
				Tokens[user.Token] = user
			} else {
				user.Token = ""
				o.Update(user, "Token")
			}
		}
	}
}

func RegsterUser(email string, password string) error {
	if len(password) >= 20 || len(password) < 6 {
		return errors.New("密码长度过短")
	}
	eamilvaild, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$`, email)
	if !eamilvaild {
		return errors.New("邮箱不合法")
	}
	_, ok := CheckEmail(email)
	if ok {
		return errors.New("邮箱已注册")
	}
	savePassWord := GetSavePassWord(password)
	user := User{Email: email, PassWord: savePassWord}
	o.Insert(&user)
	Users[email] = &user
	return nil
}

func VaildLogin(email string, password string) error {
	user, ok := CheckEmail(email)
	if !ok {
		return errors.New("用户名不存在或密码错误")
	}
	if VaildPassWord(password, user.PassWord) {
		return nil
	}
	return errors.New("用户名不存在或密码错误")
}

func VaildToken(token string) error {
	if CheckToken(token) {
		return nil
	}
	return errors.New("Token不存在或已过期")
}

func Logout(token string) {
	delete(Tokens, token)
}

func GetToken(email string) string {
	tuuid, err := uuid.NewV4()
	token := tuuid.String()
	if err != nil {
		beego.Error("Uuid create fail: " + err.Error())
		return ""
	}
	if CheckOrmByEmail(email) {
		return ""
	}
	user := User{Email: email}
	if len(user.Token) != 0 {
		if CheckToken(user.Token) {
			delete(Tokens, user.Token)
		}
	}
	now := time.Now()
	user.Token = token
	user.Time = now.Add(time.Second * time.Duration(config.DefaultTokenDay))
	o.Update(&user, "Token", "Time")
	Tokens[token] = &user
	return token
}

func CheckOrmByEmail(email string) bool {
	user := User{Email: email}
	err := o.Read(&user, "Email")
	if err != nil {
		beego.Error("Get user info fail! email: " + email)
		return false
	}
	return true
}

func ChangePd(userEmail, oldPassWord, newPassWord string) bool {
	user := User{Email: userEmail}
	if !CheckOrmByEmail(userEmail) {
		return false
	} else if user.PassWord == oldPassWord {
		if len(newPassWord) > 6 && len(newPassWord) <= 20 {
			user.PassWord = newPassWord
			return true
		} else {
			log.Fatal("新密码长度不合要求")
			return false
		}
	} else {
		log.Fatal("原密码错误")
		return false
	}
}

func BackPassWord(email1 string) error {
	if !CheckOrmByEmail(email1) {
		return errors.New("email is not exits")
	}
	var passWord string
	if user, ok := CheckEmail(email1); ok {
		passWord = user.PassWord
	}
	m := email.NewMessage("PassWord", "you PassWord is: "+passWord)
	m.From = mail.Address{Name: config.FromMailName, Address: config.FromMailAddress}
	m.To = []string{email1}
	auth := smtp.PlainAuth("", config.FromMailAddress, config.FromMailPassWord, config.SendMailHost)
	if err := email.Send(config.SendMailHost+config.SendMailPort, auth, m); err != nil {
		beego.Error(err)
		return errors.New("send fail!")
	}
	return nil
}

func GetUserJsonByEmail(email string) *UserResponse {
	user := Users[email]
	now, end := time.Now(), user.Time
	return &UserResponse{Id: user.Id,
		Email:     user.Email,
		Token:     user.Token,
		Time:      int(end.Sub(now).Seconds()),
		AdminType: user.AdminType,
		Status:    user.Status}
}

func GetUserJsonByToken(token string) *UserResponse {
	user := Tokens[token]
	now, end := time.Now(), user.Time
	return &UserResponse{Id: user.Id,
		Email:     user.Email,
		Token:     user.Token,
		Time:      int(end.Sub(now).Seconds()),
		AdminType: user.AdminType,
		Status:    user.Status}
}

func CheckEmail(email string) (*User, bool) {
	user, ok := Users[email]
	return user, ok
}

func CheckToken(token string) bool {
	user, ok := Tokens[token]
	if !ok {
		return false
	}
	now := time.Now()
	if now.Before(user.Time) {
		delete(Tokens, token)
		return false
	}
	return true
}

func GetSavePassWord(userPassWord string) string {
	funcStr := config.DefaultEncryptAlgorithm
	passFunc := config.PassWordFunc[funcStr].(func(string, int) string)
	salt := GetSalt()
	num := rand.Intn(50) + 1
	passStr := passFunc(Md5(Md5(userPassWord)+salt), num)
	return fmt.Sprintf("%s$%d$%s$%s", funcStr, num, salt, passStr)
}

func VaildPassWord(userPassWord string, savePassWord string) bool {
	sPassWord := strings.Split(savePassWord, "$")
	if len(sPassWord) < 4 {
		beego.Error("User password maybe save error.")
		return false
	}
	function, snum, salt, password := sPassWord[0], sPassWord[1], sPassWord[2], sPassWord[3]
	num, _ := strconv.Atoi(snum)
	tfunc, ok := config.PassWordFunc[function]
	if !ok {
		beego.Error("Password function in passwordlist but not in passwordfunc map.")
		return false
	}
	passFunc := tfunc.(func(string, int) string)
	salted := AddSalt(userPassWord, salt)
	pass := passFunc(salted, num)
	if pass == password {
		return true
	}
	return false
}

func Md5(text string) string {
	hash := md5.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}

func GetSalt() string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	salt := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 15; i++ {
		salt = append(salt, bytes[r.Intn(len(bytes))])
	}
	return string(salt)
}

func AddSalt(passWord string, salt string) string {
	return Md5(Md5(passWord) + salt)
}
