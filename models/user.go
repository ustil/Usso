package models

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	_ "github.com/go-sql-driver/mysql"
	"github.com/satori/go.uuid"
	"usso/config"
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
	Password string

	Token string    `orm:"null"`
	Time  time.Time `orm:"type(datetime)"`

	Admintype int       `orm:"default(0)"`
	Authtime  time.Time `orm:"type(datetime)"`

	Status int    `orm:"default(0)"`
	Mtoken string `orm:"null"`

	ResetPassToken string    `orm:"null"`
	ResetPassTime  time.Time `orm:"type(datetime)"`

	Created time.Time `orm:"auto_now_add;type(datetime)"`
	Updated time.Time `orm:"auto_now;type(datetime)"`
}

func init() {
	orm.RegisterDataBase("default", "mysql", "root:123456@tcp(127.0.0.1:3306)/test?charset=utf8", 30)
	orm.RegisterModel(new(User))
	orm.RunSyncdb("default", false, true)
	var users []*User
	o := orm.NewOrm()
	o.QueryTable("user").All(&users)
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
	savePassword := GetSavePassword(password)
	user := User{Email: email, Password: savePassword}
	o.Insert(&user)
	Users[email] = &user
	return nil
}

func VaildLogin(email string, password string) error {
	user, ok := CheckEmail(email)
	if !ok {
		return errors.New("用户名不存在或密码错误")
	}
	if VaildPassword(password, user.Password) {
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

func CheckOrmByEmail(Email string) bool {
	user := User{Email: Email}
	err := o.Read(&user, "Email")
	if err != nil {
		beego.Error("Get user info fail! email: " + Email)
		return false
	}
	return true
}

func ChangePd(UserEmail, OldPassword, NewPassword string) bool {
	user := User{Email: UserEmail}
	if !CheckOrmByEmail(UserEmail) {
		return false
	} else if user.Password == OldPassword {
		if len(NewPassword) > 6 && len(NewPassword) <= 20 {
			user.Password = NewPassword
			return true
		} else {
			beego.Error("新密码长度不合要求")
			return false
		}
	} else {
		beego.Error("原密码错误")
		return false
	}
}

func GetUserJsonByEmail(email string) *UserResponse {
	user := Users[email]
	now, end := time.Now(), user.Time
	return &UserResponse{Id: user.Id,
		Email:     user.Email,
		Token:     user.Token,
		Time:      int(end.Sub(now).Seconds()),
		Admintype: user.Admintype,
		Status:    user.Status}
}

func GetUserJsonByToken(token string) *UserResponse {
	user := Tokens[token]
	now, end := time.Now(), user.Time
	return &UserResponse{Id: user.Id,
		Email:     user.Email,
		Token:     user.Token,
		Time:      int(end.Sub(now).Seconds()),
		Admintype: user.Admintype,
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

func GetSavePassword(userPassword string) string {
	funcstr := config.DefaultEncryptAlgorithm
	passFunc := config.PasswordFunc[funcstr].(func(string, int) string)
	salt := GetSalt()
	num := rand.Intn(50) + 1
	passstr := passFunc(Md5(Md5(userPassword)+salt), num)
	return fmt.Sprintf("%s$%d$%s$%s", funcstr, num, salt, passstr)
}

func VaildPassword(userPassword string, savePassword string) bool {
	sPassword := strings.Split(savePassword, "$")
	if len(sPassword) < 4 {
		beego.Error("User password maybe save error.")
		return false
	}
	function, snum, salt, password := sPassword[0], sPassword[1], sPassword[2], sPassword[3]
	num, _ := strconv.Atoi(snum)
	tfunc, ok := config.PasswordFunc[function]
	if !ok {
		beego.Error("Password function in passwordlist but not in passwordfunc map.")
		return false
	}
	passFunc := tfunc.(func(string, int) string)
	salted := AddSalt(userPassword, salt)
	pass := passFunc(salted, num)
	if pass == password {
		return true
	}
	return false
}

func Md5(text string) string {
	Hash := md5.New()
	Hash.Write([]byte(text))
	return hex.EncodeToString(Hash.Sum(nil))
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

func AddSalt(password string, salt string) string {
	return Md5(Md5(password) + salt)
}
