package controllers

import (
	"usso/models"

	"github.com/astaxie/beego"
)

type UserController struct {
	beego.Controller
}

// @router /register [post]
func (u *UserController) Register() { //注册
	email := u.GetString("email")
	passWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.RegsterUser(email, passWord)
	if err != nil {
		ret.Msg = err.Error()
	} else {
		ret.Msg = "注册成功"
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /login [post]
func (u *UserController) Login() { //登陆
	email := u.GetString("eamil")
	passWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.VaildLogin(email, passWord) //
	if err != nil {
		ret.Msg = err.Error()
	} else {
		models.GetToken(email)
		ret.Data = models.GetUserJsonByEmail(email)
		ret.Msg = "登录成功"
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /vaild [get]
func (u *UserController) Vaild() { //验证
	token := u.GetString("token")
	err := models.VaildToken(token) //
	ret := models.Response{Code: 200, Msg: ""}
	if err != nil {
		ret.Msg = err.Error()
	} else {
		ret.Data = models.GetUserJsonByToken(token)
		ret.Msg = "验证通过"
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /change [post]
func (u *UserController) ChangePassWord() {
	email := u.GetString("email")
	oldPassWord := u.GetString("oldPassWord")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.VaildLogin(email, oldPassWord)
	if err == nil {
		newPassWord := u.GetString("NewPassWord")
		if models.ChangePd(email, oldPassWord, newPassWord) {
			ret.Data = models.GetUserJsonByEmail(email)
			ret.Msg = "修改成功"
		}
	} else {
		ret.Msg = err.Error()
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /back [post]
func (u *UserController) BackPwd() {
	email := u.GetString("email")
	requestUrl := u.Ctx.Request.Host
	ret := models.Response{Code: 200, Msg: ""}
	err := models.BackPassWord(email, requestUrl)
	if err == nil {
		ret.Msg = "链接已发送至你的邮箱"
	} else {
		ret.Msg = err.Error()
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /link [get]
func (u *UserController) Link() {
	ret := models.Response{Code: 200, Msg: ""}
	resetToken1 := u.GetString("resetToken")
	resetToken, err := models.AesDecrypt(resetToken1) //得到解密之后的token
	if err != nil {
		ret.Msg = err.Error()
	} else {
		if !models.CheckResetToken(resetToken) {
			ret.Msg = "链接失效"
		} else {
			ret.Msg = "token有效且解密成功"
		}
	}
	user := models.GetUserJsonByResetToken(resetToken)
	email := user.Email
	token := user.Token
	if models.CheckOrmByEmail(email) && models.CheckOrmByToken(token) {
		password := u.GetString("ResetPassWord")
		if models.ResetPassWord(email, password) {
			ret.Msg += " 重置密码成功"
		}
	}
	u.Data["json"] = ret
	u.ServeJSON()
}
