package controllers

import (
	"usso/models"

	"github.com/astaxie/beego"
)

type UserController struct {
	beego.Controller
}

// @router /register [post]
func (u *UserController) Register() {
	email := u.GetString("email")
	PassWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.RegsterUser(email, PassWord)
	if err != nil {
		ret.Msg = err.Error()
	} else {
		ret.Msg = "注册成功"
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /login [post]
func (u *UserController) Login() {
	Email := u.GetString("eamil")
	PassWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.VaildLogin(Email, PassWord)
	if err != nil {
		ret.Msg = err.Error()
	} else {
		models.GetToken(Email)
		ret.Data = models.GetUserJsonByEmail(Email)
		ret.Msg = "登录成功"
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /vaild [get]
func (u *UserController) Vaild() {
	token := u.GetString("token")
	err := models.VaildToken(token)
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
	Email := u.GetString("email")
	OldPassWord := u.GetString("OldPassWord")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.VaildLogin(Email, OldPassWord)
	if err == nil {
		NewPassWord := u.GetString("NewPassWord")
		if models.ChangePd(Email, OldPassWord, NewPassWord) {
			ret.Data = models.GetUserJsonByEmail(Email)
			ret.Msg = "修改成功"
		}
	} else {
		ret.Msg = err.Error()
	}
	u.Data["json"] = ret
	u.ServeJSON()
}

// @router /back [get]
func (u *UserController) BackPwd() {
	Email := u.GetString("email")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.BackPassWord(Email)
	if err != "send success!" {
		beego.Error(err)
	}
	ret.Msg = err
	u.Data["json"] = ret
	u.ServeJSON()
}
