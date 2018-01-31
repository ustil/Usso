package controllers

import (
    "usso/models"
//	"encoding/json"

    "github.com/astaxie/beego"
)

type UserController struct {
	beego.Controller
}


// @router /register [post]
func (u *UserController) Register() {
    email := u.GetString("eamil")
    password := u.GetString("password")
    ret := models.Response{Code: 200, Msg: ""}
    err := models.RegsterUser(email, password)
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
    email := u.GetString("eamil")
    password := u.GetString("password")
    ret := models.Response{Code: 200, Msg: ""}
    err := models.VaildLogin(email, password)
    if err != nil {
        ret.Msg = err.Error()
    } else {
        models.GetToken(email)
        ret.Data = models.GetUserJson(email)
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
