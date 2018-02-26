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
	email := u.GetString("email") //get input's email获取前端所传参数
	passWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""}
	err := models.RegsterUser(email, passWord) //注册用户,这个函数里面就可以写注册的规则等等。。
	if err != nil {
		ret.Msg = err.Error()
	} else {
		ret.Msg = "注册成功"
	}
	u.Data["json"] = ret //给出去的json数据存在了map里，只有当前端有{{.json时才会拿出来}}
	u.ServeJSON()        //发送一个json回复response
}

// @router /login [post]
func (u *UserController) Login() { //登陆
	email := u.GetString("eamil")
	passWord := u.GetString("password")
	ret := models.Response{Code: 200, Msg: ""} //StatusCode=200,请求成功
	err := models.VaildLogin(email, passWord)  //验证登陆是否正确
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
	ret := models.Response{Code: 200, Msg: ""}
	err := models.BackPassWord(email)
	if err == nil {
		ret.Msg = "密码已发送至你的邮箱"
	} else {
		ret.Msg = err.Error()
	}
	u.Data["json"] = ret
	u.ServeJSON()
}
