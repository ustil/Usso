package main

import (
	//"fmt"
	"log"
	"usso/config"
	"usso/models"
	_ "usso/routers"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	_ "github.com/go-sql-driver/mysql"
)

func init() {
	err := orm.RegisterDataBase("default", config.DatabaseDriver, config.User+":"+config.PassWord+"@tcp("+config.Url+":"+config.Port+")/"+config.Database+"?charset=utf8", 30)
	if err != nil {
		log.Println(err)
	}
	orm.RegisterModel(new(models.User))
	orm.RunSyncdb("default", false, true)
	models.Init()
}

func main() {

	if beego.BConfig.RunMode == "dev" {
		beego.BConfig.WebConfig.DirectoryIndex = true
		beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
	}
	beego.Run()
}
