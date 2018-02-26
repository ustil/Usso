package main

import (
	"log"
	"usso/config"
	"usso/models"
	_ "usso/routers"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	err := orm.RegisterDataBase("default", config.Database, config.User+":"+config.PassWord+"@tcp("+config.Url+":"+config.Port+")/test?charset=utf8", 30)
	if err != nil {
		log.Println(err)
	}
	orm.RegisterModel(new(models.User))
	orm.RunSyncdb("default", false, true)
	if beego.BConfig.RunMode == "dev" {
		beego.BConfig.WebConfig.DirectoryIndex = true
		beego.BConfig.WebConfig.StaticDir["/swagger"] = "swagger"
	}
	beego.Run()
}
