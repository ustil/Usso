package models

type Response struct { //给客户端回复的数据结构
	Code int         `json:"code"` //状态码
	Msg  string      `json:"Msg"`  //message
	Data interface{} `json:"data"`
}

type UserResponse struct { //
	Id        int    `json:"id"`
	Email     string `json:"email"`
	Token     string `json:"token"`
	Time      int    `json:"time"`
	Admintype int    `json:"admin_type"`
	Status    int    `json:"status"`
}
