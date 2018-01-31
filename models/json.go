package models

type Response struct {
    Code          int            `json:"code"`
    Msg           string         `json:"Msg"`
    Data          interface{}    `json:"data"`
}

type UserResponse struct {
    Id            int            `json:"id"`
    Email         string         `json:"email"`
    Token         string         `json:"token"`
    Time          int            `json:"time"`
    Admintype     int            `json:"admin_type"`
    Status        int            `json:"status"`
}
