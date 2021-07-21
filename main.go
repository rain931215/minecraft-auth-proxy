package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/JoshuaDoes/go-yggdrasil"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"net/http"
	"os"
	"strings"
)

var (
	config = viper.New()
)

func main() {
	fmt.Println("Minecraft account authenticate cache proxy server started")
	config.SetConfigName("config")
	config.SetConfigType("yml")
	config.AddConfigPath(".")
	if err := config.ReadInConfig(); err != nil {
		config.SetDefault("port","30000")
		config.SetDefault("client-token", uuid.New().String())
		config.SetDefault("auth-cache", map[string]map[string]string{})
		_ = config.SafeWriteConfig()
		_ = config.ReadInConfig()
	}
	config.WatchConfig()

	http.HandleFunc("/authenticate", handler)
	port:=config.GetString("port")
	if v := os.Getenv("PORT"); len(v) > 0 {
		port = v
	}
	if err := http.ListenAndServe(fmt.Sprintf(":%v",port), nil);err!=nil{
		panic(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	email, ok := r.URL.Query()["email"]
	if !ok || len(email[0]) < 1 {
		_,_=fmt.Fprint(w,"err:email not found in get parameters")
		return
	}
	password, ok := r.URL.Query()["password"]
	if !ok || len(password[0]) < 1 {
		 _,_=fmt.Fprint(w,"err:password not found in get parameters")
		return
	}
	if v, ok:=config.GetStringMap("auth-cache")[strings.ReplaceAll(email[0],".","$")];ok{
		if account, ok := v.(map[string]string);ok{
			if account["pw-hash"]==fmt.Sprintf("%x", sha256.Sum256([]byte(password[0]))){
				authClient:=&yggdrasil.Client{ClientToken: config.GetString("client-token"),AccessToken: account["token"]}
				pass,err:=authClient.Validate()
				if err==nil&&pass{
					_, _ = fmt.Fprint(w, fmt.Sprintf("ok:%v,%v,%v", email[0], account["uuid"], account["token"]))
					return
				}
			}
		}
	}
	authClient:=&yggdrasil.Client{ClientToken: config.GetString("client-token")}
	authResponse, err := authClient.Authenticate(email[0], password[0], "Minecraft", 1)
	if err != nil {
		_, _ = fmt.Fprint(w, fmt.Sprintf("err:auth error %v",err.ErrorMessage))
		return
	}
	_, _ = fmt.Fprint(w, fmt.Sprintf("ok:%v,%v,%v", email[0], authResponse.SelectedProfile.ID, authResponse.AccessToken))
	config.Set("auth-cache."+splitEmail[0]+"@"+strings.ReplaceAll(splitEmail[1],".","$"),map[string]string{"pw-hash":fmt.Sprintf("%x", sha256.Sum256([]byte(password[0]))),"uuid": authResponse.SelectedProfile.ID,"token": authResponse.AccessToken})
	_ = config.WriteConfig()
}
