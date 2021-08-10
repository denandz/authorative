package main

import (
	"authorative/config"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mdp/qrterminal"
	"github.com/pquerna/otp/totp"
)

func main() {
	// needs sensible arg parsing...
	args := os.Args[1:]
	if len(args) < 3 {
		log.Fatalln("Insufficient arguments, please run with: adduser <config> <username> <password>")
	}

	configFile := args[0]
	username := args[1]
	password := args[2]

	// unmarshal the config
	jsonFile, err := os.OpenFile(configFile, os.O_RDWR, 0666)
	// if we os.Open returns an error then handle it
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Successfully Opened " + configFile)
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	var configuration config.ServerConfig
	c, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(c, &configuration)

	// generate a TOTP key
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "Authorative",
		AccountName: username,
	})

	_, err = configuration.CreateUser(username, password, key.Secret())
	if err != nil {
		log.Fatalln(err)
	}

	qrterminal.Generate(key.URL(), qrterminal.L, os.Stdout)

	configString, _ := json.Marshal(configuration)
	fmt.Println(string(configString))

	// write out the config file
	jsonFile.Truncate(0)
	jsonFile.Seek(0, 0)
	jsonFile.Write(configString)
	jsonFile.Sync()
}
