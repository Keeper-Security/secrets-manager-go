package main

import (
	"os"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func main() {
	klog.SetLogLevel(klog.DebugLevel)
	klog.Info("Secrets Manager Started")

	// One time tokens can be used only once - afterwards use the generated config.json
	// clientOptions := &ksm.ClientOptions{
	// 	Token:  "US:ONE_TIME_TOKEN_BASE64",
	// 	Config: ksm.NewFileKeyValueStorage("ksm-config.json")}
	// sm := ksm.NewSecretsManager(clientOptions)

	sm := ksm.NewSecretsManager(&ksm.ClientOptions{Config: ksm.NewFileKeyValueStorage("ksm-config.json")})

	allRecords, err := sm.GetSecrets([]string{})
	if err != nil {
		klog.Error("error retrieving all records: " + err.Error())
		os.Exit(1)
	}

	for _, r := range allRecords {
		klog.Println(r)
		klog.Println("\tPassword: " + r.Password())

		for i, f := range r.Files {
			klog.Printf("\t\tfile #%d -> name: %s", i, f.Name)
			f.SaveFile("/tmp/"+f.Name, true)
		}
	}

	recToUpdate := allRecords[0]

	passwordField := map[string]interface{}{}
	if passwordFields := recToUpdate.GetFieldsByType("password"); len(passwordFields) > 0 {
		passwordField = passwordFields[0]
	}

	if len(passwordField) > 0 {
		newPassword := "New Password from SDK Test - " + time.Now().Format(time.RFC850)
		recToUpdate.SetPassword(newPassword)
		if err := sm.Save(recToUpdate); err != nil {
			klog.Error("error saving record: " + err.Error())
		}
	} else {
		klog.Error("No password field found in selected record")
	}

	klog.Println("Get only one record")
	if records, err := sm.GetSecrets([]string{"<RECORD_UID>"}); err == nil {
		if len(records) > 0 {
			klog.Println(records[0].RawJson)
		} else {
			klog.Println("record doesn't exist.")
		}
	} else {
		klog.Println("error retrieveing single record: " + err.Error())
	}

	klog.Info("Secrets Manager Finished")
}
