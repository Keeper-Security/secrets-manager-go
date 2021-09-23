package main

import (
	"fmt"
	"os"
	"time"

	ksm "github.com/keeper-security/secrets-manager-go/core"
	klog "github.com/keeper-security/secrets-manager-go/core/logger"
)

func main() {
	klog.SetLogLevel(klog.DebugLevel)
	klog.Info("Secrets Manager Started")

	// One time tokens can be used only once - afterwards use the generated config.json
	// hostname := "keepersecurity.com"
	// token := "o3Uq8HlXyqAWJN7JVqFpSRSt1ELtvLduOwuGOAcaxLs"
	// sm := ksm.NewSecretsManagerFromSettings(token, hostname, true)

	sm := ksm.NewSecretsManagerFromConfig(ksm.NewFileKeyValueStorage("client-config.json"))

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
		newPassword := fmt.Sprintf("New Password from SDK Test - " + time.Now().Format(time.RFC850))
		recToUpdate.SetPassword(newPassword)

		updatedRawJson := ksm.DictToJson(recToUpdate.RecordDict)
		recToUpdate.RawJson = updatedRawJson

		if err := sm.Save(recToUpdate); err != nil {
			klog.Error("error saving record: " + err.Error())
		}
	} else {
		klog.Error("No password field found in selected record")
	}

	klog.Println("Get only one record")
	if JW_F1_R1, err := sm.GetSecrets([]string{"EG6KdJaaLG7esRZbMnfbFA"}); err == nil {
		if len(JW_F1_R1) > 0 {
			klog.Println(JW_F1_R1[0].RawJson)
		} else {
			klog.Println("record doesn't exist.")
		}
	} else {
		klog.Println("error retrieveing single record: " + err.Error())
	}

	klog.Info("Secrets Manager Finished")
}
