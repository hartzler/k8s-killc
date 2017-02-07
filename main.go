package main

import (
	"fmt"
	"strings"
	"time"
	"golang.org/x/crypto/openpgp"
	"k8s.io/client-go/1.5/kubernetes"
	"k8s.io/client-go/1.5/pkg/api"
	"k8s.io/client-go/1.5/rest"
)

func main() {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// load verification key
	pubkeytxt := `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBFiZH1oBCACeaHIvxd3iWpzMGk9pLkOrvevBGYyrMFqMyNZEPthit4yQwUcn
b3BjKrZGKmP3qrcjvvq3419+zeB0wlNvuLQWmFa1qU+l1H03NYkYgdOSD2e58gye
usC9arMnqfw3XJj0X5ykcghp5D8KNfzAQBrTkMMCAE50hWjdtWdOpNk1jgX0DYor
3t7CzUph1VcUOT27eJkGfVbHSG9B6UlLFaDL3fXN3epiqJcuf1SgR+s+ayZduRPd
lsfgvfiwYSExAyGTMSHv4SHYTznFhigszoWxTbZzgoPHgM8iwG+35FZa04tBypnt
lIqTOCLcyIGDJwQywEfst/XgmEdtE5Z6/OOxABEBAAG0G2s4cy1raWxsYy1rZXkg
PHlvdUBmb28uY29tPokBOQQTAQgAIwUCWJkfWgIbAwcLCQgHAwIBBhUIAgkKCwQW
AgMBAh4BAheAAAoJEBT2P74xJrtnn9QH/Retr+d/QlaK33n1Ppypy+rErybqz2J3
R4ARf1Goqq9eRVo7Ly6Au0vG/UuKbkAChXVmPtJ2vj78blaXzVX9B2aCTsMJivNC
x8mjlYDb4a5N6bKbjwcrwMgI7iAmtvrEC/L+Jqss/8L67QtwdGRf/a9yaJQ3bTkm
Fxni6QGyIUDS6hY83lDF0M8SDqF9LlJ60mMjLeElfTWnnDs/UHtj55f/Tlp5a+Y3
Jcg8YMO1tV6KxXJKLxXxw05vChXInPvSTO2UrTmq697p+MjG3iswMPxd6jsVQfUI
JSKffCD+cerWe53dSoh8yEiAQjE9O7JH6r/XIXe+QkRM2j/GrD1dx4k=
=mQkn
-----END PGP PUBLIC KEY BLOCK-----`
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pubkeytxt))
	if err != nil {
					fmt.Println("Read Armored Key Ring: " + err.Error())
					return
	}
	// controller loop
	for {
		killc(clientset, keyring)
		time.Sleep(10 * time.Second)
	}
}

func killc(clientset *kubernetes.Clientset, keyring openpgp.EntityList) {
	// pods
	pods, err := clientset.Core().Pods("").List(api.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	// for each pod validate the killc/signature if its not kube-system
	count:=0
	for _, pod := range pods.Items {
		if pod.ObjectMeta.Namespace != "kube-system" {
			count += 1

			// build plain text
			text := ""
			for _, container := range pod.Spec.Containers {
				text = text + container.Image
			}

			// get signature
			sig := pod.ObjectMeta.Annotations["killc/signature"]
			fmt.Printf("[DEBUG] pod: %s killc/signature: %s\n", pod.ObjectMeta.Name, sig)

			// verify
			valid, err := verify(keyring, sig, text)
			if err != nil {
				fmt.Printf("Error verifying signature %v\n", err)
			}

			if !valid {
				if err := clientset.Core().Pods(pod.ObjectMeta.Namespace).Delete(pod.ObjectMeta.Name, nil); err != nil {
					fmt.Printf("Error deleting pod: %v", err)
				} else {
					fmt.Printf("[INFO] KILLING: Invalid killc/signature for pod %s in namespace %s\n", pod.ObjectMeta.Name, pod.ObjectMeta.Namespace)
				}
			} else {
				fmt.Printf("[INFO] Valid killc/signature for pod: %s\n", pod.ObjectMeta.Name)
			}
		}
	}
	fmt.Printf("There are %d pods in the cluster, %d user pods\n", len(pods.Items), count)
}

func verify(keyring openpgp.EntityList, signature, verification_target string) (bool, error) {
	entity, err := openpgp.CheckArmoredDetachedSignature(keyring,
		strings.NewReader(verification_target),
		strings.NewReader(signature))
	if err != nil {
					fmt.Println("[ERROR] Check Detached Signature: " + err.Error())
					return false, err
	}
	fmt.Println("[DEBUG] Entity: ", entity)
	return true, nil
}
