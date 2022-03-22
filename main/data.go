package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Data interface {
	Analyzer(cap *Capture)
}

type MemData struct {
	PodIpMap, PodNameMap, VmInfo map[string]string
}

type MemDataBuilder struct {
	MemData
}

func (db *MemDataBuilder) Init() *MemDataBuilder {
	db.PodIpMap = make(map[string]string)
	db.PodNameMap = make(map[string]string)
	db.VmInfo = make(map[string]string)
	return db
}

func (db *MemDataBuilder) WithVm(file string) *MemDataBuilder {
	fmt.Printf("vm info file %s\n", file)
	f, e := os.Open(file)
	if e != nil {
		fmt.Printf("open file %s error\n", file)
		panic(e)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n') //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			break
		}

		ip := strings.Split(line, " ")[0]
		app := strings.Split(line, " ")[2]
		owner := strings.Split(line, " ")[3]
		_ = owner
		//fmt.Printf("line is %s vm ip is %s\n", line, ip)
		db.VmInfo[ip] = app
	}
	fmt.Printf("build vm info from file %s complete\n", file)
	return db
}

func (db *MemDataBuilder) WithPod(configPath string) *MemDataBuilder {
	filepathNames, err := filepath.Glob(filepath.Join(configPath, "*"))
	if err != nil {
		panic(fmt.Sprintf("cannot find file path %s", err.Error()))
	}

	for i := range filepathNames {
		filePath := filepathNames[i]
		fi, e := os.Stat(filePath)
		if e != nil {
			panic(fmt.Sprintf("cannot find file Stat %s", e.Error()))
		}
		if fi.IsDir() {
			continue
		}
		fmt.Printf("config file %s\n", filePath)

		k8sConfig, err1 := clientcmd.BuildConfigFromFlags("", filePath)
		if err1 != nil {
			panic(fmt.Sprintf("build config from file %s : %s", filePath, err1.Error()))
		}
		clientSet, err2 := kubernetes.NewForConfig(k8sConfig)
		if err2 != nil {
			panic(fmt.Sprintf("new clientset error, %s", err2.Error()))
		}

		pods, err3 := clientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err3 != nil {
			panic(fmt.Sprintf("List pod by file %s error %s", filePath, err3.Error()))
		}
		fmt.Printf("load %d pods info from %s into memory.\n", len(pods.Items), filePath)
		for _, pod := range pods.Items {
			podIp := pod.Status.PodIP
			if podIp == "" {
				//fmt.Printf("pod %s cannot get ip info\n", pod.GetName())
				continue
			}
			podName := pod.GetName()

			db.PodIpMap[podIp] = podName
			db.PodNameMap[podName] = podIp
		}
		fmt.Printf("load complete\n")

		go db.addWatch(clientSet)
	}

	return db
}

func (db *MemDataBuilder) addWatch(clientSet kubernetes.Interface) {
	// 创建stopCH对象，用于进程退出前通知Informer提前退出,暂时没使用
	stopCh := make(chan struct{})
	defer close(stopCh)

	// 实例化SharedInformer对象，参数clientset用于与Api Server交互， time.Minute设定resync周期，0为禁用resync
	sharedInformers := informers.NewSharedInformerFactory(clientSet, time.Minute*30)
	informer := sharedInformers.Core().V1().Pods().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    db.podAddFun,
		UpdateFunc: db.podUpdateFun,
		DeleteFunc: db.podDeleteFun,
	})

	informer.Run(stopCh)
}

func (db *MemDataBuilder) podAddFun(obj interface{}) {
	mObj := obj.(*v1.Pod)
	podName := mObj.GetName()
	//log.Printf("New Pod Added to Store: %s\n", podName)
	if mObj.Status.PodIP == "" {
		db.PodNameMap[podName] = ""
	}
}

func (db *MemDataBuilder) podUpdateFun(oldObj, newObj interface{}) {
	//oObj := oldObj.(*v1.Pod)
	nObj := newObj.(*v1.Pod)
	podName := nObj.GetName()
	if nObj.Status.PodIP != "" {
		db.PodNameMap[podName] = nObj.Status.PodIP
		db.PodIpMap[nObj.Status.PodIP] = podName
	}
	//log.Printf("%s Pod Updated\n", nObj.GetName())
}

func (db *MemDataBuilder) podDeleteFun(obj interface{}) {
	mObj := obj.(metav1.Object)
	podName := mObj.GetName()
	//log.Printf("Pod deleted from Store: %s\n", podName)
	podIp := db.PodNameMap[podName]
	delete(db.PodIpMap, podIp)
	delete(db.PodNameMap, podName)
	//log.Printf("Pod deleted from mem: %s\n", podName)
}

func (db *MemDataBuilder) Analyzer(cap *Capture) {
	var app string
	if valueV, okv := db.VmInfo[cap.Src]; okv {
		app = valueV
	} else {
		if valueP, okp := db.PodIpMap[cap.Src]; okp {
			app = valueP
		} else {
			fmt.Printf("unKnown src ip %s\n", cap.Src)
		}
	}
	if app != "" {
		fmt.Printf("Capture: app %s ip %s query %s answered by %s\n", app, cap.Src, cap.Record, cap.AnswerIp)
	}
}
